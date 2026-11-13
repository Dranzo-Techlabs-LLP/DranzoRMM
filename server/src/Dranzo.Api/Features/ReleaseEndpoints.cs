using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Services;
using Dranzo.Domain;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

/// <summary>Offers signed agent updates to devices ring by ring (test → pilot → all).</summary>
public sealed class UpdateRollout(DranzoDbContext db, AgentRegistry agents, EnvelopeFactory envelopes, IAuditLog audit, TimeProvider clock)
{
    public static readonly string[] Rings = ["none", "test", "pilot", "all"];
    public const int MaxOffersPerPass = 50;
    public static readonly TimeSpan ReofferAfter = TimeSpan.FromMinutes(30);

    /// <summary>Which device-group rings a release in <paramref name="releaseRing"/> reaches.</summary>
    public static bool Reaches(string releaseRing, string deviceRing) => releaseRing switch
    {
        "test" => deviceRing == "test",
        "pilot" => deviceRing is "test" or "pilot",
        "all" => true,
        _ => false,
    };

    public async Task<int> RunAsync(IReadOnlyCollection<Guid>? onlyDevices, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var offered = 0;
        var online = onlyDevices ?? agents.ConnectedDeviceIds;
        if (online.Count == 0)
        {
            return 0;
        }
        var releases = (await db.AgentReleases.Include(r => r.Binaries).Where(r => r.Ring != "none" && !r.Paused).ToListAsync(ct))
            .GroupBy(r => r.PartnerId).ToDictionary(g => g.Key, g => g.OrderByDescending(r => r.Version, Comparer<string>.Create(VersionCompare.Compare)).ToList());
        if (releases.Count == 0)
        {
            return 0;
        }
        var devices = await db.Devices.Where(d => online.Contains(d.Id) && d.Status == DeviceStatus.Active).ToListAsync(ct);
        var groupRings = await db.DeviceGroups.Where(g => devices.Select(d => d.GroupId).Contains(g.Id)).ToDictionaryAsync(g => g.Id, g => g.UpdateRing, ct);
        foreach (var device in devices)
        {
            if (offered >= MaxOffersPerPass || !agents.IsConnected(device.Id) || !releases.TryGetValue(device.PartnerId, out var candidates))
            {
                continue;
            }
            // Devices outside any group only update once a release has reached everyone.
            var ring = device.GroupId is { } g && groupRings.TryGetValue(g, out var r) ? r : "all";
            var release = candidates.FirstOrDefault(c => Reaches(c.Ring, ring));
            var binary = release?.Binaries.FirstOrDefault(b => b.Kind == "binary" && b.Os == device.Os && b.Arch == device.Arch);
            if (release is null || binary is null || VersionCompare.Compare(release.Version, device.AgentVersion) <= 0 || device.FailedUpdateVersion == release.Version)
            {
                continue;
            }
            var state = await db.DeviceUpdateStates.FirstOrDefaultAsync(s => s.DeviceId == device.Id && s.ReleaseId == release.Id, ct);
            if (state is not null && (state.State is "rolled_back" or "failed" || now - state.OfferedAt < ReofferAfter))
            {
                continue;
            }
            db.BlobGrants.Add(new BlobGrant { Id = Guid.NewGuid(), PartnerId = device.PartnerId, BlobId = binary.BlobId, DeviceId = device.Id, ExpiresAt = now.AddHours(1) });
            if (state is null)
            {
                state = new DeviceUpdateState { Id = Guid.NewGuid(), PartnerId = device.PartnerId, DeviceId = device.Id, ReleaseId = release.Id, Version = release.Version, State = "offered" };
                db.DeviceUpdateStates.Add(state);
            }
            state.OfferedAt = now;
            state.UpdatedAt = now;
            await db.SaveChangesAsync(ct);
            var envelope = envelopes.Signed("update.available", device.Id, new Dictionary<string, object?>
            {
                ["version"] = release.Version, ["blobId"] = binary.BlobId.ToString("D"), ["sha256"] = binary.Sha256, ["sizeBytes"] = binary.SizeBytes, ["ring"] = release.Ring, ["force"] = false,
            });
            if (await agents.SendAsync(device.Id, envelope, ct))
            {
                offered++;
                await audit.WriteAsync(device.PartnerId, new AuditEntry("agent_update.offer", OrganizationId: device.OrganizationId, DeviceId: device.Id, TargetType: "agent_release", TargetId: release.Id.ToString(),
                    Detail: new { release.Version, from = device.AgentVersion, release.Ring }, ContentSha256: binary.Sha256, ActorType: "system", ActorName: "update-rollout"), ct);
            }
        }
        return offered;
    }
}

public sealed class UpdateRolloutService : PeriodicService
{
    public UpdateRolloutService(IServiceScopeFactory scopes, ILogger<UpdateRolloutService> log, AgentRegistry agents) : base(scopes, log, TimeSpan.FromSeconds(60))
    {
        // A device that just connected is offered a pending update without waiting for the next pass.
        agents.DeviceReady += id => _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(5));
                await using var scope = Scopes.CreateAsyncScope();
                scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
                await scope.ServiceProvider.GetRequiredService<UpdateRollout>().RunAsync([id], default);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Update offer for {DeviceId} failed", id);
            }
        });
    }

    protected override Task TickAsync(IServiceProvider sp, CancellationToken ct) => sp.GetRequiredService<UpdateRollout>().RunAsync(null, ct);
}

public sealed class UpdateStatusProcessor(DranzoDbContext db, IAuditLog audit, AlertEngine alerts, TimeProvider clock) : IAgentMessageProcessor
{
    private static readonly HashSet<string> States = ["downloading", "verifying", "installed", "rolled_back", "failed"];

    public string Type => "update.status";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var version = payload.Str("version", 32);
        var state = payload.Str("state", 16);
        if (!States.Contains(state))
        {
            throw new FormatException("unknown update state");
        }
        var device = await db.Devices.FirstAsync(d => d.Id == conn.DeviceId, ct);
        var row = await db.DeviceUpdateStates.Where(s => s.DeviceId == device.Id && s.Version == version).OrderByDescending(s => s.OfferedAt).FirstOrDefaultAsync(ct);
        if (row is null)
        {
            return; // never offered by this server: ignore
        }
        var now = clock.GetUtcNow();
        row.State = state;
        row.Error = payload.StrOrNull("error", 500);
        row.UpdatedAt = now;
        if (state is "rolled_back" or "failed")
        {
            device.FailedUpdateVersion = version;
        }
        await db.SaveChangesAsync(ct);
        if (state is "installed" or "rolled_back" or "failed")
        {
            await audit.WriteAsync(device.PartnerId, new AuditEntry("agent_update." + state, state == "installed" ? "success" : "failure", device.OrganizationId, device.Id, "agent_release", row.ReleaseId.ToString(),
                new { version, row.Error }, ActorType: "agent", ActorId: device.Id, ActorName: device.Hostname, Ip: conn.RemoteIp), ct);
        }
        if (state == "rolled_back")
        {
            await alerts.RaiseAsync(device, AlertTypes.AgentTamper, "update:" + version, $"Agent update to {version} rolled back on {device.Hostname}", row.Error ?? "The new agent version did not connect and the previous version was restored.", ct);
        }
    }
}

public static partial class ReleaseEndpoints
{
    [GeneratedRegex(@"^\d+\.\d+\.\d+(-[0-9A-Za-z.]{1,20})?$")]
    private static partial Regex VersionPattern();

    private static readonly string[] OsValues = ["windows", "macos", "linux"];
    private static readonly string[] ArchValues = ["amd64", "arm64"];

    public sealed record BinaryRequest(string? Os, string? Arch, Guid BlobId, string? Kind = null);

    private static readonly Dictionary<string, string> InstallerOs = new() { ["msi"] = "windows", ["pkg"] = "macos", ["deb"] = "linux", ["rpm"] = "linux" };

    public sealed record ReleaseRequest(string? Version, string? Notes, BinaryRequest[]? Binaries);

    public sealed record RolloutRequest(string? Ring, bool? Paused);

    public static string SignatureInput(string version, string os, string arch, string sha256) => $"DRANZO-RELEASE-V1\n{version}\n{os}\n{arch}\n{sha256}";

    public static void Map(RouteGroupBuilder api)
    {
        api.MapPut("/releases/upload", async (string? fileName, HttpContext http, Ctx c, BlobService blobs, CancellationToken ct) =>
        {
            const long max = 500L * 1024 * 1024;
            http.Features.Get<IHttpMaxRequestBodySizeFeature>()!.MaxRequestBodySize = max + 1;
            var stored = await blobs.SaveAsync(c.Who.PartnerId, http.Request.Body, fileName ?? "dranzo-agent", "agent-release", max, TimeSpan.FromHours(24), ct);
            if (stored is null || stored.SizeBytes < 1024 * 1024)
            {
                return Api.BadRequest("Upload an agent binary (1 MiB to 500 MiB).");
            }
            await c.Audit("agent_release.upload", targetType: "blob", targetId: stored.Id, detail: new { stored.SizeBytes }, contentSha256: stored.Sha256, ct: ct);
            return Results.Ok(new { blobId = stored.Id, sha256 = stored.Sha256, sizeBytes = stored.SizeBytes });
        }).RequirePermission(Permissions.ReleasesManage, partnerWide: true).RequireStepUp();

        api.MapPost("/releases", async (ReleaseRequest req, Ctx c, ICommandSigner signer, CancellationToken ct) =>
        {
            if (req.Version is null || !VersionPattern().IsMatch(req.Version))
            {
                return Api.BadRequest("version must look like 1.2.3 or 1.2.3-rc1.");
            }
            var binaries = req.Binaries ?? [];
            if (binaries.Length == 0 || binaries.Any(b => !OsValues.Contains(b.Os) || !ArchValues.Contains(b.Arch) || (b.Kind is not (null or "binary") && InstallerOs.GetValueOrDefault(b.Kind) != b.Os))
                || binaries.Select(b => (b.Os, b.Arch, b.Kind ?? "binary")).Distinct().Count() != binaries.Length)
            {
                return Api.BadRequest("binaries: one entry per os (windows, macos, linux), arch (amd64, arm64) and kind (binary, or an installer: msi, pkg, deb, rpm).");
            }
            if (await c.Db.AgentReleases.AnyAsync(r => r.Version == req.Version, ct))
            {
                return Api.Conflict("This version already exists. Versions are immutable; publish a new one.");
            }
            var blobIds = binaries.Select(b => b.BlobId).Distinct().ToList();
            var blobs = await c.Db.Blobs.Where(b => blobIds.Contains(b.Id) && b.Purpose == "agent-release").ToDictionaryAsync(b => b.Id, ct);
            if (blobs.Count != blobIds.Count)
            {
                return Api.BadRequest("Upload every binary first (PUT /releases/upload).");
            }
            var release = new AgentRelease { Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, Version = req.Version, Notes = req.Notes?.Trim() is { Length: <= 4000 } n ? n : "", CreatedAt = c.Now, CreatedByUserId = c.Who.UserId };
            foreach (var b in binaries)
            {
                var blob = blobs[b.BlobId];
                blob.ExpiresAt = null;
                release.Binaries.Add(new AgentReleaseBinary
                {
                    Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, ReleaseId = release.Id, Os = b.Os!, Arch = b.Arch!, Kind = b.Kind ?? "binary", BlobId = blob.Id, Sha256 = blob.Sha256, SizeBytes = blob.SizeBytes,
                    Signature = Convert.ToBase64String(signer.SignRaw(Encoding.UTF8.GetBytes(SignatureInput(req.Version, b.Os!, b.Arch!, blob.Sha256) + (b.Kind is null or "binary" ? "" : "\n" + b.Kind)))), KeyId = signer.KeyId,
                });
            }
            c.Db.AgentReleases.Add(release);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("agent_release.create", targetType: "agent_release", targetId: release.Id,
                detail: new { release.Version, binaries = release.Binaries.Select(b => new { b.Os, b.Arch, b.Sha256 }) }, ct: ct);
            return Results.Created($"/api/v1/releases/{release.Id}", new { release.Id });
        }).RequirePermission(Permissions.ReleasesManage, partnerWide: true).RequireStepUp();

        api.MapGet("/releases", async (Ctx c, CancellationToken ct) =>
        {
            var releases = await c.Db.AgentReleases.AsNoTracking().Include(r => r.Binaries).OrderByDescending(r => r.CreatedAt).ToListAsync(ct);
            var ids = releases.Select(r => r.Id).ToList();
            var states = await c.Db.DeviceUpdateStates.AsNoTracking().Where(s => ids.Contains(s.ReleaseId)).GroupBy(s => new { s.ReleaseId, s.State })
                .Select(g => new { g.Key.ReleaseId, g.Key.State, Count = g.Count() }).ToListAsync(ct);
            var versions = await c.Db.Devices.AsNoTracking().Where(d => d.Status == DeviceStatus.Active).GroupBy(d => d.AgentVersion).Select(g => new { version = g.Key, devices = g.Count() }).ToListAsync(ct);
            return Results.Ok(new
            {
                installedVersions = versions,
                items = releases.Select(r => new
                {
                    r.Id, r.Version, r.Notes, r.Ring, r.Paused, r.CreatedAt,
                    binaries = r.Binaries.Select(b => new { b.Id, b.Os, b.Arch, b.Kind, b.Sha256, b.SizeBytes, b.KeyId }),
                    progress = states.Where(s => s.ReleaseId == r.Id).ToDictionary(s => s.State, s => s.Count),
                }),
            });
        }).RequirePermission(Permissions.ReleasesManage, partnerWide: true);

        api.MapPost("/releases/{id:guid}/rollout", async (Guid id, RolloutRequest req, Ctx c, CancellationToken ct) =>
        {
            var release = await c.Db.AgentReleases.FirstOrDefaultAsync(r => r.Id == id, ct);
            if (release is null)
            {
                return Api.NotFound();
            }
            if (req.Ring is not null)
            {
                if (!UpdateRollout.Rings.Contains(req.Ring))
                {
                    return Api.BadRequest("ring must be none, test, pilot or all.");
                }
                release.Ring = req.Ring;
            }
            release.Paused = req.Paused ?? release.Paused;
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("agent_release.rollout", targetType: "agent_release", targetId: id, detail: new { release.Version, release.Ring, release.Paused }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.ReleasesManage, partnerWide: true).RequireStepUp();

        api.MapGet("/releases/{id:guid}/devices", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            if (!await c.Db.AgentReleases.AnyAsync(r => r.Id == id, ct))
            {
                return Api.NotFound();
            }
            var states = await c.Db.DeviceUpdateStates.AsNoTracking().Where(s => s.ReleaseId == id).OrderByDescending(s => s.UpdatedAt).Take(5000).ToListAsync(ct);
            var deviceIds = states.Select(s => s.DeviceId).ToList();
            var names = await c.Db.Devices.AsNoTracking().Where(d => deviceIds.Contains(d.Id)).ToDictionaryAsync(d => d.Id, d => new { d.Hostname, d.AgentVersion, d.OrganizationId }, ct);
            return Results.Ok(states.Select(s => new { s.DeviceId, hostname = names.GetValueOrDefault(s.DeviceId)?.Hostname, currentVersion = names.GetValueOrDefault(s.DeviceId)?.AgentVersion, s.State, s.Error, s.OfferedAt, s.UpdatedAt }));
        }).RequirePermission(Permissions.ReleasesManage, partnerWide: true);

        // ----- Installer downloads for whoever enrolls devices -----
        api.MapGet("/agent/installers", async (Ctx c, CancellationToken ct) =>
        {
            var releases = await c.Db.AgentReleases.AsNoTracking().Include(r => r.Binaries).ToListAsync(ct);
            var byVersion = Comparer<string>.Create(VersionCompare.Compare);
            // Newest file for each OS / architecture / kind (installers and the plain program for manual installs).
            var newest = releases.SelectMany(r => r.Binaries.Select(b => (Release: r, Binary: b)))
                .GroupBy(x => (x.Binary.Os, x.Binary.Arch, x.Binary.Kind))
                .Select(g => g.OrderByDescending(x => x.Release.Version, byVersion).First())
                .OrderBy(x => x.Binary.Os).ThenBy(x => x.Binary.Arch).ThenBy(x => x.Binary.Kind).ToList();
            return Results.Ok(new
            {
                version = releases.Select(r => r.Version).OrderByDescending(v => v, byVersion).FirstOrDefault(),
                installers = newest.Select(x => new
                {
                    x.Binary.Id, x.Binary.Os, x.Binary.Arch, x.Binary.Kind, x.Binary.Sha256, x.Binary.SizeBytes, version = x.Release.Version,
                    fileName = InstallerFileName(x.Release.Version, x.Binary), url = $"/api/v1/agent/installers/{x.Binary.Id}",
                }),
            });
        }).RequirePermission(Permissions.EnrollmentManage);

        api.MapGet("/agent/installers/{id:guid}", async (Guid id, Ctx c, Dranzo.Infrastructure.Storage.IObjectStore store, HttpContext http, CancellationToken ct) =>
        {
            var binary = await c.Db.AgentReleaseBinaries.AsNoTracking().FirstOrDefaultAsync(b => b.Id == id, ct);
            var release = binary is null ? null : await c.Db.AgentReleases.AsNoTracking().FirstOrDefaultAsync(r => r.Id == binary.ReleaseId, ct);
            var blob = binary is null ? null : await c.Db.Blobs.AsNoTracking().FirstOrDefaultAsync(b => b.Id == binary.BlobId, ct);
            if (binary is null || release is null || blob is null)
            {
                return Api.NotFound();
            }
            await c.Audit("agent_installer.download", targetType: "agent_release", targetId: release.Id, detail: new { release.Version, binary.Os, binary.Arch, binary.Kind }, contentSha256: binary.Sha256, ct: ct);
            http.Response.Headers.ContentDisposition = new System.Net.Mime.ContentDisposition { FileName = InstallerFileName(release.Version, binary), Inline = false }.ToString();
            http.Response.Headers["X-Content-Sha256"] = binary.Sha256;
            return Results.Stream(await store.OpenReadAsync(blob.StorageKey, ct), "application/octet-stream");
        }).RequirePermission(Permissions.EnrollmentManage);

        // ----- Agent controls on one device -----
        api.MapPost("/devices/{id:guid}/uninstall-code", async (Guid id, UninstallCodeRequest req, Ctx c, Jobs.JobService jobs, CancellationToken ct) =>
        {
            var device = await c.Db.Devices.FirstOrDefaultAsync(d => d.Id == id, ct);
            if (device is null)
            {
                return Api.NotFound();
            }
            object spec;
            if (string.IsNullOrEmpty(req.Code))
            {
                spec = new { uninstallCode = (object?)null };
            }
            else
            {
                if (req.Code.Length is < 8 or > 64)
                {
                    return Api.BadRequest("The uninstall code must be 8 to 64 characters.");
                }
                // Only a salted, slow hash goes to the device; the code itself is never stored or logged.
                var salt = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
                const int iterations = 210_000;
                var hash = System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(req.Code), salt, iterations, System.Security.Cryptography.HashAlgorithmName.SHA256, 32);
                spec = new { uninstallCode = new { salt = Convert.ToBase64String(salt), iterations, hash = Convert.ToBase64String(hash) } };
            }
            var created = await jobs.CreateAsync(new Jobs.NewJob("Set agent uninstall code", JobKinds.AgentConfigure, new Jobs.JobTarget(DeviceIds: [id]), spec, 60), [device], c.Who.PartnerId, c.Who.UserId, c.Who.Name, ct);
            device.UninstallCodeSet = !string.IsNullOrEmpty(req.Code);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("device.uninstall_code", organizationId: device.OrganizationId, deviceId: id, targetType: "device", targetId: id, detail: new { set = device.UninstallCodeSet }, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id });
        }).RequirePermission(Permissions.DevicesManage).RequireStepUp();

        api.MapPost("/devices/{id:guid}/uninstall-agent", async (Guid id, Ctx c, Jobs.JobService jobs, CancellationToken ct) =>
        {
            var device = await c.Db.Devices.FirstOrDefaultAsync(d => d.Id == id, ct);
            if (device is null)
            {
                return Api.NotFound();
            }
            var created = await jobs.CreateAsync(new Jobs.NewJob("Uninstall agent", JobKinds.AgentUninstall, new Jobs.JobTarget(DeviceIds: [id]), new { }, 300), [device], c.Who.PartnerId, c.Who.UserId, c.Who.Name, ct);
            await c.Audit("device.uninstall_agent", organizationId: device.OrganizationId, deviceId: id, targetType: "device", targetId: id, detail: new { device.Hostname }, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id });
        }).RequirePermission(Permissions.DevicesRevoke).RequireStepUp();
    }

    public sealed record UninstallCodeRequest(string? Code);

    private static string InstallerFileName(string version, AgentReleaseBinary b) => b.Kind == "binary"
        ? $"dranzo-agent-{version}-{b.Os}-{b.Arch}{(b.Os == "windows" ? ".exe" : "")}"
        : $"DranzoAgent-{version}-{b.Os}-{b.Arch}.{b.Kind}";
}

/// <summary>When the agent confirms it removed itself, its certificate is revoked.</summary>
public sealed class AgentUninstallResultHandler(DranzoDbContext db, AgentRegistry agents, IAuditLog audit) : Jobs.IJobResultHandler
{
    public bool Handles(string kind) => kind == JobKinds.AgentUninstall;

    public async Task HandleAsync(JobRun run, Device device, JsonElement result, CancellationToken ct)
    {
        if (run.Status != JobRunStatus.Succeeded)
        {
            return;
        }
        await db.Devices.Where(d => d.Id == device.Id).ExecuteUpdateAsync(s => s.SetProperty(d => d.Status, DeviceStatus.Revoked)
            .SetProperty(d => d.CertThumbprint, (string?)null).SetProperty(d => d.PrevCertThumbprint, (string?)null).SetProperty(d => d.IsOnline, false), ct);
        await RadiusEndpoints.RevokeDeviceCertificatesAsync(db, device.PartnerId, device.Id, DateTimeOffset.UtcNow, ct);
        agents.Disconnect(device.Id, "agent uninstalled");
        await audit.WriteAsync(device.PartnerId, new AuditEntry("device.revoke", OrganizationId: device.OrganizationId, DeviceId: device.Id, TargetType: "device", TargetId: device.Id.ToString(),
            Detail: new { device.Hostname, reason = "agent uninstalled", jobRunId = run.Id }, ActorType: "user", ActorId: run.Job.RequestedByUserId, ActorName: run.Job.RequestedByName), ct);
    }
}
