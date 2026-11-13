using System.Text.Json;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Jobs;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

public sealed class PostureProcessor(DranzoDbContext db, AlertEngine alerts, TimeProvider clock) : IAgentMessageProcessor
{
    private const int KeepSnapshots = 5;

    public string Type => "posture";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        if (payload.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("posture payload must be an object");
        }
        var device = await db.Devices.FirstAsync(d => d.Id == conn.DeviceId, ct);
        var unsupported = payload.StrArr("unsupported", 32, 32);
        var av = payload.Arr("antivirus", 32).Where(a => a.ValueKind == JsonValueKind.Object).ToList();
        bool? avOk = unsupported.Contains("antivirus") ? null
            : av.Count > 0 ? av.Any(a => a.Bool("enabled") && a.BoolOrNull("upToDate") != false)
            : device.Os == "linux" ? null : false; // no AV product on Linux is common and not treated as a failure
        bool? fwOk = unsupported.Contains("firewall") ? null : payload.Obj("firewall").BoolOrNull("enabled");
        var volumes = payload.Arr("diskEncryption", 64).Where(a => a.ValueKind == JsonValueKind.Object).ToList();
        bool? encOk = unsupported.Contains("diskEncryption") || volumes.Count == 0 ? null : volumes.All(v => v.Str("status", 16) is "encrypted" or "in_progress");
        var admins = payload.StrArr("localAdmins", 200, 128).Distinct().Order().ToArray();

        var previous = await db.PostureSnapshots.Where(p => p.DeviceId == device.Id && p.IsLatest).FirstOrDefaultAsync(ct);
        var newAdmins = previous is null ? [] : admins.Except(previous.LocalAdmins, StringComparer.OrdinalIgnoreCase).ToArray();
        if (previous is not null)
        {
            previous.IsLatest = false;
        }
        db.PostureSnapshots.Add(new PostureSnapshot
        {
            Id = Guid.NewGuid(), PartnerId = device.PartnerId, OrganizationId = device.OrganizationId, DeviceId = device.Id, CollectedAt = clock.GetUtcNow(), IsLatest = true,
            DataJson = payload.GetRawText(), AntivirusOk = avOk, FirewallOk = fwOk, EncryptionOk = encOk, LocalAdmins = admins,
        });
        device.PendingReboot = payload.BoolOrNull("pendingReboot") ?? device.PendingReboot;
        await db.SaveChangesAsync(ct);
        var stale = await db.PostureSnapshots.Where(i => i.DeviceId == device.Id).OrderByDescending(i => i.CollectedAt).Skip(KeepSnapshots).Select(i => i.Id).ToListAsync(ct);
        if (stale.Count > 0)
        {
            await db.PostureSnapshots.Where(i => stale.Contains(i.Id)).ExecuteDeleteAsync(ct);
        }

        foreach (var admin in newAdmins)
        {
            await alerts.RaiseAsync(device, AlertTypes.LocalAdminNew, "admin:" + admin.ToLowerInvariant(), $"New local administrator on {device.Hostname}", $"Account '{admin}' is now a local administrator.", ct);
        }
        await alerts.EvaluateDeviceAsync(device.Id, ct);
    }
}

public static class SecurityEndpoints
{
    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/security/posture", async (Guid? organizationId, Ctx c, CancellationToken ct) =>
        {
            var devices = await c.Db.Devices.AsNoTracking().Where(d => d.Status == DeviceStatus.Active && (organizationId == null || d.OrganizationId == organizationId))
                .Select(d => new { d.Id, d.Hostname, d.OrganizationId, d.Os, d.IsOnline, d.PendingReboot, d.LastPatchInstallAt }).ToListAsync(ct);
            var posture = await c.Db.PostureSnapshots.AsNoTracking().Where(p => p.IsLatest && (organizationId == null || p.OrganizationId == organizationId))
                .Select(p => new { p.DeviceId, p.CollectedAt, p.AntivirusOk, p.FirewallOk, p.EncryptionOk, p.LocalAdmins }).ToDictionaryAsync(p => p.DeviceId, ct);
            var vulns = await c.Db.DeviceVulnerabilities.AsNoTracking().Where(v => organizationId == null || v.OrganizationId == organizationId)
                .GroupBy(v => v.DeviceId).Select(g => new { DeviceId = g.Key, Total = g.Count(), Kev = g.Count(x => x.KnownExploited), Critical = g.Count(x => x.Severity == "critical") }).ToDictionaryAsync(x => x.DeviceId, ct);
            var scoreInputs = await SecurityScore.LoadAsync(c.Db, organizationId, null, ct);
            var items = devices.Select(d =>
            {
                var p = posture.GetValueOrDefault(d.Id);
                var v = vulns.GetValueOrDefault(d.Id);
                var score = scoreInputs.TryGetValue(d.Id, out var inputs) ? SecurityScore.Compute(inputs, c.Now) : null;
                return new
                {
                    score = score?.Score, grade = score?.Grade ?? "?",
                    d.Id, d.Hostname, d.OrganizationId, d.Os, d.IsOnline, d.PendingReboot, lastPatchDate = d.LastPatchInstallAt, collectedAt = p?.CollectedAt,
                    antivirusOk = p?.AntivirusOk, firewallOk = p?.FirewallOk, encryptionOk = p?.EncryptionOk, localAdmins = p?.LocalAdmins ?? [],
                    vulnerabilities = v?.Total ?? 0, knownExploited = v?.Kev ?? 0, criticalVulnerabilities = v?.Critical ?? 0,
                };
            }).OrderBy(x => x.Hostname).ToList();
            return Results.Ok(new
            {
                total = items.Count,
                antivirusIssues = items.Count(i => i.antivirusOk == false), firewallIssues = items.Count(i => i.firewallOk == false), encryptionIssues = items.Count(i => i.encryptionOk == false),
                notReporting = items.Count(i => i.collectedAt is null), withKnownExploited = items.Count(i => i.knownExploited > 0),
                averageScore = items.Any(i => i.score is not null) ? (int?)Math.Round(items.Where(i => i.score is not null).Average(i => i.score!.Value)) : null,
                items,
            });
        }).RequirePermission(Permissions.SecurityRead);

        api.MapGet("/devices/{id:guid}/posture", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            if (!await c.Db.Devices.AnyAsync(d => d.Id == id, ct))
            {
                return Api.NotFound();
            }
            var p = await c.Db.PostureSnapshots.AsNoTracking().Where(x => x.DeviceId == id && x.IsLatest).FirstOrDefaultAsync(ct);
            // "null" (not an empty body) when the device has not reported yet.
            return p is null ? Results.Content("null", "application/json") : Results.Ok(new { p.CollectedAt, p.AntivirusOk, p.FirewallOk, p.EncryptionOk, p.LocalAdmins, data = JsonSerializer.Deserialize<JsonElement>(p.DataJson) });
        }).RequirePermission(Permissions.SecurityRead);

        api.MapGet("/devices/{id:guid}/security-score", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            if (!await c.Db.Devices.AnyAsync(d => d.Id == id, ct))
            {
                return Api.NotFound();
            }
            var inputs = await SecurityScore.LoadAsync(c.Db, null, id, ct);
            // Revoked devices have no score.
            return inputs.TryGetValue(id, out var i) ? Results.Ok(SecurityScore.Compute(i, c.Now)) : Results.Content("null", "application/json");
        }).RequirePermission(Permissions.SecurityRead);

        api.MapGet("/devices/{id:guid}/vulnerabilities", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            if (!await c.Db.Devices.AnyAsync(d => d.Id == id, ct))
            {
                return Api.NotFound();
            }
            return Results.Ok(await c.Db.DeviceVulnerabilities.AsNoTracking().Where(v => v.DeviceId == id).OrderByDescending(v => v.KnownExploited).ThenByDescending(v => v.CvssScore)
                .Select(v => new { v.CveId, v.SoftwareName, v.SoftwareVersion, v.Severity, v.CvssScore, v.KnownExploited, v.DetectedAt }).Take(2000).ToListAsync(ct));
        }).RequirePermission(Permissions.SecurityRead);

        api.MapGet("/vulnerabilities", async (Guid? organizationId, string? severity, bool? knownExploited, int? page, int? pageSize, Ctx c, CancellationToken ct) =>
        {
            var (skip, take, p) = Api.Paging(page, pageSize);
            var q = c.Db.DeviceVulnerabilities.AsNoTracking().Where(v => (organizationId == null || v.OrganizationId == organizationId) && (severity == null || v.Severity == severity) && (knownExploited == null || v.KnownExploited == knownExploited));
            var grouped = q.GroupBy(v => new { v.CveId, v.Severity, v.CvssScore, v.KnownExploited })
                .Select(g => new { g.Key.CveId, g.Key.Severity, g.Key.CvssScore, g.Key.KnownExploited, devices = g.Select(x => x.DeviceId).Distinct().Count(), software = g.Min(x => x.SoftwareName) });
            var total = await grouped.CountAsync(ct);
            var rows = await grouped.OrderByDescending(x => x.KnownExploited).ThenByDescending(x => x.CvssScore).ThenByDescending(x => x.devices).Skip(skip).Take(take).ToListAsync(ct);
            var ids = rows.Select(r => r.CveId).ToList();
            var summaries = await c.Db.CveEntries.AsNoTracking().Where(e => ids.Contains(e.Id)).Select(e => new { e.Id, e.Summary, e.Published }).ToDictionaryAsync(e => e.Id, ct);
            return Results.Ok(new
            {
                total, page = p, pageSize = take,
                items = rows.Select(r => new { r.CveId, r.Severity, r.CvssScore, r.KnownExploited, r.devices, r.software, summary = summaries.GetValueOrDefault(r.CveId)?.Summary, published = summaries.GetValueOrDefault(r.CveId)?.Published }),
                note = "Matches are heuristic (name and version against NVD). Distribution packages (deb/rpm/snap/flatpak) and operating-system CVEs are not matched.",
            });
        }).RequirePermission(Permissions.SecurityRead);

        api.MapGet("/vulnerabilities/feed-status", async (Ctx c, CancellationToken ct) =>
            Results.Ok(new { feeds = await c.Db.FeedStates.AsNoTracking().ToListAsync(ct), cveCount = await c.Db.CveEntries.CountAsync(ct), knownExploited = await c.Db.CveEntries.CountAsync(e => e.KnownExploited, ct) }))
            .RequirePermission(Permissions.SecurityRead);

        api.MapPost("/security/scan", async (JobEndpoints.TargetRequest req, Ctx c, JobService jobs, CancellationToken ct) =>
        {
            var (target, devices, error) = await JobEndpoints.ResolveTargetAsync(req, c, jobs, ct);
            if (error is not null)
            {
                return error;
            }
            if (devices.Count == 0)
            {
                return Api.BadRequest("The target matches no devices.");
            }
            var created = await jobs.CreateAsync(new NewJob("Security posture scan", JobKinds.PostureScan, target!, new { }, 600), devices, c.Who.PartnerId, c.Who.IsApiKey ? null : c.Who.UserId, c.Who.Name, ct);
            await c.Audit("security.scan", organizationId: created.Job.OrganizationId, targetType: "job", targetId: created.Job.Id, detail: new { devices = devices.Count }, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id, deviceCount = devices.Count });
        }).RequirePermission(Permissions.DevicesManage);
    }
}
