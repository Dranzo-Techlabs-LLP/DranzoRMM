using System.Text.Json;
using System.Text.RegularExpressions;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Jobs;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

public sealed class SoftwareInventoryProcessor(DranzoDbContext db, VulnerabilityMatcher matcher, AlertEngine alerts, TimeProvider clock) : IAgentMessageProcessor
{
    public const int MaxItems = 5000;

    public string Type => "software.inventory";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var hash = Dranzo.Infrastructure.Security.Hashing.Sha256Hex(payload.TryGetProperty("items", out var rawItems) ? rawItems.GetRawText() : "");
        if (conn.LastReportHash.TryGetValue(Type, out var last) && last == hash)
        {
            return; // unchanged since the last report on this connection
        }
        conn.LastReportHash[Type] = hash;
        var device = await db.Devices.AsNoTracking().FirstAsync(d => d.Id == conn.DeviceId, ct);
        var now = clock.GetUtcNow();
        var items = payload.Arr("items", MaxItems).Where(i => i.ValueKind == JsonValueKind.Object).Select(i => new InstalledSoftware
        {
            Id = Guid.NewGuid(), PartnerId = device.PartnerId, OrganizationId = device.OrganizationId, DeviceId = device.Id,
            Name = i.Str("name", 256), Version = i.Str("version", 128), Publisher = i.StrOrNull("publisher", 256), Source = i.Str("source", 16, "unknown"),
            PackageId = i.StrOrNull("id", 256), InstallDate = i.Time("installDate"), SeenAt = now,
        }).Where(s => s.Name.Length > 0).ToList();
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.InstalledSoftware.Where(s => s.DeviceId == device.Id).ExecuteDeleteAsync(ct);
        db.InstalledSoftware.AddRange(items);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        await matcher.MatchDeviceAsync(device.Id, ct);
        await alerts.EvaluateDeviceAsync(device.Id, ct);
    }
}

/// <summary>After an install or uninstall finishes, ask the agent for a fresh software list.</summary>
public sealed class SoftwareResultHandler(JobService jobs, DranzoDbContext db) : IJobResultHandler
{
    public bool Handles(string kind) => kind is JobKinds.SoftwareInstall or JobKinds.SoftwareUninstall or JobKinds.PackageInstall or JobKinds.PackageUninstall;

    public async Task HandleAsync(JobRun run, Device device, JsonElement result, CancellationToken ct)
    {
        if (run.Status != JobRunStatus.Succeeded)
        {
            return;
        }
        var already = await db.JobRuns.AnyAsync(r => r.DeviceId == device.Id && r.Kind == JobKinds.SoftwareScan && r.Status == JobRunStatus.Pending, ct);
        if (!already)
        {
            await jobs.CreateAsync(new NewJob("Refresh software inventory", JobKinds.SoftwareScan, new JobTarget(DeviceIds: [device.Id]), new { }, 300, IsSystem: true), [device], device.PartnerId, null, "system", ct);
        }
    }
}

public static partial class SoftwareEndpoints
{
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9+._:@/-]{0,199}$")]
    public static partial Regex PackageIdPattern();

    private static readonly Dictionary<string, (string Os, string[] Extensions)> PackageTypes = new()
    {
        ["msi"] = ("windows", [".msi"]), ["exe"] = ("windows", [".exe"]),
        ["pkg"] = ("macos", [".pkg"]), ["dmg"] = ("macos", [".dmg"]),
        ["deb"] = ("linux", [".deb"]), ["rpm"] = ("linux", [".rpm"]),
    };

    private static readonly string[] DetectionTypes = ["file", "registry", "pkgutil", "dpkg", "rpm", "winget", "brew", "app"];

    public sealed record DeployRequest(string? Action, string? Name, Dictionary<string, string>? Packages, string? Version, JobEndpoints.TargetRequest? Target, int? MaxAttempts, int? TimeoutSeconds);

    public sealed record Detection(string? Type, string? Key, string? ValueName, string? MinVersion);

    public sealed record PackageRequest(string? Name, string? Version, string? Type, Guid BlobId, string[]? InstallArgs, string[]? UninstallCommand, Detection? Detection, Guid? OrganizationId);

    public sealed record PackageDeployRequest(string? Action, JobEndpoints.TargetRequest? Target, int? MaxAttempts, int? TimeoutSeconds);

    private static bool ArgsOk(string[]? args) => args is null || (args.Length <= 32 && args.All(a => a is not null && a.Length <= 1024 && !a.Contains('\0')));

    public static void Map(RouteGroupBuilder api)
    {
        // ----- Inventory -----
        api.MapGet("/devices/{id:guid}/software", async (Guid id, string? search, Ctx c, CancellationToken ct) =>
        {
            if (!await c.Db.Devices.AnyAsync(d => d.Id == id, ct))
            {
                return Api.NotFound();
            }
            var q = c.Db.InstalledSoftware.AsNoTracking().Where(s => s.DeviceId == id);
            if (!string.IsNullOrWhiteSpace(search))
            {
                q = q.Where(s => EF.Functions.ILike(s.Name, "%" + Api.LikeLiteral(search) + "%", Api.LikeEscape));
            }
            return Results.Ok(await q.OrderBy(s => s.Name).Take(SoftwareInventoryProcessor.MaxItems)
                .Select(s => new { s.Name, s.Version, s.Publisher, s.Source, s.PackageId, s.InstallDate, s.SeenAt }).ToListAsync(ct));
        }).RequirePermission(Permissions.SoftwareRead);

        api.MapGet("/software", async (Guid? organizationId, string? search, int? page, int? pageSize, Ctx c, CancellationToken ct) =>
        {
            var (skip, take, p) = Api.Paging(page, pageSize);
            var q = c.Db.InstalledSoftware.AsNoTracking().Where(s => organizationId == null || s.OrganizationId == organizationId);
            if (!string.IsNullOrWhiteSpace(search))
            {
                q = q.Where(s => EF.Functions.ILike(s.Name, "%" + Api.LikeLiteral(search) + "%", Api.LikeEscape));
            }
            var grouped = q.GroupBy(s => new { s.Name, s.Publisher }).Select(g => new { g.Key.Name, g.Key.Publisher, devices = g.Select(x => x.DeviceId).Distinct().Count(), versions = g.Select(x => x.Version).Distinct().Count() });
            var total = await grouped.CountAsync(ct);
            return Results.Ok(new { total, page = p, pageSize = take, items = await grouped.OrderByDescending(x => x.devices).ThenBy(x => x.Name).Skip(skip).Take(take).ToListAsync(ct) });
        }).RequirePermission(Permissions.SoftwareRead);

        api.MapGet("/software/devices", async (string name, Guid? organizationId, Ctx c, CancellationToken ct) =>
            Results.Ok(await c.Db.InstalledSoftware.AsNoTracking().Where(s => s.Name == name && (organizationId == null || s.OrganizationId == organizationId))
                .OrderBy(s => s.Device.Hostname).Take(2000).Select(s => new { s.DeviceId, hostname = s.Device.Hostname, s.OrganizationId, s.Version, s.Source }).ToListAsync(ct)))
            .RequirePermission(Permissions.SoftwareRead);

        // ----- Package-manager deployment (winget / Homebrew / apt / dnf) -----
        api.MapPost("/software/deploy", async (DeployRequest req, Ctx c, JobService jobs, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
        {
            if (req.Action is not ("install" or "uninstall"))
            {
                return Api.BadRequest("action must be install or uninstall.");
            }
            var packages = req.Packages ?? [];
            if (packages.Count == 0 || packages.Any(kv => kv.Key is not ("winget" or "brew" or "apt" or "dnf") || !PackageIdPattern().IsMatch(kv.Value ?? "")
                || kv.Value!.Contains("://", StringComparison.Ordinal) || kv.Value.StartsWith('/') || kv.Value.Contains("..", StringComparison.Ordinal)))
            {
                return Api.BadRequest("packages must map winget/brew/apt/dnf to a valid package id.");
            }
            if (req.Version is not null && !PackageIdPattern().IsMatch(req.Version))
            {
                return Api.BadRequest("Invalid version.");
            }
            var (target, devices, error) = await JobEndpoints.ResolveTargetAsync(req.Target, c, jobs, ct);
            if (error is not null)
            {
                return error;
            }
            if (devices.Count == 0)
            {
                return Api.BadRequest("The target matches no devices.");
            }
            if (JobEndpoints.NeedsStepUp(target!, devices.Count, false, opt.Value) && !StepUp.IsFresh(c.Who, opt.Value, clock))
            {
                return StepUp.Required();
            }
            var name = Api.CleanName(req.Name) ?? $"{(req.Action == "install" ? "Install" : "Uninstall")} {packages.Values.First()}";
            var kind = req.Action == "install" ? JobKinds.SoftwareInstall : JobKinds.SoftwareUninstall;
            var created = await jobs.CreateAsync(new NewJob(name, kind, target!, new { packages, version = req.Version }, req.TimeoutSeconds ?? 1800, MaxAttempts: req.MaxAttempts ?? 2),
                devices, c.Who.PartnerId, c.Who.IsApiKey ? null : c.Who.UserId, c.Who.Name, ct);
            await c.Audit("software." + req.Action, organizationId: created.Job.OrganizationId, targetType: "job", targetId: created.Job.Id, detail: new { packages, req.Version, devices = devices.Count, target }, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id, deviceCount = devices.Count });
        }).RequirePermission(Permissions.SoftwareDeploy);

        // ----- Custom packages -----
        // Step 1: upload the installer as the raw request body. The server computes the SHA-256.
        api.MapPut("/packages/upload", async (string fileName, HttpContext http, Ctx c, BlobService blobs, IOptions<DranzoOptions> opt, CancellationToken ct) =>
        {
            var max = opt.Value.Storage.MaxPackageBytes;
            http.Features.Get<IHttpMaxRequestBodySizeFeature>()!.MaxRequestBodySize = max + 1;
            if (http.Request.ContentLength > max)
            {
                return Api.Error(413, "too_large", $"Packages are limited to {max} bytes.");
            }
            var ext = Path.GetExtension(BlobService.SafeFileName(fileName)).ToLowerInvariant();
            if (!PackageTypes.Values.Any(t => t.Extensions.Contains(ext)))
            {
                return Api.BadRequest("File type must be one of: msi, exe, pkg, dmg, deb, rpm.");
            }
            var stored = await blobs.SaveAsync(c.Who.PartnerId, http.Request.Body, fileName, "package", max, TimeSpan.FromHours(24), ct);
            if (stored is null)
            {
                return Api.Error(413, "too_large", "Upload was empty or exceeded the size limit.");
            }
            await c.Audit("package.upload", targetType: "blob", targetId: stored.Id, detail: new { fileName = BlobService.SafeFileName(fileName), stored.SizeBytes }, contentSha256: stored.Sha256, ct: ct);
            return Results.Ok(new { blobId = stored.Id, sha256 = stored.Sha256, sizeBytes = stored.SizeBytes });
        }).RequirePermission(Permissions.PackagesManage);

        // Step 2: describe the uploaded file.
        api.MapPost("/packages", async (PackageRequest req, Ctx c, CancellationToken ct) =>
        {
            if (Api.CleanName(req.Name) is not { } name)
            {
                return Api.BadRequest("Name is required.");
            }
            if (req.Type is null || !PackageTypes.TryGetValue(req.Type, out var typeInfo))
            {
                return Api.BadRequest("type must be msi, exe, pkg, dmg, deb or rpm.");
            }
            if (!ArgsOk(req.InstallArgs) || !ArgsOk(req.UninstallCommand) || (req.Version?.Length ?? 0) > 64)
            {
                return Api.BadRequest("Invalid installArgs, uninstallCommand or version.");
            }
            if (req.Detection is { } d && (!DetectionTypes.Contains(d.Type) || string.IsNullOrEmpty(d.Key) || d.Key.Length > 512 || (d.ValueName?.Length ?? 0) > 256 || (d.MinVersion?.Length ?? 0) > 64))
            {
                return Api.BadRequest("Invalid detection rule.");
            }
            if (req.OrganizationId is { } org ? !c.Tenant.CoversOrganization(org) || !await c.Db.Organizations.AnyAsync(o => o.Id == org, ct) : !c.Tenant.AllOrgs)
            {
                return req.OrganizationId is null ? Api.Error(403, "forbidden", "Shared packages need partner-wide scope; set organizationId.") : Api.NotFound();
            }
            var blob = await c.Db.Blobs.FirstOrDefaultAsync(b => b.Id == req.BlobId && b.Purpose == "package", ct);
            if (blob is null)
            {
                return Api.BadRequest("Upload the file first (PUT /packages/upload).");
            }
            if (!typeInfo.Extensions.Contains(Path.GetExtension(blob.FileName).ToLowerInvariant()))
            {
                return Api.BadRequest("The uploaded file's extension does not match the package type.");
            }
            blob.ExpiresAt = null; // attached: no longer a temporary upload
            var package = new Package
            {
                Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = req.OrganizationId, Name = name, Version = req.Version ?? "", Os = typeInfo.Os, Type = req.Type,
                BlobId = blob.Id, InstallArgsJson = JsonSerializer.Serialize(req.InstallArgs ?? []), UninstallCommandJson = JsonSerializer.Serialize(req.UninstallCommand ?? []),
                DetectionJson = req.Detection is null ? null : JsonSerializer.Serialize(req.Detection, JsonSerializerOptions.Web), CreatedAt = c.Now, CreatedByUserId = c.Who.UserId,
            };
            c.Db.Packages.Add(package);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("package.create", organizationId: package.OrganizationId, targetType: "package", targetId: package.Id, detail: new { name, package.Type, package.Version, blob.FileName }, contentSha256: blob.Sha256, ct: ct);
            return Results.Created($"/api/v1/packages/{package.Id}", new { package.Id });
        }).RequirePermission(Permissions.PackagesManage);

        api.MapGet("/packages", async (Ctx c, CancellationToken ct) =>
        {
            var packages = await c.Db.Packages.AsNoTracking().Where(p => p.DeletedAt == null).OrderBy(p => p.Name).ToListAsync(ct);
            var blobIds = packages.Select(p => p.BlobId).ToList();
            // Packages were loaded through the tenant filter; their blobs are partner-checked.
            var blobs = await c.Db.Blobs.IgnoreQueryFilters().AsNoTracking().Where(b => b.PartnerId == c.Who.PartnerId && blobIds.Contains(b.Id)).ToDictionaryAsync(b => b.Id, ct);
            return Results.Ok(packages.Select(p => new
            {
                p.Id, p.OrganizationId, p.Name, p.Version, p.Os, p.Type, p.CreatedAt,
                fileName = blobs.GetValueOrDefault(p.BlobId)?.FileName, sizeBytes = blobs.GetValueOrDefault(p.BlobId)?.SizeBytes, sha256 = blobs.GetValueOrDefault(p.BlobId)?.Sha256,
                installArgs = JsonSerializer.Deserialize<string[]>(p.InstallArgsJson), uninstallCommand = JsonSerializer.Deserialize<string[]>(p.UninstallCommandJson),
                detection = p.DetectionJson is null ? (JsonElement?)null : JsonSerializer.Deserialize<JsonElement>(p.DetectionJson),
            }));
        }).RequirePermission(Permissions.SoftwareRead);

        api.MapDelete("/packages/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var package = await c.Db.Packages.FirstOrDefaultAsync(p => p.Id == id && p.DeletedAt == null, ct);
            if (package is null || (package.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            package.DeletedAt = c.Now;
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("package.delete", organizationId: package.OrganizationId, targetType: "package", targetId: id, detail: new { package.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.PackagesManage);

        api.MapPost("/packages/{id:guid}/deploy", async (Guid id, PackageDeployRequest req, Ctx c, JobService jobs, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
        {
            var package = await c.Db.Packages.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id && p.DeletedAt == null, ct);
            if (package is null)
            {
                return Api.NotFound();
            }
            if (req.Action is not ("install" or "uninstall"))
            {
                return Api.BadRequest("action must be install or uninstall.");
            }
            var uninstall = JsonSerializer.Deserialize<string[]>(package.UninstallCommandJson) ?? [];
            if (req.Action == "uninstall" && uninstall.Length == 0)
            {
                return Api.BadRequest("This package has no uninstall command.");
            }
            var (target, devices, error) = await JobEndpoints.ResolveTargetAsync(req.Target, c, jobs, ct);
            if (error is not null)
            {
                return error;
            }
            if (devices.Count == 0)
            {
                return Api.BadRequest("The target matches no devices.");
            }
            if (package.OrganizationId is { } pkgOrg && devices.Any(d => d.OrganizationId != pkgOrg))
            {
                return Api.BadRequest("This package belongs to one organization and cannot be deployed to another.");
            }
            if (JobEndpoints.NeedsStepUp(target!, devices.Count, false, opt.Value) && !StepUp.IsFresh(c.Who, opt.Value, clock))
            {
                return StepUp.Required();
            }
            var blob = await c.Db.Blobs.IgnoreQueryFilters().AsNoTracking().FirstAsync(b => b.Id == package.BlobId && b.PartnerId == c.Who.PartnerId, ct);
            var detection = package.DetectionJson is null ? (JsonElement?)null : JsonSerializer.Deserialize<JsonElement>(package.DetectionJson);
            object spec = req.Action == "install"
                ? new { os = package.Os, blobId = blob.Id, sha256 = blob.Sha256, sizeBytes = blob.SizeBytes, fileName = blob.FileName, type = package.Type, installArgs = JsonSerializer.Deserialize<string[]>(package.InstallArgsJson), detection }
                : new { os = package.Os, type = package.Type, uninstallCommand = uninstall, detection };
            var kind = req.Action == "install" ? JobKinds.PackageInstall : JobKinds.PackageUninstall;
            var created = await jobs.CreateAsync(new NewJob($"{(req.Action == "install" ? "Install" : "Uninstall")} {package.Name} {package.Version}".Trim(), kind, target!, spec,
                req.TimeoutSeconds ?? 3600, MaxAttempts: req.MaxAttempts ?? 2, ContentSha256: blob.Sha256), devices, c.Who.PartnerId, c.Who.IsApiKey ? null : c.Who.UserId, c.Who.Name, ct);
            await c.Audit("package." + req.Action, organizationId: created.Job.OrganizationId, targetType: "job", targetId: created.Job.Id,
                detail: new { package = package.Name, packageId = package.Id, package.Version, devices = devices.Count, target }, contentSha256: blob.Sha256, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id, deviceCount = devices.Count });
        }).RequirePermission(Permissions.SoftwareDeploy);
    }
}
