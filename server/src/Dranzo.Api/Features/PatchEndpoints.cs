using System.Text.Json;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Jobs;
using Dranzo.Api.Services;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

public static class PatchRules
{
    public static readonly string[] Sources = ["wua", "softwareupdate", "apt", "dnf", "winget", "brew"];
    public static readonly string[] Severities = ["critical", "important", "moderate", "low", "unspecified"];
    public static readonly string[] RebootModes = ["never", "if_required", "force"];

    public static string NormalizeSeverity(string s) => s.ToLowerInvariant() switch
    {
        "critical" => "critical",
        "important" or "high" => "important",
        "moderate" or "medium" => "moderate",
        "low" => "low",
        _ => "unspecified",
    };

    /// <summary>The policy that governs a device: an organization-specific one wins over a shared one.</summary>
    public static PatchPolicy? PolicyFor(IEnumerable<PatchPolicy> policies, Guid organizationId) =>
        policies.Where(p => p.Enabled && (p.OrganizationId == organizationId || p.OrganizationId == null))
            .OrderByDescending(p => p.OrganizationId != null).ThenBy(p => p.CreatedAt).FirstOrDefault();

    public static bool AutoApproves(PatchPolicy p, PatchCatalogEntry e) =>
        (p.Sources.Length == 0 || p.Sources.Contains(e.Source))
        && (p.AutoApproveSeverities.Contains(e.Severity) || p.AutoApproveCategories.Contains(e.Category, StringComparer.OrdinalIgnoreCase));
}

/// <summary>Ingests the agent's list of pending updates.</summary>
public sealed class PatchStateProcessor(DranzoDbContext db, AlertEngine alerts, TimeProvider clock) : IAgentMessageProcessor
{
    public string Type => "patch.state";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var device = await db.Devices.FirstAsync(d => d.Id == conn.DeviceId, ct);
        var now = clock.GetUtcNow();
        var reported = payload.Arr("pending", 2000).Where(i => i.ValueKind == JsonValueKind.Object)
            .Select(i => new
            {
                Source = i.Str("source", 16), UpdateId = i.Str("id", 200), Title = i.Str("title", 300), Kb = i.StrOrNull("kb", 32), Category = i.Str("category", 64),
                Severity = PatchRules.NormalizeSeverity(i.Str("severity", 16)), Current = i.StrOrNull("currentVersion", 64), New = i.StrOrNull("newVersion", 64), Reboot = i.Bool("requiresReboot"),
            })
            .Where(i => PatchRules.Sources.Contains(i.Source) && i.UpdateId.Length > 0)
            .GroupBy(i => (i.Source, i.UpdateId)).Select(g => g.First()).ToList();

        var keys = reported.Select(r => r.UpdateId).ToList();
        var catalog = await db.PatchCatalog.Where(e => e.OrganizationId == device.OrganizationId && keys.Contains(e.UpdateId)).ToListAsync(ct);
        // Several devices often report the same new update at the same moment: insert catalog rows conflict-safe, then reload.
        // At most 500 new catalog entries per report: a device cannot grow the catalog without bound.
        var missing = reported.Where(r => !catalog.Any(e => e.Source == r.Source && e.UpdateId == r.UpdateId)).Take(500).ToList();
        reported = [.. reported.Where(r => catalog.Any(e => e.Source == r.Source && e.UpdateId == r.UpdateId) || missing.Contains(r))];
        foreach (var r in missing)
        {
            var title = r.Title.Length > 0 ? r.Title : r.UpdateId;
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                INSERT INTO "PatchCatalog" ("Id", "PartnerId", "OrganizationId", "Source", "UpdateId", "Title", "Kb", "Category", "Severity", "FirstSeenAt")
                VALUES ({Guid.NewGuid()}, {device.PartnerId}, {device.OrganizationId}, {r.Source}, {r.UpdateId}, {title}, {r.Kb}, {r.Category}, {r.Severity}, {now})
                ON CONFLICT ("PartnerId", "OrganizationId", "Source", "UpdateId") DO NOTHING
                """, ct);
        }
        if (missing.Count > 0)
        {
            catalog = await db.PatchCatalog.Where(e => e.OrganizationId == device.OrganizationId && keys.Contains(e.UpdateId)).ToListAsync(ct);
        }
        var policy = PatchRules.PolicyFor(await db.PatchPolicies.Where(p => p.PartnerId == device.PartnerId).ToListAsync(ct), device.OrganizationId);
        var states = await db.DevicePatchStates.Include(s => s.CatalogEntry).Where(s => s.DeviceId == device.Id).ToListAsync(ct);

        var seen = new HashSet<Guid>();
        foreach (var r in reported)
        {
            var entry = catalog.First(e => e.Source == r.Source && e.UpdateId == r.UpdateId);
            seen.Add(entry.Id);
            var state = states.FirstOrDefault(s => s.CatalogEntryId == entry.Id);
            if (state is null)
            {
                state = new DevicePatchState
                {
                    Id = Guid.NewGuid(), PartnerId = device.PartnerId, OrganizationId = device.OrganizationId, DeviceId = device.Id, CatalogEntryId = entry.Id, CatalogEntry = entry,
                    Status = policy is not null && PatchRules.AutoApproves(policy, entry) ? PatchStatus.Approved : PatchStatus.Pending, FirstSeenAt = now,
                };
                db.DevicePatchStates.Add(state);
            }
            else if (state.Status is PatchStatus.Installed)
            {
                // Reported as pending again after we believed it installed (rollback, failed install).
                state.Status = PatchStatus.Pending;
                state.InstalledAt = null;
            }
            state.CurrentVersion = r.Current;
            state.NewVersion = r.New;
            state.RequiresReboot = r.Reboot;
            state.UpdatedAt = now;
        }
        // No longer offered by the OS: installed (by us, the user or the OS itself) or superseded.
        foreach (var gone in states.Where(s => !seen.Contains(s.CatalogEntryId) && s.Status is PatchStatus.Pending or PatchStatus.Approved or PatchStatus.Deferred or PatchStatus.Failed))
        {
            gone.Status = PatchStatus.Installed;
            gone.InstalledAt = now;
            gone.UpdatedAt = now;
            gone.Error = null;
        }
        device.LastPatchScanAt = now;
        device.PendingReboot = device.PendingReboot || payload.Bool("rebootRequired");
        await db.SaveChangesAsync(ct);
        await alerts.EvaluateDeviceAsync(device.Id, ct);
    }
}

/// <summary>Records per-update results of a <c>patch.install</c> job and rescans.</summary>
public sealed class PatchResultHandler(DranzoDbContext db, JobService jobs, AlertEngine alerts, TimeProvider clock) : IJobResultHandler
{
    public bool Handles(string kind) => kind == JobKinds.PatchInstall;

    public async Task HandleAsync(JobRun run, Device device, JsonElement result, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var states = await db.DevicePatchStates.Include(s => s.CatalogEntry).Where(s => s.DeviceId == device.Id).ToListAsync(ct);
        var any = false;
        foreach (var item in result.Arr("installed", 2000))
        {
            var id = item.Str("id", 200);
            foreach (var state in states.Where(s => s.CatalogEntry.UpdateId == id))
            {
                any = true;
                if (item.Bool("ok"))
                {
                    state.Status = PatchStatus.Installed;
                    state.InstalledAt = now;
                    state.Error = null;
                }
                else
                {
                    state.Status = PatchStatus.Failed;
                    state.Error = item.Str("error", 500, "Install failed.");
                }
                state.UpdatedAt = now;
            }
        }
        var tracked = await db.Devices.FirstAsync(d => d.Id == device.Id, ct);
        if (any && run.Status == JobRunStatus.Succeeded)
        {
            tracked.LastPatchInstallAt = now;
        }
        tracked.PendingReboot = tracked.PendingReboot || result.Bool("rebootRequired");
        await db.SaveChangesAsync(ct);
        await alerts.EvaluateDeviceAsync(device.Id, ct); // patch failures
        await jobs.CreateAsync(new NewJob("Rescan updates", JobKinds.PatchScan, new JobTarget(DeviceIds: [device.Id]), new { }, 900, IsSystem: true), [device], device.PartnerId, null, "system", ct);
    }
}

/// <summary>Starts patch installation when a policy's maintenance window opens.</summary>
public sealed class PatchWindowService(IServiceScopeFactory scopes, ILogger<PatchWindowService> log) : PeriodicService(scopes, log, TimeSpan.FromSeconds(60))
{
    protected override Task TickAsync(IServiceProvider sp, CancellationToken ct) => RunDueAsync(sp, ct);

    public static async Task RunDueAsync(IServiceProvider sp, CancellationToken ct)
    {
        var db = sp.GetRequiredService<DranzoDbContext>();
        var jobs = sp.GetRequiredService<JobService>();
        var now = sp.GetRequiredService<TimeProvider>().GetUtcNow();
        var due = await db.PatchPolicies.Where(p => p.Enabled && p.WindowCron != null && p.NextWindowAt != null && p.NextWindowAt <= now).ToListAsync(ct);
        foreach (var policy in due)
        {
            var all = await db.PatchPolicies.Where(p => p.PartnerId == policy.PartnerId).ToListAsync(ct);
            var orgs = await db.Organizations.Where(o => o.PartnerId == policy.PartnerId && (policy.OrganizationId == null || o.Id == policy.OrganizationId)).ToListAsync(ct);
            foreach (var org in orgs.Where(o => PatchRules.PolicyFor(all, o.Id)?.Id == policy.Id))
            {
                var devices = await db.Devices.Where(d => d.OrganizationId == org.Id && d.Status == DeviceStatus.Active).ToListAsync(ct);
                await PatchEndpoints.CreateInstallJobAsync(db, jobs, devices, null, policy, $"Patch window: {policy.Name}", policy.PartnerId, null, "system", true, now, ct);
            }
            var tz = policy.OrganizationId is { } oid ? orgs.FirstOrDefault(o => o.Id == oid)?.TimeZone ?? "UTC" : "UTC";
            policy.NextWindowAt = Scheduler.NextOccurrence(policy.WindowCron!, tz, now);
            await db.SaveChangesAsync(ct);
        }
    }
}

public static class PatchEndpoints
{
    public sealed record RebootRequest(string? Mode, bool? NotifyUser, int? Deferrals, int? DeadlineMinutes, string? Message);

    public sealed record InstallRequest(JobEndpoints.TargetRequest? Target, Guid[]? CatalogEntryIds, RebootRequest? Reboot);

    public sealed record ApproveRequest(Guid[]? CatalogEntryIds, string? Status, Guid? OrganizationId, Guid[]? DeviceIds);

    public sealed record PolicyRequest(string? Name, Guid? OrganizationId, bool? Enabled, string[]? AutoApproveSeverities, string[]? AutoApproveCategories, string[]? Sources,
        int? DeferDays, string? WindowCron, int? WindowMinutes, string? RebootMode, bool? RebootNotifyUser, int? RebootDeferrals, int? RebootDeadlineMinutes);

    public sealed record DeviceRebootRequest(int? DelaySeconds, string? Message, bool? NotifyUser);

    /// <summary>
    /// Creates one <c>patch.install</c> job. Each device is sent only its own approved updates
    /// (optionally limited to <paramref name="onlyEntries"/>) whose deferral period has passed.
    /// </summary>
    public static async Task<(Job? Job, int Devices)> CreateInstallJobAsync(DranzoDbContext db, JobService jobs, List<Device> devices, Guid[]? onlyEntries, PatchPolicy? policy,
        string name, Guid partnerId, Guid? userId, string requestedBy, bool isSystem, DateTimeOffset now, CancellationToken ct, RebootRequest? reboot = null)
    {
        var ids = devices.Select(d => d.Id).ToList();
        var deferCutoff = now.AddDays(-(policy?.DeferDays ?? 0));
        var approved = await db.DevicePatchStates.Include(s => s.CatalogEntry)
            .Where(s => ids.Contains(s.DeviceId) && s.Status == PatchStatus.Approved && s.CatalogEntry.FirstSeenAt <= deferCutoff && (onlyEntries == null || onlyEntries.Contains(s.CatalogEntryId)))
            .ToListAsync(ct);
        if (policy is { Sources.Length: > 0 })
        {
            approved = [.. approved.Where(s => policy.Sources.Contains(s.CatalogEntry.Source))];
        }
        var rebootSpec = new
        {
            mode = reboot?.Mode ?? policy?.RebootMode ?? "if_required",
            notifyUser = reboot?.NotifyUser ?? policy?.RebootNotifyUser ?? true,
            deferrals = Math.Clamp(reboot?.Deferrals ?? policy?.RebootDeferrals ?? 3, 0, 20),
            deadlineMinutes = Math.Clamp(reboot?.DeadlineMinutes ?? policy?.RebootDeadlineMinutes ?? 240, 0, 7 * 24 * 60),
            message = reboot?.Message is { Length: > 0 and <= 500 } m ? m : "Your IT provider installed updates. This computer needs to restart.",
        };
        var perDevice = approved.GroupBy(s => s.DeviceId).ToDictionary(g => g.Key, g => (object)new
        {
            updateIds = g.Select(s => s.CatalogEntry.UpdateId).Distinct().ToArray(),
            sources = g.Select(s => s.CatalogEntry.Source).Distinct().ToArray(),
            reboot = rebootSpec,
        });
        var targets = devices.Where(d => perDevice.ContainsKey(d.Id)).ToList();
        if (targets.Count == 0)
        {
            return (null, 0);
        }
        var created = await jobs.CreateAsync(new NewJob(name, JobKinds.PatchInstall, new JobTarget(DeviceIds: [.. targets.Select(d => d.Id)]), new { }, 4 * 3600, MaxOutputBytes: 4 * 1024 * 1024,
            IsSystem: isSystem, PerDeviceSpec: perDevice, ExpiresAfter: policy is not null && isSystem ? TimeSpan.FromMinutes(Math.Max(15, policy.WindowMinutes)) : null),
            targets, partnerId, userId, requestedBy, ct);
        return (created.Job, targets.Count);
    }

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/patches", async (Guid? organizationId, string? status, string? severity, string? source, Ctx c, CancellationToken ct) =>
        {
            var q = c.Db.DevicePatchStates.AsNoTracking().Where(s => organizationId == null || s.OrganizationId == organizationId);
            if (status is not null)
            {
                if (!Enum.TryParse<PatchStatus>(status, true, out var st))
                {
                    return Api.BadRequest("Unknown status.");
                }
                q = q.Where(s => s.Status == st);
            }
            else
            {
                q = q.Where(s => s.Status != PatchStatus.Installed);
            }
            if (severity is not null)
            {
                q = q.Where(s => s.CatalogEntry.Severity == severity);
            }
            if (source is not null)
            {
                q = q.Where(s => s.CatalogEntry.Source == source);
            }
            var rows = await q.GroupBy(s => new { s.CatalogEntryId, s.CatalogEntry.Title, s.CatalogEntry.Kb, s.CatalogEntry.Source, s.CatalogEntry.Severity, s.CatalogEntry.Category, s.CatalogEntry.FirstSeenAt })
                .Select(g => new
                {
                    id = g.Key.CatalogEntryId, g.Key.Title, g.Key.Kb, g.Key.Source, g.Key.Severity, g.Key.Category, g.Key.FirstSeenAt,
                    devices = g.Count(), pending = g.Count(x => x.Status == PatchStatus.Pending), approved = g.Count(x => x.Status == PatchStatus.Approved),
                    failed = g.Count(x => x.Status == PatchStatus.Failed), rejected = g.Count(x => x.Status == PatchStatus.Rejected), deferred = g.Count(x => x.Status == PatchStatus.Deferred),
                }).OrderByDescending(x => x.devices).Take(2000).ToListAsync(ct);
            return Results.Ok(rows);
        }).RequirePermission(Permissions.PatchesRead);

        api.MapGet("/devices/{id:guid}/patches", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var device = await c.Db.Devices.AsNoTracking().FirstOrDefaultAsync(d => d.Id == id, ct);
            if (device is null)
            {
                return Api.NotFound();
            }
            var items = await c.Db.DevicePatchStates.AsNoTracking().Where(s => s.DeviceId == id).OrderBy(s => s.Status).ThenBy(s => s.CatalogEntry.Title)
                .Select(s => new { id = s.CatalogEntryId, s.CatalogEntry.Title, s.CatalogEntry.Kb, s.CatalogEntry.Source, s.CatalogEntry.Severity, s.CatalogEntry.Category, status = s.Status.ToString().ToLower(), s.CurrentVersion, s.NewVersion, s.RequiresReboot, s.FirstSeenAt, s.InstalledAt, s.Error }).ToListAsync(ct);
            return Results.Ok(new { device.LastPatchScanAt, device.LastPatchInstallAt, device.PendingReboot, items });
        }).RequirePermission(Permissions.PatchesRead);

        // Patched / unpatched per device.
        api.MapGet("/patches/compliance", async (Guid? organizationId, Ctx c, CancellationToken ct) =>
        {
            var devices = await c.Db.Devices.AsNoTracking().Where(d => d.Status == DeviceStatus.Active && (organizationId == null || d.OrganizationId == organizationId))
                .Select(d => new { d.Id, d.Hostname, d.OrganizationId, d.Os, d.IsOnline, d.LastPatchScanAt, d.LastPatchInstallAt, d.PendingReboot }).ToListAsync(ct);
            var counts = await c.Db.DevicePatchStates.AsNoTracking().Where(s => (organizationId == null || s.OrganizationId == organizationId) && s.Status != PatchStatus.Installed && s.Status != PatchStatus.Rejected)
                .GroupBy(s => s.DeviceId).Select(g => new
                {
                    DeviceId = g.Key, Missing = g.Count(), Critical = g.Count(x => x.CatalogEntry.Severity == "critical" || x.CatalogEntry.Severity == "important"), Failed = g.Count(x => x.Status == PatchStatus.Failed),
                }).ToDictionaryAsync(x => x.DeviceId, ct);
            var items = devices.Select(d =>
            {
                var n = counts.GetValueOrDefault(d.Id);
                return new
                {
                    d.Id, d.Hostname, d.OrganizationId, d.Os, d.IsOnline, d.LastPatchScanAt, d.LastPatchInstallAt, d.PendingReboot,
                    missing = n?.Missing ?? 0, missingCritical = n?.Critical ?? 0, failed = n?.Failed ?? 0,
                    state = d.LastPatchScanAt is null ? "unknown" : (n?.Missing ?? 0) == 0 ? "patched" : "unpatched",
                };
            }).OrderByDescending(x => x.missingCritical).ThenByDescending(x => x.missing).ToList();
            return Results.Ok(new
            {
                total = items.Count, patched = items.Count(i => i.state == "patched"), unpatched = items.Count(i => i.state == "unpatched"), unknown = items.Count(i => i.state == "unknown"), items,
            });
        }).RequirePermission(Permissions.PatchesRead);

        api.MapPost("/patches/approve", async (ApproveRequest req, Ctx c, CancellationToken ct) =>
        {
            if (req.CatalogEntryIds is not { Length: > 0 and <= 2000 })
            {
                return Api.BadRequest("catalogEntryIds is required.");
            }
            var status = req.Status switch { "approved" => PatchStatus.Approved, "rejected" => PatchStatus.Rejected, "deferred" => PatchStatus.Deferred, "pending" => PatchStatus.Pending, _ => (PatchStatus?)null };
            if (status is null)
            {
                return Api.BadRequest("status must be approved, rejected, deferred or pending.");
            }
            // Only device states inside the caller's patches.approve scope are touched (tenant filter).
            var q = c.Db.DevicePatchStates.Where(s => req.CatalogEntryIds.Contains(s.CatalogEntryId) && s.Status != PatchStatus.Installed
                && (req.OrganizationId == null || s.OrganizationId == req.OrganizationId) && (req.DeviceIds == null || req.DeviceIds.Contains(s.DeviceId)));
            var states = await q.ToListAsync(ct);
            foreach (var s in states)
            {
                s.Status = status.Value;
                s.UpdatedAt = c.Now;
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("patch." + req.Status, organizationId: req.OrganizationId, targetType: "patch", detail: new { catalogEntryIds = req.CatalogEntryIds, deviceStates = states.Count }, ct: ct);
            return Results.Ok(new { updated = states.Count });
        }).RequirePermission(Permissions.PatchesApprove);

        api.MapPost("/patches/scan", async (JobEndpoints.TargetRequest req, Ctx c, JobService jobs, CancellationToken ct) =>
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
            var created = await jobs.CreateAsync(new NewJob("Scan for updates", JobKinds.PatchScan, target!, new { }, 900), devices, c.Who.PartnerId, c.Who.IsApiKey ? null : c.Who.UserId, c.Who.Name, ct);
            await c.Audit("patch.scan", organizationId: created.Job.OrganizationId, targetType: "job", targetId: created.Job.Id, detail: new { devices = devices.Count }, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id, deviceCount = devices.Count });
        }).RequirePermission(Permissions.PatchesInstall);

        api.MapPost("/patches/install", async (InstallRequest req, Ctx c, JobService jobs, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
        {
            if (req.Reboot?.Mode is { } mode && !PatchRules.RebootModes.Contains(mode))
            {
                return Api.BadRequest("reboot.mode must be never, if_required or force.");
            }
            var (target, devices, error) = await JobEndpoints.ResolveTargetAsync(req.Target, c, jobs, ct);
            if (error is not null)
            {
                return error;
            }
            if (JobEndpoints.NeedsStepUp(target!, devices.Count, false, opt.Value) && !StepUp.IsFresh(c.Who, opt.Value, clock))
            {
                return StepUp.Required();
            }
            var (job, count) = await CreateInstallJobAsync(c.Db, jobs, devices, req.CatalogEntryIds, null, "Install approved updates", c.Who.PartnerId, c.Who.IsApiKey ? null : c.Who.UserId, c.Who.Name, false, c.Now, ct, req.Reboot);
            if (job is null)
            {
                return Api.BadRequest("None of the targeted devices has approved updates to install.");
            }
            await c.Audit("patch.install", organizationId: job.OrganizationId, targetType: "job", targetId: job.Id, detail: new { devices = count, catalogEntryIds = req.CatalogEntryIds, reboot = req.Reboot }, ct: ct);
            return Results.Created($"/api/v1/jobs/{job.Id}", new { jobId = job.Id, deviceCount = count });
        }).RequirePermission(Permissions.PatchesInstall);

        api.MapPost("/devices/{id:guid}/reboot", async (Guid id, DeviceRebootRequest req, Ctx c, JobService jobs, CancellationToken ct) =>
        {
            var device = await c.Db.Devices.FirstOrDefaultAsync(d => d.Id == id, ct);
            if (device is null)
            {
                return Api.NotFound();
            }
            var spec = new { delaySeconds = Math.Clamp(req.DelaySeconds ?? 300, 0, 24 * 3600), message = req.Message is { Length: > 0 and <= 500 } m ? m : "Your IT provider scheduled a restart of this computer.", notifyUser = req.NotifyUser ?? true };
            var created = await jobs.CreateAsync(new NewJob("Restart device", JobKinds.Reboot, new JobTarget(DeviceIds: [id]), spec, 120), [device], c.Who.PartnerId, c.Who.IsApiKey ? null : c.Who.UserId, c.Who.Name, ct);
            await c.Audit("device.reboot", organizationId: device.OrganizationId, deviceId: id, targetType: "device", targetId: id, detail: spec, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id });
        }).RequirePermission(Permissions.DevicesManage);

        // ----- Patch policies -----
        api.MapGet("/patch-policies", async (Ctx c, CancellationToken ct) =>
            Results.Ok(await c.Db.PatchPolicies.AsNoTracking().OrderBy(p => p.Name).ToListAsync(ct)))
            .RequirePermission(Permissions.PatchesRead);

        api.MapPost("/patch-policies", async (PolicyRequest req, Ctx c, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
        {
            if (req.OrganizationId is { } org ? !c.Tenant.CoversOrganization(org) || !await c.Db.Organizations.AnyAsync(o => o.Id == org, ct) : !c.Tenant.AllOrgs)
            {
                return req.OrganizationId is null ? Api.Error(403, "forbidden", "Shared patch policies need partner-wide scope; set organizationId.") : Api.NotFound();
            }
            var policy = new PatchPolicy { Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = req.OrganizationId, Name = "", CreatedAt = c.Now };
            var problem = await ApplyAsync(policy, req, c, creating: true, ct);
            if (problem is not null)
            {
                return Api.BadRequest(problem);
            }
            if (policy.RebootMode == "force" && !StepUp.IsFresh(c.Who, opt.Value, clock))
            {
                return StepUp.Required(); // organization-wide forced restarts
            }
            c.Db.PatchPolicies.Add(policy);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("patch_policy.create", organizationId: policy.OrganizationId, targetType: "patch_policy", targetId: policy.Id, detail: new { policy.Name, policy.Enabled, policy.AutoApproveSeverities, policy.AutoApproveCategories, policy.Sources, policy.DeferDays, policy.WindowCron, policy.WindowMinutes, policy.RebootMode }, ct: ct);
            return Results.Created($"/api/v1/patch-policies/{policy.Id}", new { policy.Id });
        }).RequirePermission(Permissions.PatchesInstall);

        api.MapPatch("/patch-policies/{id:guid}", async (Guid id, PolicyRequest req, Ctx c, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
        {
            var policy = await c.Db.PatchPolicies.FirstOrDefaultAsync(p => p.Id == id, ct);
            if (policy is null || (policy.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            var problem = await ApplyAsync(policy, req, c, creating: false, ct);
            if (problem is not null)
            {
                return Api.BadRequest(problem);
            }
            if (policy.RebootMode == "force" && !StepUp.IsFresh(c.Who, opt.Value, clock))
            {
                return StepUp.Required(); // organization-wide forced restarts
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("patch_policy.update", organizationId: policy.OrganizationId, targetType: "patch_policy", targetId: id, detail: new { policy.Name, policy.Enabled, policy.AutoApproveSeverities, policy.AutoApproveCategories, policy.Sources, policy.DeferDays, policy.WindowCron, policy.WindowMinutes, policy.RebootMode }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.PatchesInstall);

        api.MapDelete("/patch-policies/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var policy = await c.Db.PatchPolicies.FirstOrDefaultAsync(p => p.Id == id, ct);
            if (policy is null || (policy.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            c.Db.PatchPolicies.Remove(policy);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("patch_policy.delete", organizationId: policy.OrganizationId, targetType: "patch_policy", targetId: id, detail: new { policy.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.PatchesInstall);
    }

    private static async Task<string?> ApplyAsync(PatchPolicy p, PolicyRequest req, Ctx c, bool creating, CancellationToken ct)
    {
        if (req.Name is not null || creating)
        {
            if (Api.CleanName(req.Name) is not { } name)
            {
                return "Name is required.";
            }
            p.Name = name;
        }
        if (req.AutoApproveSeverities is { } sev)
        {
            if (sev.Any(s => !PatchRules.Severities.Contains(s)))
            {
                return "autoApproveSeverities: " + string.Join(", ", PatchRules.Severities);
            }
            p.AutoApproveSeverities = [.. sev.Distinct()];
        }
        if (req.AutoApproveCategories is { } cats)
        {
            if (cats.Length > 32 || cats.Any(x => x is null || x.Length is 0 or > 64))
            {
                return "autoApproveCategories: up to 32 names.";
            }
            p.AutoApproveCategories = [.. cats.Distinct()];
        }
        if (req.Sources is { } sources)
        {
            if (sources.Any(s => !PatchRules.Sources.Contains(s)))
            {
                return "sources: " + string.Join(", ", PatchRules.Sources);
            }
            p.Sources = [.. sources.Distinct()];
        }
        if (req.RebootMode is { } mode)
        {
            if (!PatchRules.RebootModes.Contains(mode))
            {
                return "rebootMode must be never, if_required or force.";
            }
            p.RebootMode = mode;
        }
        p.Enabled = req.Enabled ?? p.Enabled;
        p.DeferDays = Math.Clamp(req.DeferDays ?? p.DeferDays, 0, 90);
        p.WindowMinutes = Math.Clamp(req.WindowMinutes ?? p.WindowMinutes, 15, 24 * 60);
        p.RebootNotifyUser = req.RebootNotifyUser ?? p.RebootNotifyUser;
        p.RebootDeferrals = Math.Clamp(req.RebootDeferrals ?? p.RebootDeferrals, 0, 20);
        p.RebootDeadlineMinutes = Math.Clamp(req.RebootDeadlineMinutes ?? p.RebootDeadlineMinutes, 0, 7 * 24 * 60);
        if (req.WindowCron is not null)
        {
            if (req.WindowCron.Length == 0)
            {
                p.WindowCron = null;
            }
            else if (!Scheduler.TryParse(req.WindowCron, out var error))
            {
                return "Invalid windowCron: " + error;
            }
            else
            {
                p.WindowCron = req.WindowCron;
            }
        }
        var tz = p.OrganizationId is { } org ? await c.Db.Organizations.Where(o => o.Id == org).Select(o => o.TimeZone).FirstOrDefaultAsync(ct) ?? "UTC" : "UTC";
        p.NextWindowAt = p.WindowCron is null || !p.Enabled ? null : Scheduler.NextOccurrence(p.WindowCron, tz, c.Now);
        return null;
    }
}
