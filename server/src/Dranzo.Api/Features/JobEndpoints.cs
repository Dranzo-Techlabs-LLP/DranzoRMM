using System.Text.Json;
using Dranzo.Api.Auth;
using Dranzo.Api.Jobs;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

public static class JobEndpoints
{
    public sealed record TargetRequest(Guid[]? DeviceIds, Guid? GroupId, Guid? SiteId, Guid? OrganizationId, Guid? SavedFilterId, DeviceFilter? Filter);

    public sealed record ScheduleRequest(string? Cron, string? TimeZone);

    public sealed record RunScriptRequest(Guid ScriptId, int? Version, TargetRequest? Target, Dictionary<string, JsonElement>? Parameters, string[]? Args,
        string? RunAs, int? TimeoutSeconds, int? MaxOutputBytes, int? MaxParallel, int? MaxAttempts, ScheduleRequest? Schedule, string? Name);

    public sealed record FilterRequest(string? Name, Guid? OrganizationId, DeviceFilter? Filter);

    public sealed record JobPatch(bool? Enabled);

    /// <summary>
    /// Turns a request target into a validated <see cref="JobTarget"/> and the devices it covers inside the caller's
    /// current scope. Returns an error result when the target is missing, unknown or out of scope.
    /// </summary>
    public static async Task<(JobTarget? Target, List<Device> Devices, IResult? Error)> ResolveTargetAsync(TargetRequest? req, Ctx c, JobService jobs, CancellationToken ct)
    {
        if (req is null)
        {
            return (null, [], Api.BadRequest("target is required."));
        }
        JobTarget target;
        if (req.DeviceIds is { Length: > 0 })
        {
            if (req.DeviceIds.Length > 5000)
            {
                return (null, [], Api.BadRequest("At most 5000 explicit devices per job."));
            }
            target = new JobTarget(DeviceIds: [.. req.DeviceIds.Distinct()]);
        }
        else if (req.GroupId is { } g)
        {
            if (!await c.Db.DeviceGroups.AnyAsync(x => x.Id == g, ct))
            {
                return (null, [], Api.NotFound());
            }
            target = new JobTarget(GroupId: g);
        }
        else if (req.SiteId is { } s)
        {
            var site = await c.Db.Sites.FirstOrDefaultAsync(x => x.Id == s, ct);
            if (site is null || !c.Tenant.CoversSite(site.OrganizationId, site.Id))
            {
                return (null, [], Api.NotFound());
            }
            target = new JobTarget(SiteId: s);
        }
        else if (req.SavedFilterId is { } f)
        {
            var saved = await c.Db.SavedFilters.FirstOrDefaultAsync(x => x.Id == f, ct);
            if (saved is null)
            {
                return (null, [], Api.NotFound());
            }
            target = new JobTarget(OrganizationId: saved.OrganizationId, Filter: JsonSerializer.Deserialize<DeviceFilter>(saved.FilterJson, JsonSerializerOptions.Web) ?? new DeviceFilter());
        }
        else if (req.Filter is not null)
        {
            target = new JobTarget(OrganizationId: req.OrganizationId ?? req.Filter.OrganizationId, Filter: req.Filter);
        }
        else if (req.OrganizationId is { } o)
        {
            if (!c.Tenant.CoversOrganization(o) || !await c.Db.Organizations.AnyAsync(x => x.Id == o, ct))
            {
                return (null, [], Api.NotFound());
            }
            target = new JobTarget(OrganizationId: o);
        }
        else
        {
            return (null, [], Api.BadRequest("target must name devices, a group, a site, an organization or a filter."));
        }
        if (target.Filter is not null && target.OrganizationId is { } filterOrg && !c.Tenant.CoversOrganization(filterOrg))
        {
            return (null, [], Api.NotFound());
        }
        var devices = await jobs.ResolveAsync(target, ct);
        // Explicit ids must all be visible; a partial run would hide that some ids were out of scope.
        if (target.IsExplicit && devices.Count != target.DeviceIds!.Length)
        {
            return (null, [], Api.NotFound());
        }
        return (target, devices, null);
    }

    /// <summary>Wide actions need step-up: more than the threshold of devices, or every device of an organization.</summary>
    public static bool NeedsStepUp(JobTarget target, int deviceCount, bool scheduled, DranzoOptions options) =>
        deviceCount > options.Auth.BulkStepUpThreshold || target.IsWholeOrganizationOrWider || (scheduled && !target.IsExplicit);

    public static void Map(RouteGroupBuilder api)
    {
        api.MapPost("/jobs/run-script", async (RunScriptRequest req, Ctx c, JobService jobs, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
        {
            var script = await c.Db.Scripts.AsNoTracking().FirstOrDefaultAsync(s => s.Id == req.ScriptId && s.DeletedAt == null, ct);
            if (script is null)
            {
                return Api.NotFound();
            }
            var versionNo = req.Version ?? script.CurrentVersion;
            var version = await c.Db.ScriptVersions.AsNoTracking().FirstOrDefaultAsync(v => v.ScriptId == script.Id && v.Version == versionNo, ct);
            if (version is null)
            {
                return Api.NotFound();
            }
            var runAs = req.RunAs ?? "system";
            if (runAs is not ("system" or "user"))
            {
                return Api.BadRequest("runAs must be system or user.");
            }
            var args = req.Args ?? [];
            if (args.Length > 64 || args.Any(a => a is null || a.Length > 4096 || a.Contains('\0')))
            {
                return Api.BadRequest("args: at most 64 values of up to 4096 characters.");
            }
            var declared = JsonSerializer.Deserialize<ScriptParameter[]>(version.ParametersJson, JsonSerializerOptions.Web) ?? [];
            var env = new Dictionary<string, string>();
            var supplied = req.Parameters ?? [];
            if (supplied.Keys.FirstOrDefault(k => declared.All(d => d.Name != k)) is { } unknown)
            {
                return Api.BadRequest($"Unknown parameter '{unknown}'.");
            }
            foreach (var p in declared)
            {
                string? value = supplied.TryGetValue(p.Name, out var el) ? el.ValueKind switch
                {
                    JsonValueKind.String => el.GetString(),
                    JsonValueKind.Number => el.GetRawText(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    _ => null,
                } : p.Default;
                if (value is null)
                {
                    if (p.Required)
                    {
                        return Api.BadRequest($"Parameter '{p.Name}' is required.");
                    }
                    continue;
                }
                if (value.Length > 4096 || value.Contains('\0')
                    || (p.Type == "int" && !long.TryParse(value, out _)) || (p.Type == "bool" && value is not ("true" or "false")))
                {
                    return Api.BadRequest($"Parameter '{p.Name}' is not a valid {p.Type}.");
                }
                env[p.Name] = value;
            }
            // Scheduled jobs for a shared script must be pinned to an organization the caller covers, or need partner scope.
            string? cron = null, tz = null;
            if (req.Schedule?.Cron is { } cronText)
            {
                if (!Scheduler.TryParse(cronText, out var cronError))
                {
                    return Api.BadRequest("Invalid cron expression: " + cronError);
                }
                cron = cronText;
            }
            var (target, devices, error) = await ResolveTargetAsync(req.Target, c, jobs, ct);
            if (error is not null)
            {
                return error;
            }
            // A script that belongs to one organization can only run on that organization's devices.
            if (script.OrganizationId is { } scriptOrg && devices.Any(d => d.OrganizationId != scriptOrg))
            {
                return Api.BadRequest("This script belongs to one organization and cannot run on devices of another.");
            }
            if (cron is not null)
            {
                var orgForTz = target!.OrganizationId ?? devices.Select(d => (Guid?)d.OrganizationId).FirstOrDefault();
                tz = req.Schedule!.TimeZone ?? (orgForTz is null ? "UTC" : await c.Db.Organizations.IgnoreQueryFilters().Where(o => o.Id == orgForTz && o.PartnerId == c.Who.PartnerId).Select(o => o.TimeZone).FirstOrDefaultAsync(ct) ?? "UTC");
                if (!TenantEndpoints.TryTimeZone(tz, out _))
                {
                    return Api.BadRequest("Unknown time zone.");
                }
                if (!target.IsExplicit && target.OrganizationId is null && target.GroupId is null && target.SiteId is null && !c.Tenant.AllOrgs)
                {
                    return Api.BadRequest("A scheduled job must target devices, a group, a site or one organization.");
                }
            }
            if (devices.Count == 0 && cron is null)
            {
                return Api.BadRequest("The target matches no devices you can run scripts on.");
            }
            if (NeedsStepUp(target!, devices.Count, cron is not null, opt.Value) && !StepUp.IsFresh(c.Who, opt.Value, clock))
            {
                await c.Audit("script.run", "denied", targetType: "script", targetId: script.Id, detail: new { reason = "step_up_required", devices = devices.Count }, contentSha256: version.BodySha256, ct: ct);
                return StepUp.Required();
            }
            var spec = new { scriptId = script.Id, version = version.Version, language = script.Language, body = version.Body, args, env, runAs, osTargets = script.OsTargets };
            var created = await jobs.CreateAsync(new NewJob(
                Api.CleanName(req.Name) ?? script.Name, JobKinds.Script, target!, spec,
                req.TimeoutSeconds ?? 300, req.MaxOutputBytes ?? 1_048_576, req.MaxAttempts ?? 1, req.MaxParallel ?? 0, cron, tz,
                script.Id, version.Version, version.BodySha256), devices, c.Who.PartnerId, c.Who.IsApiKey ? null : c.Who.UserId, c.Who.Name, ct);
            await c.Audit("script.run", organizationId: created.Job.OrganizationId, targetType: "job", targetId: created.Job.Id,
                detail: new { script = script.Name, scriptId = script.Id, version = version.Version, devices = devices.Count, runAs, scheduled = cron, target }, contentSha256: version.BodySha256, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id, runs = created.Runs.Select(r => new { r.Id, r.DeviceId }), deviceCount = devices.Count, nextRunAt = created.Job.NextRunAt });
        }).RequirePermission(Permissions.ScriptsRun);

        // Tells the dashboard how many devices a target covers and whether step-up will be asked for.
        api.MapPost("/jobs/preview-target", async (TargetRequest req, Ctx c, JobService jobs, IOptions<DranzoOptions> opt, CancellationToken ct) =>
        {
            var (target, devices, error) = await ResolveTargetAsync(req, c, jobs, ct);
            return error ?? Results.Ok(new
            {
                deviceCount = devices.Count,
                stepUpRequired = NeedsStepUp(target!, devices.Count, false, opt.Value),
                byOs = devices.GroupBy(d => d.Os).ToDictionary(g => g.Key, g => g.Count()),
                online = devices.Count(d => d.IsOnline),
            });
        }).RequirePermission(Permissions.DevicesRead);

        // Jobs are listed through the runs the caller can see, so site- and group-scoped users get their own slice.
        api.MapGet("/jobs", async (Guid? deviceId, string? kind, bool? scheduled, int? page, int? pageSize, Ctx c, CancellationToken ct) =>
        {
            var (skip, take, p) = Api.Paging(page, pageSize);
            var runs = c.Db.JobRuns.AsNoTracking().Where(r => (deviceId == null || r.DeviceId == deviceId) && (kind == null || r.Kind == kind));
            var grouped = runs.GroupBy(r => r.JobId).Select(g => new
            {
                JobId = g.Key, Total = g.Count(), Last = g.Max(r => r.CreatedAt),
                Succeeded = g.Count(r => r.Status == JobRunStatus.Succeeded),
                Failed = g.Count(r => r.Status == JobRunStatus.Failed || r.Status == JobRunStatus.TimedOut || r.Status == JobRunStatus.Rejected),
                Active = g.Count(r => r.Status == JobRunStatus.Pending || r.Status == JobRunStatus.Dispatched || r.Status == JobRunStatus.Running),
            });
            var total = await grouped.CountAsync(ct);
            var pageRows = await grouped.OrderByDescending(x => x.Last).Skip(skip).Take(take).ToListAsync(ct);
            var ids = pageRows.Select(x => x.JobId).ToList();
            var jobs = await c.Db.Jobs.IgnoreQueryFilters().AsNoTracking().Where(j => j.PartnerId == c.Who.PartnerId && ids.Contains(j.Id)).ToDictionaryAsync(j => j.Id, ct);
            var items = pageRows.Where(x => jobs.ContainsKey(x.JobId) && (scheduled == null || (jobs[x.JobId].Cron != null) == scheduled)).Select(x =>
            {
                var j = jobs[x.JobId];
                return new { j.Id, j.Name, j.Kind, j.OrganizationId, j.RequestedByName, j.CreatedAt, j.Cron, j.TimeZone, j.NextRunAt, j.Enabled, j.ScriptId, j.ScriptVersion, j.IsSystem, x.Total, x.Succeeded, x.Failed, x.Active, lastRunAt = x.Last };
            });
            return Results.Ok(new { total, page = p, pageSize = take, items });
        }).RequirePermission(Permissions.JobsRead);

        // Schedules (including ones that have not fired yet). Organization scope or wider.
        api.MapGet("/schedules", async (Ctx c, CancellationToken ct) =>
            Results.Ok(await c.Db.Jobs.AsNoTracking().Where(j => j.Cron != null).OrderBy(j => j.Name)
                .Select(j => new { j.Id, j.Name, j.Kind, j.OrganizationId, j.Cron, j.TimeZone, j.NextRunAt, j.Enabled, j.RequestedByName, j.CreatedAt, j.ScriptId, j.TargetJson }).ToListAsync(ct)))
            .RequirePermission(Permissions.JobsRead);

        api.MapGet("/jobs/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var runs = await c.Db.JobRuns.AsNoTracking().Where(r => r.JobId == id).OrderBy(r => r.Device.Hostname).Take(5000)
                .Select(r => new { r.Id, r.DeviceId, hostname = r.Device.Hostname, os = r.Device.Os, status = r.Status.ToString().ToLower(), r.ExitCode, r.Message, r.CreatedAt, r.StartedAt, r.FinishedAt, r.Truncated, r.Attempt, r.BatchId }).ToListAsync(ct);
            var job = await c.Db.Jobs.AsNoTracking().FirstOrDefaultAsync(j => j.Id == id, ct);
            if (runs.Count == 0 && job is null)
            {
                return Api.NotFound();
            }
            // Site/group-scoped callers reach the job through their runs; the job row itself is partner-checked.
            job ??= await c.Db.Jobs.IgnoreQueryFilters().AsNoTracking().FirstAsync(j => j.Id == id && j.PartnerId == c.Who.PartnerId, ct);
            return Results.Ok(new
            {
                job.Id, job.Name, job.Kind, job.OrganizationId, job.RequestedByName, job.CreatedAt, job.Cron, job.TimeZone, job.NextRunAt, job.Enabled,
                job.ScriptId, job.ScriptVersion, job.TimeoutSeconds, job.MaxOutputBytes, job.ContentSha256, job.IsSystem, runs,
            });
        }).RequirePermission(Permissions.JobsRead);

        api.MapPatch("/jobs/{id:guid}", async (Guid id, JobPatch req, Ctx c, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
        {
            var job = await c.Db.Jobs.FirstOrDefaultAsync(j => j.Id == id && j.Cron != null, ct);
            if (job is null)
            {
                return Api.NotFound();
            }
            if (req.Enabled == true && !job.Enabled && !StepUp.IsFresh(c.Who, opt.Value, clock))
            {
                return StepUp.Required();
            }
            if (req.Enabled is { } enabled)
            {
                job.Enabled = enabled;
                job.NextRunAt = enabled ? Scheduler.NextOccurrence(job.Cron!, job.TimeZone ?? "UTC", clock.GetUtcNow()) : null;
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("schedule.update", organizationId: job.OrganizationId, targetType: "job", targetId: id, detail: new { job.Name, job.Enabled }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.ScriptsRun);

        api.MapDelete("/jobs/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var job = await c.Db.Jobs.FirstOrDefaultAsync(j => j.Id == id && j.Cron != null, ct);
            if (job is null)
            {
                return Api.NotFound();
            }
            // History (runs, audit) is kept; the schedule just stops.
            job.Enabled = false;
            job.Cron = null;
            job.NextRunAt = null;
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("schedule.delete", organizationId: job.OrganizationId, targetType: "job", targetId: id, detail: new { job.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.ScriptsRun);

        api.MapPost("/jobs/{id:guid}/cancel", async (Guid id, Ctx c, JobDispatcher dispatcher, TimeProvider clock, CancellationToken ct) =>
        {
            var runs = await c.Db.JobRuns.Where(r => r.JobId == id && (r.Status == JobRunStatus.Pending || r.Status == JobRunStatus.Dispatched || r.Status == JobRunStatus.Running)).ToListAsync(ct);
            if (runs.Count == 0 && !await c.Db.JobRuns.AnyAsync(r => r.JobId == id, ct))
            {
                return Api.NotFound();
            }
            foreach (var run in runs)
            {
                await CancelRunAsync(run, c, dispatcher, clock, ct);
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("job.cancel", targetType: "job", targetId: id, detail: new { runs = runs.Count }, ct: ct);
            return Results.Ok(new { cancelled = runs.Count });
        }).RequirePermission(Permissions.JobsCancel);

        // ----- Runs -----
        api.MapGet("/runs", async (Guid? deviceId, Guid? jobId, string? status, string? kind, int? page, int? pageSize, Ctx c, CancellationToken ct) =>
        {
            var (skip, take, p) = Api.Paging(page, pageSize);
            var q = c.Db.JobRuns.AsNoTracking().Where(r => (deviceId == null || r.DeviceId == deviceId) && (jobId == null || r.JobId == jobId) && (kind == null || r.Kind == kind));
            if (status is not null)
            {
                if (!Enum.TryParse<JobRunStatus>(status, true, out var st))
                {
                    return Api.BadRequest("Unknown status.");
                }
                q = q.Where(r => r.Status == st);
            }
            var total = await q.CountAsync(ct);
            var items = await q.OrderByDescending(r => r.CreatedAt).Skip(skip).Take(take).Select(r => new
            {
                r.Id, r.JobId, jobName = r.Job.Name, r.Kind, r.DeviceId, hostname = r.Device.Hostname, status = r.Status.ToString().ToLower(), r.ExitCode, r.Message,
                r.CreatedAt, r.StartedAt, r.FinishedAt, r.Truncated, requestedBy = r.Job.RequestedByName, r.Attempt,
            }).ToListAsync(ct);
            return Results.Ok(new { total, page = p, pageSize = take, items });
        }).RequirePermission(Permissions.JobsRead);

        api.MapGet("/runs/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var r = await c.Db.JobRuns.AsNoTracking().Include(x => x.Job).Include(x => x.Device).FirstOrDefaultAsync(x => x.Id == id, ct);
            if (r is null)
            {
                return Api.NotFound();
            }
            // The run was loaded through the tenant filter, so its output may be read by run id.
            var chunks = await c.Db.JobOutputChunks.IgnoreQueryFilters().AsNoTracking().Where(o => o.JobRunId == id && o.PartnerId == c.Who.PartnerId)
                .OrderBy(o => o.Seq).ThenBy(o => o.Id).Select(o => new { o.Seq, o.Stream, o.Data }).ToListAsync(ct);
            return Results.Ok(new
            {
                r.Id, r.JobId, jobName = r.Job.Name, r.Kind, r.DeviceId, hostname = r.Device.Hostname, status = r.Status.ToString().ToLower(), r.ExitCode, r.Message,
                r.CreatedAt, r.DispatchedAt, r.StartedAt, r.FinishedAt, r.Truncated, r.OutputBytes, r.OutputSha256, requestedBy = r.Job.RequestedByName, r.Attempt, r.MaxAttempts,
                result = r.ResultJson is null ? (JsonElement?)null : JsonSerializer.Deserialize<JsonElement>(r.ResultJson),
                output = chunks,
            });
        }).RequirePermission(Permissions.JobsRead);

        api.MapPost("/runs/{id:guid}/cancel", async (Guid id, Ctx c, JobDispatcher dispatcher, TimeProvider clock, CancellationToken ct) =>
        {
            var run = await c.Db.JobRuns.FirstOrDefaultAsync(r => r.Id == id, ct);
            if (run is null)
            {
                return Api.NotFound();
            }
            if (run.Status is not (JobRunStatus.Pending or JobRunStatus.Dispatched or JobRunStatus.Running))
            {
                return Api.Conflict("The run has already finished.");
            }
            await CancelRunAsync(run, c, dispatcher, clock, ct);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("job.cancel", organizationId: run.OrganizationId, deviceId: run.DeviceId, targetType: "job_run", targetId: id, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.JobsCancel);

        // ----- Saved device filters -----
        api.MapGet("/saved-filters", async (Ctx c, CancellationToken ct) =>
            Results.Ok((await c.Db.SavedFilters.AsNoTracking().OrderBy(f => f.Name).ToListAsync(ct))
                .Select(f => new { f.Id, f.Name, f.OrganizationId, filter = JsonSerializer.Deserialize<JsonElement>(f.FilterJson) })))
            .RequirePermission(Permissions.DevicesRead);

        api.MapPost("/saved-filters", async (FilterRequest req, Ctx c, CancellationToken ct) =>
        {
            if (Api.CleanName(req.Name) is not { } name || req.Filter is null)
            {
                return Api.BadRequest("name and filter are required.");
            }
            var org = req.OrganizationId ?? req.Filter.OrganizationId;
            if (org is { } o ? !c.Tenant.CoversOrganization(o) || !await c.Db.Organizations.AnyAsync(x => x.Id == o, ct) : !c.Tenant.AllOrgs)
            {
                return org is null ? Api.Error(403, "forbidden", "Filters across all organizations need partner-wide scope; set organizationId.") : Api.NotFound();
            }
            var f = new SavedFilter
            {
                Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = org, Name = name,
                FilterJson = JsonSerializer.Serialize(req.Filter with { OrganizationId = org }, JsonSerializerOptions.Web), CreatedByUserId = c.Who.UserId, CreatedAt = c.Now,
            };
            c.Db.SavedFilters.Add(f);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("saved_filter.create", organizationId: org, targetType: "saved_filter", targetId: f.Id, detail: new { name }, ct: ct);
            return Results.Created($"/api/v1/saved-filters/{f.Id}", new { f.Id });
        }).RequirePermission(Permissions.DevicesManage);

        api.MapDelete("/saved-filters/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var f = await c.Db.SavedFilters.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (f is null || (f.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            c.Db.SavedFilters.Remove(f);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("saved_filter.delete", organizationId: f.OrganizationId, targetType: "saved_filter", targetId: id, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.DevicesManage);
    }

    private static async Task CancelRunAsync(JobRun run, Ctx c, JobDispatcher dispatcher, TimeProvider clock, CancellationToken ct)
    {
        run.CancelRequested = true;
        if (run.Status == JobRunStatus.Pending)
        {
            run.Status = JobRunStatus.Cancelled;
            run.FinishedAt = clock.GetUtcNow();
            run.Message = "Cancelled before it was sent to the device.";
        }
        else
        {
            // The agent confirms with a job.result of "cancelled".
            await dispatcher.SendCancelAsync(run.DeviceId, run.Id, ct);
        }
    }
}
