using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Dranzo.Api.Agents;
using Dranzo.Api.Live;
using Dranzo.Domain;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Jobs;

/// <summary>
/// Sends pending runs to connected agents. Single consumer, so a run is never dispatched twice.
/// Commands are signed here, at send time, with a fresh nonce and short expiry.
/// </summary>
public sealed class JobDispatcher : BackgroundService
{
    private readonly Channel<Guid> _kicks = Channel.CreateUnbounded<Guid>(new UnboundedChannelOptions { SingleReader = true });
    private readonly IServiceScopeFactory _scopes;
    private readonly AgentRegistry _registry;
    private readonly EnvelopeFactory _envelopes;
    private readonly IOptions<DranzoOptions> _options;
    private readonly TimeProvider _clock;
    private readonly ILogger<JobDispatcher> _log;

    public JobDispatcher(IServiceScopeFactory scopes, AgentRegistry registry, EnvelopeFactory envelopes, IOptions<DranzoOptions> options, TimeProvider clock, ILogger<JobDispatcher> log)
    {
        _scopes = scopes;
        _registry = registry;
        _envelopes = envelopes;
        _options = options;
        _clock = clock;
        _log = log;
        registry.DeviceReady += Kick;
    }

    /// <summary>Asks the dispatcher to look at one device's queue now.</summary>
    public void Kick(Guid deviceId) => _kicks.Writer.TryWrite(deviceId);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var lastSweep = DateTimeOffset.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var wait = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                wait.CancelAfter(TimeSpan.FromSeconds(5));
                var devices = new HashSet<Guid>();
                try
                {
                    devices.Add(await _kicks.Reader.ReadAsync(wait.Token));
                    while (_kicks.Reader.TryRead(out var more))
                    {
                        devices.Add(more);
                    }
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                {
                }
                if (DateTimeOffset.UtcNow - lastSweep > TimeSpan.FromSeconds(5))
                {
                    lastSweep = DateTimeOffset.UtcNow;
                    await SweepAsync(stoppingToken);
                    devices.UnionWith(_registry.ConnectedDeviceIds);
                }
                foreach (var deviceId in devices)
                {
                    await DispatchDeviceAsync(deviceId, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Dispatcher loop failed");
                await Task.Delay(1000, stoppingToken);
            }
        }
    }

    /// <summary>Runs one dispatch pass for a device (also called directly by tests).</summary>
    public async Task DispatchDeviceAsync(Guid deviceId, CancellationToken ct)
    {
        if (!_registry.IsConnected(deviceId))
        {
            return;
        }
        await using var scope = _scopes.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
        var db = scope.ServiceProvider.GetRequiredService<DranzoDbContext>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditLog>();
        var live = scope.ServiceProvider.GetRequiredService<LiveNotifier>();
        var now = _clock.GetUtcNow();
        var opt = _options.Value.Agents;

        var device = await db.Devices.FirstOrDefaultAsync(d => d.Id == deviceId && d.Status == DeviceStatus.Active, ct);
        if (device is null)
        {
            return;
        }
        var active = await db.JobRuns.CountAsync(r => r.DeviceId == deviceId && (r.Status == JobRunStatus.Dispatched || r.Status == JobRunStatus.Running), ct);
        var slots = opt.MaxConcurrentRunsPerDevice - active;
        if (slots <= 0)
        {
            return;
        }
        var pending = await db.JobRuns.Include(r => r.Job)
            .Where(r => r.DeviceId == deviceId && r.Status == JobRunStatus.Pending && r.ExpiresAt > now && (r.NotBefore == null || r.NotBefore <= now))
            .OrderBy(r => r.CreatedAt).Take(slots * 4).ToListAsync(ct);
        if (pending.Count == 0)
        {
            return;
        }
        var org = await db.Organizations.FirstOrDefaultAsync(o => o.Id == device.OrganizationId, ct);

        foreach (var run in pending)
        {
            if (slots <= 0)
            {
                break;
            }
            if (run.CancelRequested)
            {
                run.Status = JobRunStatus.Cancelled;
                run.FinishedAt = now;
                continue;
            }
            if (run.Job.MaxParallel > 0)
            {
                var inFlight = await db.JobRuns.CountAsync(r => r.JobId == run.JobId && (r.Status == JobRunStatus.Dispatched || r.Status == JobRunStatus.Running), ct);
                if (inFlight >= run.Job.MaxParallel)
                {
                    continue;
                }
            }
            var (spec, unsupported) = JobService.BuildWireSpec(run.Job, run, device, org);
            if (spec is null)
            {
                run.Status = JobRunStatus.Unsupported;
                run.Message = unsupported;
                run.FinishedAt = now;
                await db.SaveChangesAsync(ct);
                await live.RunChangedAsync(run, device);
                continue;
            }
            await GrantBlobsAsync(db, device, spec, now, ct);
            var fields = new Dictionary<string, object?>
            {
                ["jobRunId"] = run.Id.ToString("D"),
                ["kind"] = run.Kind,
                ["timeoutSeconds"] = run.TimeoutSeconds,
                ["maxOutputBytes"] = run.MaxOutputBytes,
                ["sessionId"] = run.SessionId?.ToString("D"),
                ["spec"] = spec,
            };
            var envelope = _envelopes.Signed("job.dispatch", deviceId, fields, validity: TimeSpan.FromSeconds(opt.CommandValiditySeconds));
            // Persist "Dispatched" before sending so a crash cannot lead to a second dispatch of the same run.
            run.Status = JobRunStatus.Dispatched;
            run.DispatchedAt = now;
            await db.SaveChangesAsync(ct);
            if (!await _registry.SendAsync(deviceId, envelope, ct))
            {
                run.Status = JobRunStatus.Pending;
                run.DispatchedAt = null;
                await db.SaveChangesAsync(ct);
                return;
            }
            slots--;
            await audit.WriteAsync(device.PartnerId, new AuditEntry("job.dispatch", OrganizationId: device.OrganizationId, DeviceId: deviceId, TargetType: "job_run", TargetId: run.Id.ToString(),
                Detail: new { run.Kind, jobId = run.JobId, job = run.Job.Name, requestedBy = run.Job.RequestedByName, attempt = run.Attempt },
                ContentSha256: run.Job.ContentSha256.Length > 0 ? run.Job.ContentSha256 : Hashing.Sha256Hex(spec.ToJsonString()),
                ActorType: run.Job.IsSystem ? "system" : run.Job.RequestedByName.StartsWith("apikey:", StringComparison.Ordinal) ? "apikey" : "user",
                ActorId: run.Job.RequestedByUserId, ActorName: run.Job.RequestedByName), ct);
            await live.RunChangedAsync(run, device);
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>A device may download a blob only while a run that references it was recently dispatched to it.</summary>
    private static async Task GrantBlobsAsync(DranzoDbContext db, Device device, JsonNode spec, DateTimeOffset now, CancellationToken ct)
    {
        if (spec is JsonObject o && o["blobId"] is JsonValue v && v.TryGetValue<string>(out var s) && Guid.TryParse(s, out var blobId)
            && await db.Blobs.AnyAsync(b => b.Id == blobId && b.PartnerId == device.PartnerId, ct))
        {
            db.BlobGrants.Add(new BlobGrant { Id = Guid.NewGuid(), PartnerId = device.PartnerId, BlobId = blobId, DeviceId = device.Id, ExpiresAt = now.AddHours(1) });
        }
    }

    /// <summary>Housekeeping: expire stale pending runs, time out runs whose agent never answered.</summary>
    public async Task SweepAsync(CancellationToken ct)
    {
        await using var scope = _scopes.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
        var db = scope.ServiceProvider.GetRequiredService<DranzoDbContext>();
        var now = _clock.GetUtcNow();
        var opt = _options.Value.Agents;

        await db.JobRuns.Where(r => r.Status == JobRunStatus.Pending && r.ExpiresAt <= now)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, JobRunStatus.Expired).SetProperty(r => r.FinishedAt, now)
                .SetProperty(r => r.Message, "Device did not come online before the job expired."), ct);

        // Dispatched but never acknowledged within the command validity (+ skew): the command can no longer be accepted.
        var ackDeadline = now.AddSeconds(-(opt.CommandValiditySeconds + 330));
        var unacked = await db.JobRuns.Where(r => r.Status == JobRunStatus.Dispatched && r.DispatchedAt < ackDeadline).ToListAsync(ct);
        foreach (var run in unacked)
        {
            if (run.Attempt < run.MaxAttempts)
            {
                run.Status = JobRunStatus.Pending;
                run.Attempt++;
                run.DispatchedAt = null;
            }
            else
            {
                run.Status = JobRunStatus.Failed;
                run.Message = "The agent did not acknowledge the job.";
                run.FinishedAt = now;
            }
        }
        // Running far past its timeout with no result: the agent lost it (crash, reboot, uninstall).
        var lost = await db.JobRuns.Where(r => r.Status == JobRunStatus.Running && r.StartedAt != null).ToListAsync(ct);
        foreach (var run in lost.Where(r => r.StartedAt!.Value.AddSeconds(r.TimeoutSeconds + 300) < now))
        {
            run.Status = JobRunStatus.TimedOut;
            run.Message = "No result received from the agent.";
            run.FinishedAt = now;
        }
        await db.SaveChangesAsync(ct);
        await db.BlobGrants.Where(g => g.ExpiresAt <= now).ExecuteDeleteAsync(ct);
    }

    /// <summary>Sends a signed cancel for a run that is already with the agent.</summary>
    public Task<bool> SendCancelAsync(Guid deviceId, Guid runId, CancellationToken ct) =>
        _registry.SendAsync(deviceId, _envelopes.Signed("job.cancel", deviceId, new Dictionary<string, object?> { ["jobRunId"] = runId.ToString("D") }), ct);
}

/// <summary>Fires cron-scheduled jobs in the job's time zone.</summary>
public sealed class Scheduler(IServiceScopeFactory scopes, ILogger<Scheduler> log) : Services.PeriodicService(scopes, log, TimeSpan.FromSeconds(20))
{
    public static DateTimeOffset? NextOccurrence(string cron, string timeZone, DateTimeOffset after)
    {
        var expr = Cronos.CronExpression.Parse(cron, Cronos.CronFormat.Standard);
        var tz = TimeZoneInfo.FindSystemTimeZoneById(timeZone);
        return expr.GetNextOccurrence(after, tz)?.ToUniversalTime();
    }

    public static bool TryParse(string cron, out string? error)
    {
        try
        {
            Cronos.CronExpression.Parse(cron, Cronos.CronFormat.Standard);
            error = null;
            return true;
        }
        catch (Cronos.CronFormatException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    protected override Task TickAsync(IServiceProvider sp, CancellationToken ct) => RunDueAsync(sp, ct);

    private static string PermissionFor(string kind) => kind switch
    {
        JobKinds.Script => Permissions.ScriptsRun,
        JobKinds.PatchInstall or JobKinds.PatchScan => Permissions.PatchesInstall,
        JobKinds.SoftwareInstall or JobKinds.SoftwareUninstall or JobKinds.PackageInstall or JobKinds.PackageUninstall => Permissions.SoftwareDeploy,
        JobKinds.NetworkScan => Permissions.NetworkManage,
        _ => Permissions.DevicesManage,
    };

    public static async Task RunDueAsync(IServiceProvider sp, CancellationToken ct)
    {
        var db = sp.GetRequiredService<DranzoDbContext>();
        var jobs = sp.GetRequiredService<JobService>();
        var dispatcher = sp.GetRequiredService<JobDispatcher>();
        var now = sp.GetRequiredService<TimeProvider>().GetUtcNow();
        var due = await db.Jobs.Where(j => j.Cron != null && j.Enabled && j.NextRunAt != null && j.NextRunAt <= now).ToListAsync(ct);
        foreach (var job in due)
        {
            var target = JsonSerializer.Deserialize<JobTarget>(job.TargetJson, JobService.Json) ?? new JobTarget();
            // The target was validated against the creator's scope when the schedule was created; it is re-resolved
            // inside the job's partner (and organization, when set) every time it fires.
            var q = db.Devices.Where(d => d.PartnerId == job.PartnerId);
            if (job.OrganizationId is { } org)
            {
                q = q.Where(d => d.OrganizationId == org);
            }
            var devices = await target.Apply(q).ToListAsync(ct);
            // Run with the authority the creator has *now*: a disabled or removed technician's schedule stops, and devices
            // that later moved out of their scope are skipped.
            if (job.RequestedByUserId is { } creatorId)
            {
                var creator = await db.Users.IgnoreQueryFilters().AsNoTracking().FirstOrDefaultAsync(u => u.Id == creatorId && u.PartnerId == job.PartnerId, ct);
                var scope = new TenantContext();
                var allowed = creator is { Disabled: false } && await sp.GetRequiredService<Auth.ScopeResolver>().ApplyAsync(scope,
                    new Auth.CurrentPrincipal { IsAuthenticated = true, PartnerId = job.PartnerId, UserId = creatorId }, PermissionFor(job.Kind), false, ct);
                if (!allowed)
                {
                    job.Enabled = false;
                    job.NextRunAt = null;
                    await db.SaveChangesAsync(ct);
                    await sp.GetRequiredService<IAuditLog>().WriteAsync(job.PartnerId, new AuditEntry("schedule.disabled", "denied", job.OrganizationId, TargetType: "job", TargetId: job.Id.ToString(),
                        Detail: new { job.Name, reason = "creator no longer holds the permission" }, ActorType: "system", ActorName: "scheduler"), ct);
                    continue;
                }
                devices = [.. devices.Where(d => scope.CoversDevice(d.PartnerId, d.OrganizationId, d.SiteId, d.GroupId))];
            }
            var runs = jobs.AddRuns(job, devices);
            job.NextRunAt = NextOccurrence(job.Cron!, job.TimeZone ?? "UTC", now);
            await db.SaveChangesAsync(ct);
            foreach (var run in runs)
            {
                dispatcher.Kick(run.DeviceId);
            }
        }
    }
}
