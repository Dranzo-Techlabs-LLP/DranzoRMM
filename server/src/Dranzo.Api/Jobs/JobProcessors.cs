using System.Text.Json;
using Dranzo.Api.Agents;
using Dranzo.Api.Live;
using Dranzo.Domain;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Jobs;

/// <summary>Kind-specific follow-up when a run finishes (inventory updates, patch state, compliance...).</summary>
public interface IJobResultHandler
{
    bool Handles(string kind);

    Task HandleAsync(JobRun run, Device device, JsonElement result, CancellationToken ct);
}

public sealed class JobAckProcessor(DranzoDbContext db, LiveNotifier live, IAuditLog audit, JobDispatcher dispatcher, TimeProvider clock) : IAgentMessageProcessor
{
    public string Type => "job.ack";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var runId = payload.GuidOrNull("jobRunId") ?? throw new FormatException("jobRunId required");
        // The run must belong to the device on this connection: an agent can never touch another device's runs.
        var run = await db.JobRuns.Include(r => r.Device).FirstOrDefaultAsync(r => r.Id == runId && r.DeviceId == conn.DeviceId, ct);
        if (run is null || run.Status != JobRunStatus.Dispatched)
        {
            return;
        }
        var now = clock.GetUtcNow();
        if (payload.Bool("accepted"))
        {
            run.Status = JobRunStatus.Running;
            run.StartedAt = now;
        }
        else
        {
            var reason = payload.Str("reason", 200, "refused");
            if (reason == "duplicate")
            {
                // The agent already has this run (a retransmission); it is in progress.
                run.Status = JobRunStatus.Running;
                run.StartedAt ??= now;
            }
            else if (reason is "busy" or "shutting_down")
            {
                run.Status = JobRunStatus.Pending;
                run.DispatchedAt = null;
                run.NotBefore = now.AddSeconds(30);
            }
            else
            {
                run.Status = JobRunStatus.Rejected;
                run.Message = "Refused by the agent: " + reason;
                run.FinishedAt = now;
                await audit.WriteAsync(run.PartnerId, new AuditEntry("job.refused_by_agent", "failure", run.OrganizationId, run.DeviceId, "job_run", run.Id.ToString(),
                    new { reason, run.Kind }, ActorType: "agent", ActorId: run.DeviceId, ActorName: run.Device.Hostname, Ip: conn.RemoteIp), ct);
            }
        }
        await db.SaveChangesAsync(ct);
        await live.RunChangedAsync(run, run.Device);
        if (run.Status != JobRunStatus.Running)
        {
            dispatcher.Kick(run.DeviceId);
        }
    }
}

public sealed class JobOutputProcessor(DranzoDbContext db, LiveNotifier live) : IAgentMessageProcessor
{
    public const int MaxChunkChars = 64 * 1024;

    public string Type => "job.output";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var runId = payload.GuidOrNull("jobRunId") ?? throw new FormatException("jobRunId required");
        var run = await db.JobRuns.FirstOrDefaultAsync(r => r.Id == runId && r.DeviceId == conn.DeviceId, ct);
        if (run is null || run.Status is not (JobRunStatus.Running or JobRunStatus.Dispatched))
        {
            return;
        }
        var data = payload.Str("data", MaxChunkChars);
        var stream = payload.Str("stream", 8) == "stderr" ? "stderr" : "stdout";
        var seq = (int)Math.Clamp(payload.Long("seq") ?? 0, 0, int.MaxValue);
        var bytes = System.Text.Encoding.UTF8.GetByteCount(data);
        // The agent enforces the cap; the server enforces it again and never stores more than allowed.
        if (run.OutputBytes + bytes > run.MaxOutputBytes)
        {
            if (!run.Truncated)
            {
                run.Truncated = true;
                await db.SaveChangesAsync(ct);
            }
            return;
        }
        run.OutputBytes += bytes;
        db.JobOutputChunks.Add(new JobOutputChunk { PartnerId = run.PartnerId, JobRunId = run.Id, Seq = seq, Stream = stream, Data = data });
        await db.SaveChangesAsync(ct);
        await live.RunOutputAsync(run.Id, seq, stream, data);
    }
}

public sealed class JobResultProcessor(DranzoDbContext db, LiveNotifier live, IAuditLog audit, JobDispatcher dispatcher, IEnumerable<IJobResultHandler> handlers, Dranzo.Api.Notifications.NotificationService notifications, TimeProvider clock, ILogger<JobResultProcessor> log) : IAgentMessageProcessor
{
    private static readonly Dictionary<string, JobRunStatus> Statuses = new()
    {
        ["succeeded"] = JobRunStatus.Succeeded, ["failed"] = JobRunStatus.Failed, ["timeout"] = JobRunStatus.TimedOut,
        ["cancelled"] = JobRunStatus.Cancelled, ["rejected"] = JobRunStatus.Rejected, ["unsupported"] = JobRunStatus.Unsupported,
    };

    public string Type => "job.result";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var runId = payload.GuidOrNull("jobRunId") ?? throw new FormatException("jobRunId required");
        var run = await db.JobRuns.Include(r => r.Device).Include(r => r.Job).FirstOrDefaultAsync(r => r.Id == runId && r.DeviceId == conn.DeviceId, ct);
        if (run is null || run.Status is not (JobRunStatus.Running or JobRunStatus.Dispatched))
        {
            return; // unknown, foreign or already finished: ignore (results are accepted exactly once)
        }
        if (!Statuses.TryGetValue(payload.Str("status", 16), out var status))
        {
            throw new FormatException("unknown job status");
        }
        var now = clock.GetUtcNow();
        run.Status = status;
        run.StartedAt ??= now;
        run.FinishedAt = now;
        run.ExitCode = payload.Long("exitCode") is { } code ? (int)Math.Clamp(code, int.MinValue, int.MaxValue) : null;
        run.Message = payload.StrOrNull("message", 2000);
        run.Truncated = run.Truncated || payload.Bool("truncated");
        var sha = payload.Str("outputSha256", 64);
        run.OutputSha256 = sha.Length == 64 && sha.All(Uri.IsHexDigit) ? sha.ToLowerInvariant() : null;
        JsonElement result = default;
        if (payload.TryGetProperty("result", out var r) && r.ValueKind == JsonValueKind.Object)
        {
            var raw = r.GetRawText();
            if (raw.Length <= 1_500_000)
            {
                run.ResultJson = raw;
                result = r;
            }
        }
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(run.PartnerId, new AuditEntry("job.result", status is JobRunStatus.Succeeded ? "success" : "failure", run.OrganizationId, run.DeviceId, "job_run", run.Id.ToString(),
            new { run.Kind, status = payload.Str("status", 16), run.ExitCode, run.Truncated, run.OutputBytes, jobId = run.JobId },
            ContentSha256: run.OutputSha256, ActorType: "agent", ActorId: run.DeviceId, ActorName: run.Device.Hostname, Ip: conn.RemoteIp), ct);

        foreach (var handler in handlers.Where(h => h.Handles(run.Kind)))
        {
            try
            {
                await handler.HandleAsync(run, run.Device, result, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log.LogError(ex, "Result handler {Handler} failed for run {RunId}", handler.GetType().Name, run.Id);
            }
        }

        if (status == JobRunStatus.Failed && run.Attempt < run.MaxAttempts)
        {
            db.JobRuns.Add(new JobRun
            {
                Id = Guid.NewGuid(), PartnerId = run.PartnerId, OrganizationId = run.OrganizationId, DeviceId = run.DeviceId, JobId = run.JobId, BatchId = run.BatchId,
                Kind = run.Kind, SpecJson = run.SpecJson, Status = JobRunStatus.Pending, CreatedAt = now, NotBefore = now.AddSeconds(60), ExpiresAt = run.ExpiresAt,
                Attempt = run.Attempt + 1, MaxAttempts = run.MaxAttempts, TimeoutSeconds = run.TimeoutSeconds, MaxOutputBytes = run.MaxOutputBytes, SessionId = run.SessionId,
            });
            await db.SaveChangesAsync(ct);
        }
        await live.RunChangedAsync(run, run.Device);
        if (!run.Job.IsSystem)
        {
            await notifications.PublishEventAsync(run.PartnerId, run.OrganizationId, "job.finished",
                new { runId = run.Id, jobId = run.JobId, job = run.Job.Name, run.Kind, deviceId = run.DeviceId, hostname = run.Device.Hostname, status = payload.Str("status", 16), run.ExitCode }, ct);
        }
        dispatcher.Kick(run.DeviceId);
    }
}
