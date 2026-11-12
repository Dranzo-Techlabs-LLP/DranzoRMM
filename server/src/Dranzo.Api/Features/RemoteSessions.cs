using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using Dranzo.Api.Agents;
using Dranzo.Api.Live;
using Dranzo.Api.Notifications;
using Dranzo.Domain;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

/// <summary>In-memory state of a remote session that is requested or running.</summary>
public sealed class LiveSession(Guid id, Guid deviceId, Guid partnerId, Guid organizationId, Guid userId, string kind) : IDisposable
{
    private readonly IncrementalHash _inputHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    private readonly Lock _lock = new();
    private long _seq;
    private bool _disposed;

    public Guid Id { get; } = id;
    public Guid DeviceId { get; } = deviceId;
    public Guid PartnerId { get; } = partnerId;
    public Guid OrganizationId { get; } = organizationId;
    public Guid UserId { get; } = userId;
    public string Kind { get; } = kind;
    public volatile bool Active;
    public long BytesIn;
    public long BytesOut;
    public DateTimeOffset LastActivity { get; set; }

    /// <summary>Next <c>session.input</c> sequence number (strictly increasing, starts at 1) and transcript hash update.</summary>
    public long NextInput(ReadOnlySpan<byte> data)
    {
        lock (_lock)
        {
            if (!_disposed && data.Length > 0)
            {
                _inputHash.AppendData(data);
            }
            BytesIn += data.Length;
            return ++_seq;
        }
    }

    public string FinishInputHash()
    {
        lock (_lock)
        {
            return _disposed ? "" : Convert.ToHexStringLower(_inputHash.GetCurrentHash());
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            _disposed = true;
            _inputHash.Dispose();
        }
    }
}

public sealed class SessionRegistry
{
    private readonly ConcurrentDictionary<Guid, LiveSession> _sessions = new();

    public LiveSession Add(LiveSession s) => _sessions[s.Id] = s;

    public LiveSession? Get(Guid id) => _sessions.GetValueOrDefault(id);

    public LiveSession? Remove(Guid id) => _sessions.TryRemove(id, out var s) ? s : null;

    public IReadOnlyList<LiveSession> ForDevice(Guid deviceId) => [.. _sessions.Values.Where(s => s.DeviceId == deviceId)];

    public IReadOnlyList<LiveSession> All => [.. _sessions.Values];
}

/// <summary>Starts, tracks and ends remote sessions. Every state change is audited.</summary>
public sealed class RemoteSessionService(DranzoDbContext db, SessionRegistry registry, AgentRegistry agents, EnvelopeFactory envelopes, IAuditLog audit, LiveNotifier notifier,
    NotificationService notifications, TimeProvider clock)
{
    public const int MaxSessionHours = 12;
    public const int IdleMinutes = 30;

    public async Task<(RemoteSession? Session, string? Error)> StartAsync(Device device, Organization org, string kind, Guid userId, string userName, string displayName, string? ip, object? extra, CancellationToken ct)
    {
        if (!agents.IsConnected(device.Id))
        {
            return (null, "The device is offline.");
        }
        if (device.Capabilities.Length > 0 && !device.Capabilities.Contains("session." + kind))
        {
            return (null, $"The agent on this device does not support {kind} sessions.");
        }
        var now = clock.GetUtcNow();
        var session = new RemoteSession
        {
            Id = Guid.NewGuid(), PartnerId = device.PartnerId, OrganizationId = device.OrganizationId, DeviceId = device.Id, UserId = userId, UserName = userName, Kind = kind,
            ConsentMode = org.ConsentMode, State = RemoteSessionState.Requested, RequestedAt = now, Ip = ip,
        };
        db.RemoteSessions.Add(session);
        await db.SaveChangesAsync(ct);
        registry.Add(new LiveSession(session.Id, device.Id, device.PartnerId, device.OrganizationId, userId, kind) { LastActivity = now });
        await audit.WriteAsync(device.PartnerId, new AuditEntry("session.request", OrganizationId: device.OrganizationId, DeviceId: device.Id, TargetType: "remote_session", TargetId: session.Id.ToString(),
            Detail: new { kind, consent = org.ConsentMode.ToString().ToLowerInvariant() }), ct);

        var fields = new Dictionary<string, object?>
        {
            ["sessionId"] = session.Id.ToString("D"),
            ["kind"] = kind,
            ["consent"] = org.ConsentMode.ToString().ToLowerInvariant(),
            ["consentTimeoutSeconds"] = 60,
            // Shown to the person at the device: who is connecting.
            ["requestedBy"] = displayName,
        };
        if (extra is not null)
        {
            fields[kind] = extra;
        }
        if (!await agents.SendAsync(device.Id, envelopes.Signed("session.start", device.Id, fields), ct))
        {
            await FinishAsync(session.Id, RemoteSessionState.Failed, "The device went offline.", null, ct);
            return (null, "The device went offline.");
        }
        return (session, null);
    }

    /// <summary>Applies a state reported by the agent (already checked to come from the session's own device).</summary>
    public async Task OnAgentStatusAsync(LiveSession live, string state, string? reason, string? agentIp, CancellationToken ct)
    {
        switch (state)
        {
            case "pending_consent":
                await db.RemoteSessions.Where(s => s.Id == live.Id && s.State == RemoteSessionState.Requested)
                    .ExecuteUpdateAsync(s => s.SetProperty(x => x.State, RemoteSessionState.PendingConsent), ct);
                await notifier.SessionAsync(live.Id, "sessionState", new { sessionId = live.Id, state = "pending_consent" });
                break;
            case "active":
                var session = await db.RemoteSessions.Include(s => s.Device).FirstOrDefaultAsync(s => s.Id == live.Id, ct);
                if (session is null || session.State is not (RemoteSessionState.Requested or RemoteSessionState.PendingConsent))
                {
                    return;
                }
                var now = clock.GetUtcNow();
                session.State = RemoteSessionState.Active;
                session.StartedAt = now;
                session.ConsentResult = session.ConsentMode switch
                {
                    ConsentMode.Require => reason == "no_user_logged_in" ? "no_user_logged_in" : "accepted",
                    ConsentMode.Notify => "notified",
                    _ => "not_required",
                };
                await db.SaveChangesAsync(ct);
                live.Active = true;
                live.LastActivity = now;
                await audit.WriteAsync(session.PartnerId, new AuditEntry("session.start", OrganizationId: session.OrganizationId, DeviceId: session.DeviceId, TargetType: "remote_session", TargetId: session.Id.ToString(),
                    Detail: new { session.Kind, consent = session.ConsentMode.ToString().ToLowerInvariant(), consentResult = session.ConsentResult },
                    ActorType: "user", ActorId: session.UserId, ActorName: session.UserName, Ip: session.Ip), ct);
                await notifications.PublishEventAsync(session.PartnerId, session.OrganizationId, "session.started", new { sessionId = session.Id, session.Kind, deviceId = session.DeviceId, hostname = session.Device.Hostname, user = session.UserName }, ct);
                await notifier.SessionAsync(live.Id, "sessionState", new { sessionId = live.Id, state = "active", consentResult = session.ConsentResult });
                break;
            case "denied":
                await FinishAsync(live.Id, RemoteSessionState.Denied, reason ?? "user_denied", agentIp, ct);
                break;
            case "failed":
                await FinishAsync(live.Id, RemoteSessionState.Failed, reason ?? "failed", agentIp, ct);
                break;
            case "ended":
                await FinishAsync(live.Id, RemoteSessionState.Ended, reason ?? "ended", agentIp, ct);
                break;
        }
    }

    /// <summary>Ends a session from the server side (technician, timeout, disconnect). Sends a signed <c>session.end</c>.</summary>
    public async Task EndAsync(Guid sessionId, string reason, CancellationToken ct, Guid? endedById = null, string? endedByName = null)
    {
        var live = registry.Get(sessionId);
        if (live is not null)
        {
            await agents.SendAsync(live.DeviceId, envelopes.Signed("session.end", live.DeviceId, new Dictionary<string, object?> { ["sessionId"] = sessionId.ToString("D"), ["reason"] = reason }), ct);
        }
        await FinishAsync(sessionId, RemoteSessionState.Ended, reason, null, ct, endedById, endedByName);
    }

    private async Task FinishAsync(Guid sessionId, RemoteSessionState state, string reason, string? agentIp, CancellationToken ct, Guid? endedById = null, string? endedByName = null)
    {
        var live = registry.Remove(sessionId);
        var session = await db.RemoteSessions.Include(s => s.Device).FirstOrDefaultAsync(s => s.Id == sessionId, ct);
        if (session is null || session.State is RemoteSessionState.Ended or RemoteSessionState.Denied or RemoteSessionState.Failed)
        {
            live?.Dispose();
            return;
        }
        var wasActive = session.State == RemoteSessionState.Active;
        session.State = state;
        session.EndedAt = clock.GetUtcNow();
        session.EndReason = reason.Length > 200 ? reason[..200] : reason;
        if (state == RemoteSessionState.Denied)
        {
            session.ConsentResult = reason == "timeout" ? "timeout" : "denied";
        }
        if (live is not null)
        {
            session.BytesIn = live.BytesIn;
            session.BytesOut = live.BytesOut;
            session.InputSha256 = live.Kind == "terminal" ? live.FinishInputHash() : null;
            live.Active = false;
            live.Dispose();
        }
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(session.PartnerId, new AuditEntry(state == RemoteSessionState.Denied ? "session.denied" : "session.end", state is RemoteSessionState.Ended ? "success" : "failure",
            session.OrganizationId, session.DeviceId, "remote_session", session.Id.ToString(),
            new { session.Kind, reason = session.EndReason, consentResult = session.ConsentResult, session.BytesIn, session.BytesOut, seconds = session.StartedAt is null ? 0 : (int)(session.EndedAt.Value - session.StartedAt.Value).TotalSeconds, owner = session.UserName },
            ContentSha256: session.InputSha256, ActorType: "user", ActorId: endedById ?? session.UserId, ActorName: endedByName ?? session.UserName, Ip: session.Ip ?? agentIp), ct);
        if (wasActive)
        {
            await notifications.PublishEventAsync(session.PartnerId, session.OrganizationId, "session.ended", new { sessionId = session.Id, session.Kind, deviceId = session.DeviceId, hostname = session.Device.Hostname, user = session.UserName, reason = session.EndReason }, ct);
        }
        await notifier.SessionAsync(sessionId, "sessionState", new { sessionId, state = state.ToString().ToLowerInvariant(), reason = session.EndReason });
    }

    /// <summary>Relays one signed terminal input frame. The caller has been authorised by the hub.</summary>
    public async Task<bool> SendInputAsync(LiveSession live, string kind, byte[]? data, int? cols, int? rows, CancellationToken ct)
    {
        if (!live.Active || live.Kind != "terminal")
        {
            return false;
        }
        var seq = live.NextInput(data ?? []);
        live.LastActivity = clock.GetUtcNow();
        var fields = new Dictionary<string, object?> { ["sessionId"] = live.Id.ToString("D"), ["seq"] = seq, ["kind"] = kind };
        if (data is not null)
        {
            fields["data"] = Convert.ToBase64String(data);
        }
        if (cols is not null)
        {
            fields["cols"] = Math.Clamp(cols.Value, 10, 500);
            fields["rows"] = Math.Clamp(rows ?? 24, 5, 300);
        }
        return await agents.SendAsync(live.DeviceId, envelopes.Signed("session.input", live.DeviceId, fields, withNonce: false), ct);
    }
}

public sealed class SessionStatusProcessor(RemoteSessionService sessions, SessionRegistry registry) : IAgentMessageProcessor
{
    private static readonly HashSet<string> States = ["pending_consent", "active", "denied", "ended", "failed"];

    public string Type => "session.status";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var id = payload.GuidOrNull("sessionId") ?? throw new FormatException("sessionId required");
        var live = registry.Get(id);
        // Only the device the session was opened on may report on it.
        if (live is null || live.DeviceId != conn.DeviceId)
        {
            return;
        }
        var state = payload.Str("state", 32);
        if (!States.Contains(state))
        {
            throw new FormatException("unknown session state");
        }
        await sessions.OnAgentStatusAsync(live, state, payload.StrOrNull("reason", 200), conn.RemoteIp, ct);
    }
}

public sealed class SessionOutputProcessor(SessionRegistry registry, LiveNotifier live, TimeProvider clock) : IAgentMessageProcessor
{
    public string Type => "session.output";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var id = payload.GuidOrNull("sessionId") ?? throw new FormatException("sessionId required");
        var session = registry.Get(id);
        if (session is null || session.DeviceId != conn.DeviceId || !session.Active || session.Kind != "terminal")
        {
            return;
        }
        var data = payload.Str("data", 256 * 1024);
        Interlocked.Add(ref session.BytesOut, data.Length * 3L / 4);
        session.LastActivity = clock.GetUtcNow();
        await live.SessionAsync(id, "terminalOutput", new { sessionId = id, seq = payload.Long("seq") ?? 0, data });
    }
}

/// <summary>Ends sessions whose device disconnected, that are idle, or that exceeded the maximum length.</summary>
public sealed class SessionMonitor : Services.PeriodicService
{
    public SessionMonitor(IServiceScopeFactory scopes, ILogger<SessionMonitor> log, AgentRegistry agents, SessionRegistry registry) : base(scopes, log, TimeSpan.FromSeconds(30))
    {
        // Fail closed: when the control connection drops, the session is over on both sides.
        agents.DeviceGone += deviceId => _ = Task.Run(async () =>
        {
            foreach (var s in registry.ForDevice(deviceId))
            {
                try
                {
                    await using var scope = Scopes.CreateAsyncScope();
                    scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
                    await scope.ServiceProvider.GetRequiredService<RemoteSessionService>().EndAsync(s.Id, "connection lost", default);
                }
                catch (Exception ex)
                {
                    log.LogError(ex, "Failed to end session {SessionId} after disconnect", s.Id);
                }
            }
        });
    }

    protected override async Task TickAsync(IServiceProvider sp, CancellationToken ct)
    {
        var registry = sp.GetRequiredService<SessionRegistry>();
        var sessions = sp.GetRequiredService<RemoteSessionService>();
        var db = sp.GetRequiredService<DranzoDbContext>();
        var now = sp.GetRequiredService<TimeProvider>().GetUtcNow();
        foreach (var s in registry.All.Where(s => now - s.LastActivity > TimeSpan.FromMinutes(RemoteSessionService.IdleMinutes)))
        {
            await sessions.EndAsync(s.Id, s.Active ? "idle timeout" : "no response from the device", ct);
        }
        var tooLong = await db.RemoteSessions.Where(s => s.State == RemoteSessionState.Active && s.StartedAt < now.AddHours(-RemoteSessionService.MaxSessionHours)).Select(s => s.Id).ToListAsync(ct);
        foreach (var id in tooLong)
        {
            await sessions.EndAsync(id, "maximum session length reached", ct);
        }
        // Sessions left open in the database by a server restart.
        var live = registry.All.Select(s => s.Id).ToList();
        await db.RemoteSessions.Where(s => (s.State == RemoteSessionState.Active || s.State == RemoteSessionState.Requested || s.State == RemoteSessionState.PendingConsent) && !live.Contains(s.Id))
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.State, RemoteSessionState.Ended).SetProperty(x => x.EndedAt, now).SetProperty(x => x.EndReason, "server restarted"), ct);
    }
}
