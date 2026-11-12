using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

namespace Dranzo.Api.Agents;

/// <summary>One live agent WebSocket.</summary>
public sealed class AgentConnection(Guid deviceId, Guid partnerId, Guid organizationId, WebSocket socket, int ratePerSecond, int burst) : IDisposable
{
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly Lock _rateLock = new();
    private double _tokens = burst;
    private long _lastRefill = Environment.TickCount64;

    public Guid DeviceId { get; } = deviceId;
    public Guid PartnerId { get; } = partnerId;
    public Guid OrganizationId { get; } = organizationId;
    public Guid ConnectionId { get; } = Guid.NewGuid();

    /// <summary>
    /// Heavy report types are rate-limited per connection on top of the overall token bucket: one burst of a few
    /// messages, then about one per minute. A compromised agent cannot use them to load the server.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, (int Burst, double PerMinute, int MaxBytes)> TypeLimits = new Dictionary<string, (int, double, int)>
    {
        ["inventory"] = (5, 1, 512 * 1024),
        ["software.inventory"] = (5, 1, 2 * 1024 * 1024),
        ["posture"] = (5, 1, 512 * 1024),
        ["patch.state"] = (5, 1, 1024 * 1024),
        ["error"] = (10, 2, 16 * 1024),
        ["update.status"] = (10, 4, 16 * 1024),
    };

    private readonly Dictionary<string, (double Tokens, long Last)> _typeBuckets = [];

    /// <summary>Last content hash per report type, so an unchanged report is not processed again.</summary>
    public Dictionary<string, string> LastReportHash { get; } = [];

    /// <summary>False when <paramref name="type"/> is over its own limit (size or rate).</summary>
    public bool TryConsumeType(string type, int bytes)
    {
        if (!TypeLimits.TryGetValue(type, out var limit))
        {
            return true;
        }
        if (bytes > limit.MaxBytes)
        {
            return false;
        }
        lock (_rateLock)
        {
            var now = Environment.TickCount64;
            var (tokens, last) = _typeBuckets.TryGetValue(type, out var b) ? b : (limit.Burst, now);
            tokens = Math.Min(limit.Burst, tokens + ((now - last) / 60_000.0 * limit.PerMinute));
            if (tokens < 1)
            {
                _typeBuckets[type] = (tokens, now);
                return false;
            }
            _typeBuckets[type] = (tokens - 1, now);
            return true;
        }
    }
    public bool HelloReceived { get; set; }
    public string? RemoteIp { get; init; }
    public WebSocket Socket => socket;

    /// <summary>Token bucket; false means the agent is flooding and must be disconnected.</summary>
    public bool TryConsume()
    {
        lock (_rateLock)
        {
            var now = Environment.TickCount64;
            _tokens = Math.Min(burst, _tokens + ((now - _lastRefill) / 1000.0 * ratePerSecond));
            _lastRefill = now;
            if (_tokens < 1)
            {
                return false;
            }
            _tokens -= 1;
            return true;
        }
    }

    public async Task<bool> SendAsync(string json, CancellationToken ct)
    {
        if (socket.State != WebSocketState.Open)
        {
            return false;
        }
        await _sendLock.WaitAsync(ct);
        try
        {
            await socket.SendAsync(Encoding.UTF8.GetBytes(json), WebSocketMessageType.Text, true, ct);
            return true;
        }
        catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException or InvalidOperationException)
        {
            return false;
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public Task<bool> SendPlainAsync(string type, object payload, CancellationToken ct) =>
        SendAsync(JsonSerializer.Serialize(new { type, id = Guid.NewGuid().ToString("D"), version = 1, payload }, Dranzo.Infrastructure.Security.AgentJson.Options), ct);

    public async Task CloseAsync(WebSocketCloseStatus status, string reason)
    {
        try
        {
            if (socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await socket.CloseOutputAsync(status, reason, cts.Token);
            }
        }
        catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException or OperationCanceledException or InvalidOperationException)
        {
        }
        socket.Abort();
    }

    public void Dispose() => _sendLock.Dispose();
}

/// <summary>In-process registry of connected agents (see docs/ARCHITECTURE.md section 9 for multi-instance notes).</summary>
public sealed class AgentRegistry
{
    private readonly ConcurrentDictionary<Guid, AgentConnection> _connections = new();

    /// <summary>Raised after a device completed <c>hello</c>; the dispatcher uses it to send queued work.</summary>
    public event Action<Guid>? DeviceReady;

    /// <summary>Raised when a device's connection is gone and was not replaced.</summary>
    public event Action<Guid>? DeviceGone;

    public int Count => _connections.Count;

    public AgentConnection Register(AgentConnection conn)
    {
        AgentConnection? old = null;
        _connections.AddOrUpdate(conn.DeviceId, conn, (_, existing) =>
        {
            old = existing;
            return conn;
        });
        if (old is not null)
        {
            _ = old.CloseAsync(WebSocketCloseStatus.PolicyViolation, "replaced by a newer connection");
        }
        return conn;
    }

    public void Unregister(AgentConnection conn)
    {
        if (_connections.TryRemove(new KeyValuePair<Guid, AgentConnection>(conn.DeviceId, conn)))
        {
            DeviceGone?.Invoke(conn.DeviceId);
        }
    }

    public void MarkReady(Guid deviceId) => DeviceReady?.Invoke(deviceId);

    public bool IsConnected(Guid deviceId) => _connections.TryGetValue(deviceId, out var c) && c.HelloReceived && c.Socket.State == WebSocketState.Open;

    public IReadOnlyCollection<Guid> ConnectedDeviceIds => [.. _connections.Where(kv => kv.Value.HelloReceived).Select(kv => kv.Key)];

    public async Task<bool> SendAsync(Guid deviceId, string json, CancellationToken ct) =>
        _connections.TryGetValue(deviceId, out var c) && c.HelloReceived && await c.SendAsync(json, ct);

    public void Disconnect(Guid deviceId, string reason)
    {
        if (_connections.TryGetValue(deviceId, out var c))
        {
            _ = c.CloseAsync(WebSocketCloseStatus.PolicyViolation, reason);
        }
    }
}

/// <summary>Handles one agent → server message type. Resolved from a fresh, system-scoped DI scope per message.</summary>
public interface IAgentMessageProcessor
{
    string Type { get; }

    Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct);
}
