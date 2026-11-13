using System.Text.Json;
using Dranzo.Api.Features;
using Dranzo.Api.Live;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Agents;

/// <summary>Defensive readers for agent-supplied JSON. Agents are authenticated but not trusted.</summary>
public static class J
{
    public static string Str(this JsonElement e, string name, int max = 256, string fallback = "")
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.String)
        {
            return fallback;
        }
        var s = v.GetString() ?? fallback;
        s = s.Replace("\0", "", StringComparison.Ordinal);
        return s.Length <= max ? s : s[..max];
    }

    public static string? StrOrNull(this JsonElement e, string name, int max = 256) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? e.Str(name, max) : null;

    public static bool Bool(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    public static bool? BoolOrNull(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False ? v.GetBoolean() : null;

    public static double? Num(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d) && double.IsFinite(d) ? d : null;

    public static long? Long(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var d) ? d : null;

    public static Guid? GuidOrNull(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && Guid.TryParse(v.GetString(), out var g) ? g : null;

    public static DateTimeOffset? Time(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.TryGetDateTimeOffset(out var d) ? d.ToUniversalTime() : null;

    public static JsonElement Obj(this JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Object ? v : default;

    public static IEnumerable<JsonElement> Arr(this JsonElement e, string name, int max = 10_000) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Take(max) : [];

    public static string[] StrArr(this JsonElement e, string name, int maxItems = 256, int maxLen = 256) =>
        [.. e.Arr(name, maxItems).Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").Select(s => s.Length <= maxLen ? s : s[..maxLen])];
}

public sealed class HelloProcessor(DranzoDbContext db, AgentRegistry registry, LiveNotifier live, AlertEngine alerts, IOptions<DranzoOptions> options, TimeProvider clock) : IAgentMessageProcessor
{
    public string Type => "hello";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var device = await db.Devices.FirstAsync(d => d.Id == conn.DeviceId, ct);
        var now = clock.GetUtcNow();
        device.AgentVersion = payload.Str("agentVersion", 32);
        device.Capabilities = payload.StrArr("capabilities", 64, 48);
        var hostname = payload.Str("hostname", 255);
        if (hostname.Length > 0)
        {
            device.Hostname = hostname;
        }
        device.IsOnline = true;
        device.LastSeenAt = now;
        device.LastIp = conn.RemoteIp;
        await db.SaveChangesAsync(ct);
        var a = options.Value.Agents;
        await conn.SendPlainAsync("hello.ack", new
        {
            serverTime = now,
            heartbeatSeconds = a.HeartbeatSeconds,
            inventoryIntervalSeconds = a.InventoryIntervalSeconds,
            softwareIntervalSeconds = a.SoftwareIntervalSeconds,
            postureIntervalSeconds = a.PostureIntervalSeconds,
            patchScanIntervalSeconds = a.PatchScanIntervalSeconds,
        }, ct);
        conn.HelloReceived = true;
        await live.DeviceChangedAsync(device);
        registry.MarkReady(device.Id);
        await alerts.EvaluateDeviceAsync(device.Id, ct); // closes "offline" alerts
    }
}

public sealed class HeartbeatProcessor(DranzoDbContext db, TimeProvider clock) : IAgentMessageProcessor
{
    public string Type => "heartbeat";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var cpu = Clamp(payload.Num("cpuPercent"));
        var mem = Clamp(payload.Num("memUsedPercent"));
        var user = payload.StrOrNull("consoleUser", 128);
        var reboot = payload.Bool("pendingReboot");
        var rss = payload.Long("agentRssBytes");
        await db.Devices.Where(d => d.Id == conn.DeviceId).ExecuteUpdateAsync(s => s
            .SetProperty(d => d.LastSeenAt, now).SetProperty(d => d.IsOnline, true)
            .SetProperty(d => d.CpuPercent, cpu).SetProperty(d => d.MemUsedPercent, mem)
            .SetProperty(d => d.ConsoleUser, user).SetProperty(d => d.PendingReboot, reboot).SetProperty(d => d.AgentRssBytes, rss), ct);
        await conn.SendPlainAsync("heartbeat.ack", new { serverTime = now }, ct);
    }

    private static double? Clamp(double? v) => v is null ? null : Math.Clamp(v.Value, 0, 100);
}

public sealed class InventoryProcessor(DranzoDbContext db, LiveNotifier live, AlertEngine alerts, TimeProvider clock) : IAgentMessageProcessor
{
    private const int KeepSnapshots = 10;

    public string Type => "inventory";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        if (payload.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException("inventory payload must be an object");
        }
        var device = await db.Devices.FirstAsync(d => d.Id == conn.DeviceId, ct);
        var os = payload.Obj("os");
        device.OsName = os.Str("name", 128);
        device.OsVersion = string.Join(' ', new[] { os.Str("version", 64), os.Str("build", 64) }.Where(s => s.Length > 0));
        device.Serial = payload.Str("serial", 128);
        device.Manufacturer = payload.Str("manufacturer", 128);
        device.Model = payload.Str("model", 128);
        device.ConsoleUser = payload.StrOrNull("consoleUser", 128);
        device.PendingReboot = payload.Bool("pendingReboot");
        var hostname = payload.Str("hostname", 255);
        if (hostname.Length > 0)
        {
            device.Hostname = hostname;
        }

        device.MacAddresses = [.. payload.Arr("network", 32).Select(n => Features.NetworkRules.NormalizeMac(n.Str("mac", 32))).OfType<string>().Distinct().Take(16)];
        device.DefaultGateway = Features.NetworkRules.Ipv4OrNull(payload.Str("defaultGateway", 15));
        var wifi = payload.Obj("wifi");
        device.WifiSsid = wifi.ValueKind == JsonValueKind.Object ? wifi.Str("ssid", 64) : null;

        await db.InventorySnapshots.Where(i => i.DeviceId == device.Id && i.IsLatest).ExecuteUpdateAsync(s => s.SetProperty(i => i.IsLatest, false), ct);
        db.InventorySnapshots.Add(new InventorySnapshot
        {
            Id = Guid.NewGuid(), PartnerId = device.PartnerId, OrganizationId = device.OrganizationId, DeviceId = device.Id,
            CollectedAt = clock.GetUtcNow(), IsLatest = true, DataJson = payload.GetRawText(),
        });
        await db.SaveChangesAsync(ct);

        var stale = await db.InventorySnapshots.Where(i => i.DeviceId == device.Id).OrderByDescending(i => i.CollectedAt).Skip(KeepSnapshots).Select(i => i.Id).ToListAsync(ct);
        if (stale.Count > 0)
        {
            await db.InventorySnapshots.Where(i => stale.Contains(i.Id)).ExecuteDeleteAsync(ct);
        }
        await live.DeviceChangedAsync(device);
        await alerts.EvaluateDeviceAsync(device.Id, ct); // disk usage
    }
}

/// <summary>
/// Agent-reported protocol errors. A refused command with a signature/identity problem means something between the
/// signing key and the agent is wrong (tampering, misrouting, a replaced trust store), so it raises a tamper alert.
/// </summary>
public sealed class AgentErrorProcessor(DranzoDbContext db, AlertEngine alerts, Dranzo.Infrastructure.Audit.IAuditLog audit, ILogger<AgentErrorProcessor> log) : IAgentMessageProcessor
{
    private static readonly HashSet<string> TamperCodes = ["bad_signature", "unknown_key", "wrong_device", "replayed", "unsigned"];

    public string Type => "error";

    public async Task HandleAsync(AgentConnection conn, JsonElement payload, CancellationToken ct)
    {
        var code = payload.Str("code", 64);
        log.LogWarning("Agent {DeviceId} reported error {Code}: {Message} (ref {RefId})", conn.DeviceId, code, payload.Str("message", 512), payload.Str("refId", 64));
        if (!TamperCodes.Contains(code))
        {
            return;
        }
        var device = await db.Devices.FirstAsync(d => d.Id == conn.DeviceId, ct);
        await audit.WriteAsync(device.PartnerId, new Dranzo.Infrastructure.Audit.AuditEntry("agent.command_refused", "failure", device.OrganizationId, device.Id, "device", device.Id.ToString(),
            new { code, refId = payload.Str("refId", 64) }, ActorType: "agent", ActorId: device.Id, ActorName: device.Hostname, Ip: conn.RemoteIp), ct);
        await alerts.RaiseAsync(device, AlertTypes.AgentTamper, "refused:" + code, $"Agent on {device.Hostname} refused a command ({code})",
            "The agent rejected a server command during signature verification. Check for tampering, a wrong trust store, or clock problems.", ct);
    }
}
