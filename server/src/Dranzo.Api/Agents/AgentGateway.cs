using System.Buffers;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text.Json;
using Dranzo.Api.Auth;
using Dranzo.Api.Live;
using Dranzo.Domain;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Agents;

/// <summary>Agent listener endpoints: enroll, renew, WebSocket (docs/PROTOCOL.md).</summary>
public static class AgentGateway
{
    public const string SubProtocol = "dranzo.agent.v1";
    private static readonly string[] OsValues = ["windows", "macos", "linux"];
    private static readonly string[] ArchValues = ["amd64", "arm64"];

    public sealed record EnrollRequest(string? Token, string? Csr, string? Hostname, string? Os, string? Arch, string? AgentVersion, string? MachineId);

    public sealed record RenewRequest(string? Csr);

    public static void Map(WebApplication app)
    {
        var g = app.MapGroup("/agent/v1").AgentListener();

        g.MapPost("/enroll", EnrollAsync).RequireRateLimiting("enroll");
        g.MapPost("/renew", RenewAsync).RequireRateLimiting("enroll");
        g.Map("/ws", WebSocketAsync);
    }

    private static async Task<IResult> EnrollAsync(EnrollRequest req, HttpContext http, DranzoDbContext db, TenantContext tenant,
        CertificateAuthority ca, IAuditLog audit, IOptions<DranzoOptions> options, LiveNotifier live, Dranzo.Api.Notifications.NotificationService notifications, TimeProvider clock, ILoggerFactory lf, CancellationToken ct)
    {
        tenant.SetSystem();
        var log = lf.CreateLogger("AgentGateway");
        var hostname = Api.CleanName(req.Hostname, 255);
        if (string.IsNullOrEmpty(req.Token) || req.Token.Length > 128 || string.IsNullOrEmpty(req.Csr) || hostname is null
            || !OsValues.Contains(req.Os) || !ArchValues.Contains(req.Arch) || (req.AgentVersion?.Length ?? 0) > 32 || (req.MachineId?.Length ?? 0) > 128)
        {
            return Api.BadRequest("Malformed enrollment request.");
        }
        var now = clock.GetUtcNow();
        var hash = Hashing.Sha256Hex(req.Token);
        var token = await db.EnrollmentTokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == hash, ct);
        var ip = http.Connection.RemoteIpAddress?.ToString();
        if (token is null || token.RevokedAt is not null || token.ExpiresAt <= now || token.Uses >= token.MaxUses)
        {
            if (token is not null)
            {
                await audit.WriteAsync(token.PartnerId, new AuditEntry("device.enroll", "denied", token.OrganizationId, TargetType: "enrollment_token", TargetId: token.Id.ToString(),
                    Detail: new { hostname, reason = "token_not_usable" }, ActorType: "agent", ActorName: hostname, Ip: ip), ct);
            }
            return Api.Error(401, "invalid_token", "Enrollment token is not valid.");
        }

        var deviceId = Guid.NewGuid();
        IssuedCertificate cert;
        try
        {
            cert = ca.IssueDeviceCertificate(req.Csr, deviceId, TimeSpan.FromDays(options.Value.Agents.CertValidityDays));
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            log.LogWarning("Rejected enrollment CSR from {Ip}: {Error}", ip, ex.Message);
            return Api.BadRequest("Invalid certificate signing request.");
        }

        // Consume one use atomically; concurrent enrollments cannot exceed MaxUses.
        var consumed = await db.EnrollmentTokens.Where(t => t.Id == token.Id && t.Uses < t.MaxUses && t.RevokedAt == null && t.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.Uses, t => t.Uses + 1), ct);
        if (consumed != 1)
        {
            return Api.Error(401, "invalid_token", "Enrollment token is not valid.");
        }

        var machineId = req.MachineId ?? "";
        Guid? duplicateOf = machineId.Length == 0 ? null : await db.Devices
            .Where(d => d.OrganizationId == token.OrganizationId && d.MachineId == machineId && d.Status == DeviceStatus.Active)
            .OrderByDescending(d => d.EnrolledAt).Select(d => (Guid?)d.Id).FirstOrDefaultAsync(ct);

        var device = new Device
        {
            Id = deviceId, PartnerId = token.PartnerId, OrganizationId = token.OrganizationId, SiteId = token.SiteId, GroupId = token.GroupId,
            Hostname = hostname, Os = req.Os!, Arch = req.Arch!, AgentVersion = req.AgentVersion ?? "", MachineId = machineId,
            EnrolledAt = now, CertThumbprint = cert.Thumbprint, CertNotAfter = cert.NotAfter, PossibleDuplicateOfDeviceId = duplicateOf, LastIp = ip,
        };
        db.Devices.Add(device);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(token.PartnerId, new AuditEntry("device.enroll", OrganizationId: token.OrganizationId, DeviceId: deviceId, TargetType: "device", TargetId: deviceId.ToString(),
            Detail: new { hostname, os = req.Os, arch = req.Arch, tokenId = token.Id, possibleDuplicateOf = duplicateOf }, ActorType: "agent", ActorId: deviceId, ActorName: hostname, Ip: ip), ct);
        await live.DeviceChangedAsync(device);
        await notifications.PublishEventAsync(device.PartnerId, device.OrganizationId, "device.enrolled", new { deviceId, hostname, os = req.Os, arch = req.Arch }, ct);
        return Results.Ok(new { deviceId = deviceId.ToString("D"), certificate = cert.CertificatePem, caCertificates = ca.CaCertificatePem, notAfter = cert.NotAfter });
    }

    private static async Task<IResult> RenewAsync(RenewRequest req, HttpContext http, DranzoDbContext db, TenantContext tenant,
        CertificateAuthority ca, IAuditLog audit, IOptions<DranzoOptions> options, TimeProvider clock, CancellationToken ct)
    {
        tenant.SetSystem();
        var device = await AuthenticateDeviceAsync(http, db, clock, tracking: true, ct);
        if (device is null)
        {
            return Api.Error(403, "forbidden", "Unknown or revoked device certificate.");
        }
        if (string.IsNullOrEmpty(req.Csr))
        {
            return Api.BadRequest("csr is required.");
        }
        IssuedCertificate cert;
        try
        {
            cert = ca.IssueDeviceCertificate(req.Csr, device.Id, TimeSpan.FromDays(options.Value.Agents.CertValidityDays));
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            return Api.BadRequest("Invalid certificate signing request.");
        }
        var presented = CertificateAuthority.Thumbprint(http.Connection.ClientCertificate!);
        if (presented == device.CertThumbprint)
        {
            device.PrevCertThumbprint = device.CertThumbprint;
            device.PrevCertNotAfter = device.CertNotAfter;
        }
        device.CertThumbprint = cert.Thumbprint;
        device.CertNotAfter = cert.NotAfter;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(device.PartnerId, new AuditEntry("device.cert_renew", OrganizationId: device.OrganizationId, DeviceId: device.Id, TargetType: "device", TargetId: device.Id.ToString(),
            Detail: new { notAfter = cert.NotAfter }, ActorType: "agent", ActorId: device.Id, ActorName: device.Hostname, Ip: http.Connection.RemoteIpAddress?.ToString()), ct);
        return Results.Ok(new { deviceId = device.Id.ToString("D"), certificate = cert.CertificatePem, caCertificates = ca.CaCertificatePem, notAfter = cert.NotAfter });
    }

    /// <summary>
    /// Maps the TLS client certificate to an active device. The certificate chain was already validated against the
    /// private CA during the handshake; this is the revocation check (thumbprint must be the device's current or
    /// still-valid previous certificate).
    /// </summary>
    public static async Task<Device?> AuthenticateDeviceAsync(HttpContext http, DranzoDbContext db, TimeProvider clock, bool tracking, CancellationToken ct)
    {
        var cert = http.Connection.ClientCertificate;
        if (cert is null)
        {
            return null;
        }
        var now = clock.GetUtcNow();
        if (cert.NotAfter.ToUniversalTime() <= now.UtcDateTime || cert.NotBefore.ToUniversalTime() > now.UtcDateTime.AddMinutes(5))
        {
            return null;
        }
        var tp = CertificateAuthority.Thumbprint(cert);
        var q = tracking ? db.Devices : db.Devices.AsNoTracking();
        return await q.FirstOrDefaultAsync(d => d.Status == DeviceStatus.Active
            && (d.CertThumbprint == tp || (d.PrevCertThumbprint == tp && d.PrevCertNotAfter > now)), ct);
    }

    private static async Task WebSocketAsync(HttpContext http, DranzoDbContext db, TenantContext tenant, AgentRegistry registry, IServiceScopeFactory scopes,
        IOptions<DranzoOptions> options, TimeProvider clock, ILoggerFactory lf)
    {
        tenant.SetSystem();
        var log = lf.CreateLogger("AgentGateway");
        var ct = http.RequestAborted;
        var device = await AuthenticateDeviceAsync(http, db, clock, tracking: true, ct);
        if (device is null)
        {
            http.Response.StatusCode = 403;
            return;
        }
        if (!http.WebSockets.IsWebSocketRequest)
        {
            http.Response.StatusCode = 400;
            return;
        }
        // First connection with the renewed certificate retires the previous one.
        if (device.PrevCertThumbprint is not null && CertificateAuthority.Thumbprint(http.Connection.ClientCertificate!) == device.CertThumbprint)
        {
            device.PrevCertThumbprint = null;
            device.PrevCertNotAfter = null;
            await db.SaveChangesAsync(ct);
        }

        var opt = options.Value.Agents;
        using var socket = await http.WebSockets.AcceptWebSocketAsync(new WebSocketAcceptContext { SubProtocol = SubProtocol, KeepAliveInterval = TimeSpan.FromSeconds(30) });
        using var conn = new AgentConnection(device.Id, device.PartnerId, device.OrganizationId, socket, opt.MessagesPerSecond, opt.MessageBurst) { RemoteIp = http.Connection.RemoteIpAddress?.ToString() };
        registry.Register(conn);
        using var logScope = log.BeginScope(new Dictionary<string, object> { ["device_id"] = device.Id });
        log.LogInformation("Agent connected");
        try
        {
            await ReceiveLoopAsync(conn, scopes, opt, log, ct);
        }
        catch (OperationCanceledException)
        {
        }
        catch (WebSocketException ex)
        {
            log.LogInformation("Agent socket error: {Error}", ex.Message);
        }
        finally
        {
            registry.Unregister(conn);
            log.LogInformation("Agent disconnected");
        }
    }

    private static async Task ReceiveLoopAsync(AgentConnection conn, IServiceScopeFactory scopes, AgentOptions opt, ILogger log, CancellationToken ct)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            while (conn.Socket.State == WebSocketState.Open)
            {
                using var message = new MemoryStream();
                ValueWebSocketReceiveResult result;
                do
                {
                    result = await conn.Socket.ReceiveAsync(buffer.AsMemory(), ct);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await conn.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye");
                        return;
                    }
                    if (result.MessageType != WebSocketMessageType.Text)
                    {
                        await conn.CloseAsync(WebSocketCloseStatus.InvalidMessageType, "text frames only");
                        return;
                    }
                    if (message.Length + result.Count > opt.MaxMessageBytes)
                    {
                        await conn.CloseAsync(WebSocketCloseStatus.MessageTooBig, "message too large");
                        return;
                    }
                    message.Write(buffer, 0, result.Count);
                }
                while (!result.EndOfMessage);

                if (!conn.TryConsume())
                {
                    log.LogWarning("Agent exceeded message rate; closing");
                    await conn.CloseAsync(WebSocketCloseStatus.PolicyViolation, "rate limit");
                    return;
                }
                await HandleMessageAsync(conn, message.GetBuffer().AsMemory(0, (int)message.Length), scopes, log, ct);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task HandleMessageAsync(AgentConnection conn, ReadOnlyMemory<byte> raw, IServiceScopeFactory scopes, ILogger log, CancellationToken ct)
    {
        string type;
        string? id;
        JsonElement payload;
        try
        {
            using var doc = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 32 });
            var root = doc.RootElement;
            type = root.GetProperty("type").GetString() ?? "";
            id = root.TryGetProperty("id", out var idEl) ? idEl.GetString() : null;
            var version = root.GetProperty("version").GetInt32();
            if (version != 1)
            {
                await conn.SendPlainAsync("error", new { code = "unsupported_version", message = "Protocol version 1 required.", refId = id }, ct);
                await conn.CloseAsync(WebSocketCloseStatus.ProtocolError, "unsupported version");
                return;
            }
            payload = root.TryGetProperty("payload", out var p) ? p.Clone() : default;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            await conn.SendPlainAsync("error", new { code = "malformed", message = "Malformed envelope." }, ct);
            return;
        }
        if (!conn.HelloReceived && type != "hello")
        {
            await conn.CloseAsync(WebSocketCloseStatus.PolicyViolation, "hello required");
            return;
        }

        await using var scope = scopes.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
        var processor = scope.ServiceProvider.GetServices<IAgentMessageProcessor>().FirstOrDefault(p => p.Type == type);
        if (processor is null)
        {
            await conn.SendPlainAsync("error", new { code = "unknown_type", message = $"Unknown message type '{(type.Length > 64 ? type[..64] : type)}'.", refId = id }, ct);
            return;
        }
        try
        {
            await processor.HandleAsync(conn, payload, ct);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or ArgumentException)
        {
            log.LogWarning("Rejected {Type} from agent: {Error}", type, ex.Message);
            await conn.SendPlainAsync("error", new { code = "malformed", message = "Invalid payload.", refId = id }, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A server-side failure must not take the agent connection down.
            log.LogError(ex, "Failed to process {Type} from agent", type);
        }
    }
}
