using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dranzo.Api.Services;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using MimeKit;

namespace Dranzo.Api.Notifications;

public sealed class NotificationOptions
{
    /// <summary>Development/test only: allow webhook targets on loopback/private addresses and plain http.</summary>
    public bool AllowPrivateTargets { get; set; }
}

public sealed record ChannelConfig(string[]? To = null, string? Url = null, string? Secret = null);

/// <summary>
/// Outbound HTTP for technician-configured URLs. Blocks server-side request forgery: https only, and the
/// connection is made only to a public IP address that was validated at connect time (no DNS rebinding window).
/// </summary>
public static class SafeOutbound
{
    public static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Broadcast))
        {
            return false;
        }
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return !(b[0] == 10 || b[0] == 127 || b[0] == 0 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] is >= 64 and <= 127) || b[0] >= 224 || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                || (b[0] == 198 && b[1] is 18 or 19) || (b[0] == 192 && b[1] == 88 && b[2] == 99)
                || (b[0] == 168 && b[1] == 63 && b[2] == 129 && b[3] == 16)); // Azure platform endpoint (wireserver)
        }
        if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.IsIPv6UniqueLocal)
        {
            return false;
        }
        // Translation/tunnel prefixes that can embed private IPv4 addresses: NAT64, 6to4, Teredo, documentation.
        var v6 = ip.GetAddressBytes();
        if (v6.Length == 16 && ((v6[0] == 0x00 && v6[1] == 0x64 && v6[2] == 0xff && v6[3] == 0x9b) || (v6[0] == 0x20 && v6[1] == 0x02)
            || (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x00 && v6[3] == 0x00) || (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8)))
        {
            return false;
        }
        return true;
    }

    public static string? ValidateUrl(string? url, bool allowPrivate)
    {
        if (string.IsNullOrWhiteSpace(url) || url.Length > 2048 || !Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return "A valid URL is required.";
        }
        if (uri.Scheme != Uri.UriSchemeHttps && !(allowPrivate && uri.Scheme == Uri.UriSchemeHttp))
        {
            return "The URL must use https.";
        }
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            return "Credentials in the URL are not allowed.";
        }
        if (!allowPrivate && IPAddress.TryParse(uri.Host.Trim('[', ']'), out var literal) && !IsPublic(literal))
        {
            return "The URL must point to a public address.";
        }
        return null;
    }

    public static HttpClient CreateClient(bool allowPrivate)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            ConnectTimeout = TimeSpan.FromSeconds(10),
            ConnectCallback = async (context, ct) =>
            {
                var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, ct);
                var allowed = allowPrivate ? addresses : [.. addresses.Where(IsPublic)];
                if (allowed.Length == 0)
                {
                    throw new HttpRequestException("Destination resolves to a non-public address; request blocked.");
                }
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(allowed, context.DnsEndPoint.Port, ct);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
    }
}

/// <summary>Queues and delivers notifications (alerts and event webhooks) with retries.</summary>
public sealed class NotificationService(DranzoDbContext db, Dranzo.Infrastructure.Security.SecretProtector secrets, TimeProvider clock)
{
    private const string Purpose = "notification-channel";

    public string Protect(ChannelConfig config) => secrets.Protect(Purpose, JsonSerializer.Serialize(config, JsonSerializerOptions.Web));

    public ChannelConfig Unprotect(string value) =>
        secrets.Unprotect(Purpose, value) is { } json ? JsonSerializer.Deserialize<ChannelConfig>(json, JsonSerializerOptions.Web) ?? new ChannelConfig() : new ChannelConfig();

    /// <summary>Adds one outbox row per channel. Delivery happens in <see cref="NotificationSender"/>.</summary>
    public void Enqueue(Guid partnerId, IEnumerable<Guid> channelIds, string eventType, object payload)
    {
        var now = clock.GetUtcNow();
        var json = JsonSerializer.Serialize(payload, JsonSerializerOptions.Web);
        foreach (var id in channelIds.Distinct())
        {
            db.WebhookDeliveries.Add(new WebhookDelivery { Id = Guid.NewGuid(), PartnerId = partnerId, ChannelId = id, EventType = eventType, PayloadJson = json, CreatedAt = now, NextAttemptAt = now });
        }
    }

    /// <summary>Fans an event out to every enabled webhook channel of the partner that subscribed to it.</summary>
    public async Task PublishEventAsync(Guid partnerId, Guid? organizationId, string eventType, object data, CancellationToken ct)
    {
        var channels = await db.NotificationChannels.IgnoreQueryFilters()
            .Where(c => c.PartnerId == partnerId && c.Enabled && c.Type == "webhook" && c.EventTypes.Contains(eventType) && (c.OrganizationId == null || c.OrganizationId == organizationId))
            .Select(c => c.Id).ToListAsync(ct);
        if (channels.Count > 0)
        {
            Enqueue(partnerId, channels, eventType, new { type = eventType, occurredAt = clock.GetUtcNow(), organizationId, data });
            await db.SaveChangesAsync(ct);
        }
    }
}

public sealed class NotificationSender(IServiceScopeFactory scopes, ILogger<NotificationSender> log) : PeriodicService(scopes, log, TimeSpan.FromSeconds(10))
{
    private static readonly TimeSpan[] Backoff = [TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(30), TimeSpan.FromHours(2), TimeSpan.FromHours(6)];

    protected override Task TickAsync(IServiceProvider sp, CancellationToken ct) => ProcessAsync(sp, ct);

    public static async Task<int> ProcessAsync(IServiceProvider sp, CancellationToken ct)
    {
        var db = sp.GetRequiredService<DranzoDbContext>();
        var notifications = sp.GetRequiredService<NotificationService>();
        var options = sp.GetRequiredService<IOptions<DranzoOptions>>().Value;
        var allowPrivate = sp.GetRequiredService<IOptions<NotificationOptions>>().Value.AllowPrivateTargets;
        var log = sp.GetRequiredService<ILogger<NotificationSender>>();
        var now = sp.GetRequiredService<TimeProvider>().GetUtcNow();
        var due = await db.WebhookDeliveries.Where(d => d.DeliveredAt == null && d.NextAttemptAt <= now && d.Attempts <= Backoff.Length).OrderBy(d => d.CreatedAt).Take(50).ToListAsync(ct);
        var sent = 0;
        using var http = SafeOutbound.CreateClient(allowPrivate);
        foreach (var d in due)
        {
            var channel = await db.NotificationChannels.FirstOrDefaultAsync(c => c.Id == d.ChannelId && c.PartnerId == d.PartnerId, ct);
            if (channel is null || !channel.Enabled)
            {
                d.DeliveredAt = now;
                d.LastError = "Channel removed or disabled.";
                continue;
            }
            try
            {
                await DeliverAsync(channel, notifications.Unprotect(channel.ConfigProtected), d, http, options, allowPrivate, ct);
                d.DeliveredAt = now;
                d.LastError = null;
                sent++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                d.Attempts++;
                d.LastError = ex.Message.Length > 500 ? ex.Message[..500] : ex.Message;
                d.NextAttemptAt = d.Attempts <= Backoff.Length ? now + Backoff[d.Attempts - 1] : now.AddYears(10);
                log.LogWarning("Notification via channel {Channel} failed (attempt {Attempt}): {Error}", channel.Name, d.Attempts, d.LastError);
            }
        }
        await db.SaveChangesAsync(ct);
        await db.WebhookDeliveries.Where(x => x.DeliveredAt != null && x.DeliveredAt < now.AddDays(-14)).ExecuteDeleteAsync(ct);
        return sent;
    }

    public static (string Title, string Text) Describe(WebhookDelivery d)
    {
        using var doc = JsonDocument.Parse(d.PayloadJson);
        var root = doc.RootElement;
        var title = root.TryGetProperty("title", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString()! : d.EventType;
        var text = root.TryGetProperty("text", out var x) && x.ValueKind == JsonValueKind.String ? x.GetString()! : d.PayloadJson;
        return (title, text);
    }

    private static async Task DeliverAsync(NotificationChannel channel, ChannelConfig config, WebhookDelivery d, HttpClient http, DranzoOptions options, bool allowPrivate, CancellationToken ct)
    {
        var (title, text) = Describe(d);
        switch (channel.Type)
        {
            case "email":
                if (string.IsNullOrEmpty(options.Smtp.Host))
                {
                    throw new InvalidOperationException("SMTP is not configured (Dranzo:Smtp:Host).");
                }
                var message = new MimeMessage();
                message.From.Add(MailboxAddress.Parse(options.Smtp.From));
                foreach (var to in config.To ?? [])
                {
                    message.To.Add(MailboxAddress.Parse(to));
                }
                message.Subject = "[DranzoRMM] " + title;
                message.Body = new TextPart("plain") { Text = text };
                using (var smtp = new SmtpClient())
                {
                    await smtp.ConnectAsync(options.Smtp.Host, options.Smtp.Port, options.Smtp.UseStartTls ? SecureSocketOptions.StartTls : SecureSocketOptions.Auto, ct);
                    if (!string.IsNullOrEmpty(options.Smtp.Username))
                    {
                        await smtp.AuthenticateAsync(options.Smtp.Username, options.Smtp.Password ?? "", ct);
                    }
                    await smtp.SendAsync(new MailKit.SendRequest(message), ct);
                    await smtp.DisconnectAsync(true, ct);
                }
                return;
            case "slack":
                await PostAsync(http, config.Url, JsonSerializer.Serialize(new { text = $"*{title}*\n{text}" }), null, d, allowPrivate, ct);
                return;
            case "teams":
                var card = new
                {
                    type = "message",
                    attachments = new[]
                    {
                        new
                        {
                            contentType = "application/vnd.microsoft.card.adaptive",
                            content = new
                            {
                                type = "AdaptiveCard", version = "1.4",
                                body = new object[] { new { type = "TextBlock", weight = "Bolder", size = "Medium", text = title, wrap = true }, new { type = "TextBlock", text, wrap = true } },
                            },
                        },
                    },
                };
                await PostAsync(http, config.Url, JsonSerializer.Serialize(card), null, d, allowPrivate, ct);
                return;
            case "webhook":
                await PostAsync(http, config.Url, d.PayloadJson, config.Secret, d, allowPrivate, ct);
                return;
            default:
                throw new InvalidOperationException($"Unknown channel type '{channel.Type}'.");
        }
    }

    private static async Task PostAsync(HttpClient http, string? url, string body, string? secret, WebhookDelivery d, bool allowPrivate, CancellationToken ct)
    {
        if (SafeOutbound.ValidateUrl(url, allowPrivate) is { } problem)
        {
            throw new InvalidOperationException(problem);
        }
        using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        request.Headers.Add("X-Dranzo-Event", d.EventType);
        request.Headers.Add("X-Dranzo-Delivery", d.Id.ToString());
        if (!string.IsNullOrEmpty(secret))
        {
            // Receivers verify: hex(HMAC-SHA256(secret, "{timestamp}.{body}")).
            var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(ts + "." + body));
            request.Headers.Add("X-Dranzo-Timestamp", ts);
            request.Headers.Add("X-Dranzo-Signature", "sha256=" + Convert.ToHexStringLower(mac));
        }
        using var response = await http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"Receiver answered {(int)response.StatusCode}.");
        }
    }
}
