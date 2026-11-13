using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using Dranzo.Domain;
using Dranzo.Infrastructure.Security;

namespace Dranzo.Api.Features;

/// <summary>Builds the HTTP handler for one controller. Replaced in tests by an in-memory fake.</summary>
public interface IUniFiTransport
{
    HttpMessageHandler CreateHandler(NetworkController controller);
}

/// <summary>
/// The only outbound connection to a private network the server makes (THREAT_MODEL "network controllers"): https
/// only, no redirects, no proxy, connects only to the configured host and port, never to loopback, link-local or
/// cloud metadata addresses; optional certificate pinning for the self-signed certificates consoles ship with.
/// </summary>
public sealed class UniFiTransport : IUniFiTransport
{
    public HttpMessageHandler CreateHandler(NetworkController controller)
    {
        var uri = new Uri(controller.BaseUrl);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = true,
            CookieContainer = new CookieContainer(),
            ConnectTimeout = TimeSpan.FromSeconds(10),
            ConnectCallback = async (ctx, ct) =>
            {
                if (!string.Equals(ctx.DnsEndPoint.Host, uri.Host, StringComparison.OrdinalIgnoreCase) || ctx.DnsEndPoint.Port != uri.Port)
                {
                    throw new HttpRequestException("Connections go only to the configured controller.");
                }
                var addresses = await Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, ct);
                var allowed = addresses.Where(UniFiRules.AllowedTarget).ToArray();
                if (allowed.Length == 0)
                {
                    throw new HttpRequestException("The controller address is not allowed (loopback, link-local or metadata).");
                }
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await socket.ConnectAsync(allowed, ctx.DnsEndPoint.Port, ct);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            },
        };
        if (!string.IsNullOrWhiteSpace(controller.CertificateSha256))
        {
            var pin = Convert.FromHexString(controller.CertificateSha256);
            handler.SslOptions.RemoteCertificateValidationCallback = (_, cert, _, errors) => MeshCentral.PinAccepts(pin, cert, errors);
        }
        return handler;
    }
}

public static class UniFiRules
{
    /// <summary>Loopback, link-local (incl. cloud metadata 169.254.169.254), unspecified and multicast are never contacted.</summary>
    public static bool AllowedTarget(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6)
        {
            a = a.MapToIPv4();
        }
        if (IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any) || a.IsIPv6LinkLocal || a.IsIPv6Multicast)
        {
            return false;
        }
        var b = a.GetAddressBytes();
        return a.AddressFamily != AddressFamily.InterNetwork || !(b[0] == 169 && b[1] == 254) && b[0] < 224 && b[0] != 0;
    }

    /// <summary>Normalized "https://host[:port]" or null.</summary>
    public static string? NormalizeBaseUrl(string? url)
    {
        if (!Uri.TryCreate(url?.Trim(), UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(u.UserInfo)
            || (u.AbsolutePath != "/" && u.AbsolutePath.Length > 0) || !string.IsNullOrEmpty(u.Query) || !string.IsNullOrEmpty(u.Fragment)
            || u.IsLoopback || u.Host.Length > 253)
        {
            return null;
        }
        if (IPAddress.TryParse(u.Host.Trim('[', ']'), out var ip) && !AllowedTarget(ip))
        {
            return null;
        }
        return u.IsDefaultPort ? $"https://{u.Host}" : $"https://{u.Host}:{u.Port}";
    }
}

public sealed class UniFiException(string message) : Exception(message);

/// <summary>Minimal UniFi Network client (classic "/api/s/{site}" endpoints). Not verified against real hardware yet.</summary>
public sealed class UniFiClient : IDisposable
{
    private const int MaxResponseBytes = 8 * 1024 * 1024;
    private readonly HttpClient _http;
    private readonly NetworkController _c;
    private readonly string _secret;
    private bool _loggedIn;

    public UniFiClient(IUniFiTransport transport, NetworkController controller, string secret)
    {
        _c = controller;
        _secret = secret;
        _http = new HttpClient(transport.CreateHandler(controller), disposeHandler: true)
        {
            BaseAddress = new Uri(controller.BaseUrl.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(30),
            MaxResponseContentBufferSize = MaxResponseBytes,
        };
        _http.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        if (controller.AuthMode == "apikey")
        {
            _http.DefaultRequestHeaders.Add("X-API-KEY", secret);
            _loggedIn = true;
        }
    }

    private string Site => Uri.EscapeDataString(_c.UnifiSite);
    private string Api(string path) => (_c.UnifiOs ? "proxy/network/api/s/" : "api/s/") + Site + "/" + path;

    private async Task LoginAsync(CancellationToken ct)
    {
        if (_loggedIn)
        {
            return;
        }
        using var res = await _http.PostAsJsonAsync(_c.UnifiOs ? "api/auth/login" : "api/login", new { username = _c.Username, password = _secret, remember = false }, ct);
        if (!res.IsSuccessStatusCode)
        {
            throw new UniFiException(res.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden ? "The controller refused the user name or password." : $"Login failed: HTTP {(int)res.StatusCode}.");
        }
        if (res.Headers.TryGetValues("X-CSRF-Token", out var csrf))
        {
            _http.DefaultRequestHeaders.Remove("X-CSRF-Token");
            _http.DefaultRequestHeaders.Add("X-CSRF-Token", csrf.First());
        }
        _loggedIn = true;
    }

    private async Task<JsonElement[]> SendAsync(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        await LoginAsync(ct);
        using var req = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            req.Content = JsonContent.Create(body);
        }
        using var res = await _http.SendAsync(req, ct);
        if (res.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            throw new UniFiException("The controller refused the credentials (check the API key or account, and that it may administer this site).");
        }
        if ((int)res.StatusCode is >= 300 and < 400)
        {
            throw new UniFiException("The controller redirected the request; check the address and the UniFi OS setting.");
        }
        var doc = await JsonSerializer.DeserializeAsync<JsonElement>(await res.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var rc = doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty("meta", out var meta) && meta.TryGetProperty("rc", out var r) ? r.GetString() : null;
        if (!res.IsSuccessStatusCode || rc != "ok")
        {
            var msg = doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty("meta", out var m) && m.TryGetProperty("msg", out var mm) ? mm.GetString() : null;
            throw new UniFiException($"The controller answered {(int)res.StatusCode}{(msg is null ? "" : ": " + Trim(msg))}.");
        }
        return doc.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array ? [.. data.EnumerateArray().Take(20_000)] : [];
    }

    private static string Trim(string s) => s.Length > 200 ? s[..200] : s;

    public Task<JsonElement[]> DevicesAsync(CancellationToken ct) => SendAsync(HttpMethod.Get, Api("stat/device"), null, ct);
    public Task<JsonElement[]> ClientsAsync(CancellationToken ct) => SendAsync(HttpMethod.Get, Api("stat/sta"), null, ct);
    public Task<JsonElement[]> WlansAsync(CancellationToken ct) => SendAsync(HttpMethod.Get, Api("rest/wlanconf"), null, ct);
    public Task<JsonElement[]> NetworksAsync(CancellationToken ct) => SendAsync(HttpMethod.Get, Api("rest/networkconf"), null, ct);
    public Task<JsonElement[]> UserGroupsAsync(CancellationToken ct) => SendAsync(HttpMethod.Get, Api("rest/usergroup"), null, ct);
    public Task<JsonElement[]> RadiusProfilesAsync(CancellationToken ct) => SendAsync(HttpMethod.Get, Api("rest/radiusprofile"), null, ct);
    public Task<JsonElement[]> CreateNetworkAsync(object body, CancellationToken ct) => SendAsync(HttpMethod.Post, Api("rest/networkconf"), body, ct);
    public Task<JsonElement[]> CreateWlanAsync(object body, CancellationToken ct) => SendAsync(HttpMethod.Post, Api("rest/wlanconf"), body, ct);
    public Task<JsonElement[]> UpdateWlanAsync(string id, object body, CancellationToken ct) => SendAsync(HttpMethod.Put, Api("rest/wlanconf/" + Uri.EscapeDataString(id)), body, ct);
    public Task<JsonElement[]> CreateRadiusProfileAsync(object body, CancellationToken ct) => SendAsync(HttpMethod.Post, Api("rest/radiusprofile"), body, ct);
    public Task BlockClientAsync(string mac, bool block, CancellationToken ct) => SendAsync(HttpMethod.Post, Api("cmd/stamgr"), new { cmd = block ? "block-sta" : "unblock-sta", mac }, ct);
    public Task RestartDeviceAsync(string mac, CancellationToken ct) => SendAsync(HttpMethod.Post, Api("cmd/devmgr"), new { cmd = "restart", mac }, ct);

    /// <summary>
    /// Wireless networks need the access point groups on UniFi Network 7.x+ (v2 API); an empty list on older versions.
    /// </summary>
    public async Task<string[]> ApGroupIdsAsync(CancellationToken ct)
    {
        await LoginAsync(ct);
        var path = (_c.UnifiOs ? "proxy/network/" : "") + "v2/api/site/" + Site + "/apgroups";
        using var res = await _http.GetAsync(path, ct);
        if (!res.IsSuccessStatusCode)
        {
            return [];
        }
        var doc = await res.Content.ReadFromJsonAsync<JsonElement>(ct);
        if (doc.ValueKind != JsonValueKind.Array)
        {
            return [];
        }
        // The default "All APs" group cannot be deleted; fall back to the first group.
        var groups = doc.EnumerateArray().ToList();
        var pick = groups.FirstOrDefault(g => g.TryGetProperty("attr_no_delete", out var d) && d.ValueKind == JsonValueKind.True);
        if (pick.ValueKind != JsonValueKind.Object)
        {
            pick = groups.FirstOrDefault();
        }
        return pick.ValueKind == JsonValueKind.Object && pick.TryGetProperty("_id", out var id) && id.GetString() is { } s ? [s] : [];
    }

    public void Dispose() => _http.Dispose();
}

/// <summary>Opens UniFi clients for stored controllers (decrypts the secret).</summary>
public sealed class UniFiFactory(IUniFiTransport transport, SecretProtector protector)
{
    public const string Purpose = "network-controller";

    public string Protect(string secret) => protector.Protect(Purpose, secret);

    public UniFiClient Open(NetworkController c) => new(transport, c, protector.Unprotect(Purpose, c.SecretProtected) ?? throw new UniFiException("The stored controller secret cannot be read; enter it again."));

    public static string Hash(string s) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(s)))[..16];
}
