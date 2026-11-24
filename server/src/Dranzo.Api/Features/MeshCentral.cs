using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dranzo.Api.Jobs;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

/// <summary>
/// MeshCentral integration for remote desktop. DranzoRMM does consent, indicator, authorization and audit;
/// MeshCentral carries the screen stream.
/// Verified against a real MeshCentral 1.1.44 container: the login token below signs the named account in, and
/// the default agent architecture ids (4, 43, 6, 26, 16, 29) all resolve to agent binaries.
/// Not verified: a full MeshAgent install on a device and an actual desktop stream (needs a MeshCentral device
/// group and a machine with a desktop session). See docs/RUNBOOK.md.
/// </summary>
public sealed class MeshCentral(IOptions<DranzoOptions> options, IHttpClientFactory http, TimeProvider clock)
{
    public const string HttpClientName = "meshcentral";

    private MeshOptions Opt => options.Value.Mesh;

    /// <summary>
    /// The handler for calls to MeshCentral. Normal certificate validation applies; when <paramref name="pinSha256Hex"/>
    /// is set, a certificate that fails validation is still accepted if its SHA-256 equals the pin (self-signed MeshCentral).
    /// </summary>
    public static SocketsHttpHandler CreateHandler(string? pinSha256Hex)
    {
        var handler = new SocketsHttpHandler();
        if (string.IsNullOrWhiteSpace(pinSha256Hex))
        {
            return handler;
        }
        byte[] pin;
        try
        {
            pin = Convert.FromHexString(pinSha256Hex.Replace(":", "", StringComparison.Ordinal).Trim());
        }
        catch (FormatException)
        {
            pin = [];
        }
        if (pin.Length != SHA256.HashSizeInBytes)
        {
            throw new InvalidOperationException("Dranzo:Mesh:CertificateSha256 must be the 64-digit hex SHA-256 of MeshCentral's certificate.");
        }
        handler.SslOptions.RemoteCertificateValidationCallback = (_, cert, _, errors) => PinAccepts(pin, cert, errors);
        return handler;
    }

    public static bool PinAccepts(byte[] pin, System.Security.Cryptography.X509Certificates.X509Certificate? cert, System.Net.Security.SslPolicyErrors errors) =>
        errors == System.Net.Security.SslPolicyErrors.None
        || (cert is not null && CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.GetRawCertData()), pin));

    public bool Configured => !string.IsNullOrEmpty(Opt.Url) && !string.IsNullOrEmpty(Opt.LoginTokenKey);

    /// <summary>
    /// The MeshCentral account a session for this organization signs in as. Returns null (refuse) when the
    /// organization has no dedicated account and a shared one has not been explicitly allowed.
    /// </summary>
    public string? UserFor(Organization org) => !string.IsNullOrEmpty(org.MeshUser) ? org.MeshUser
        : Opt.AllowSharedUser ? $"user/{Opt.Domain}/{Opt.User}" : null;

    /// <summary>
    /// A MeshCentral login token in MeshCentral's own cookie format: base64(iv ‖ tag ‖ AES-256-GCM(json)) with
    /// '+' → '@' and '/' → '$'. The key is the first 32 bytes of the server's login token key.
    /// </summary>
    public string LoginToken(string meshUser)
    {
        var key = Convert.FromHexString(Opt.LoginTokenKey!)[..32];
        var json = JsonSerializer.SerializeToUtf8Bytes(new { u = meshUser, a = 3, time = clock.GetUtcNow().ToUnixTimeSeconds(), expire = Opt.LoginTokenMinutes });
        var iv = RandomNumberGenerator.GetBytes(12);
        var cipher = new byte[json.Length];
        var tag = new byte[16];
        using (var aes = new AesGcm(key, 16))
        {
            aes.Encrypt(iv, json, cipher, tag);
        }
        return Convert.ToBase64String([.. iv, .. tag, .. cipher]).Replace('+', '@').Replace('/', '$');
    }

    public static string? DecodeToken(string token, string keyHex)
    {
        var raw = Convert.FromBase64String(token.Replace('@', '+').Replace('$', '/'));
        var plain = new byte[raw.Length - 28];
        using var aes = new AesGcm(Convert.FromHexString(keyHex)[..32], 16);
        aes.Decrypt(raw.AsSpan(0, 12), raw.AsSpan(28), raw.AsSpan(12, 16), plain);
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>
    /// The MeshCentral link that opens the device's desktop. MeshCentral's web app looks the device up as
    /// "node/&lt;domain&gt;/" + gotonode and reads query values without URL-decoding them, so gotonode is only the part
    /// after the last '/', and it is not percent-encoded: node ids use MeshCentral's URL-safe base64 ('@' and '$'
    /// instead of '+' and '/'), and "%40"/"%24" never matched. Either mistake opened MeshCentral with no device selected
    /// ("Disconnected", Connect greyed out), found in the 2026-11-24 field test. Anything outside that alphabet is
    /// refused rather than passed on.
    /// </summary>
    public string DesktopUrl(string nodeId, string meshUser)
    {
        var shortId = nodeId[(nodeId.LastIndexOf('/') + 1)..];
        if (shortId.Length == 0 || !shortId.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '@' or '$' or '-' or '_'))
        {
            throw new InvalidOperationException("The device's MeshCentral node id is not valid.");
        }
        return $"{Opt.Url!.TrimEnd('/')}/?login={Uri.EscapeDataString(LoginToken(meshUser))}&gotonode={shortId}&viewmode=11&hide=31";
    }

    /// <summary>Fetches the MeshAgent installer for a device from the MeshCentral server.</summary>
    public async Task<(Stream Content, string FileName)> DownloadAgentAsync(string os, string arch, string meshGroupId, CancellationToken ct)
    {
        if (!Opt.AgentIds.TryGetValue($"{os}-{arch}", out var id))
        {
            throw new InvalidOperationException($"No MeshCentral agent id configured for {os}-{arch}.");
        }
        var url = $"{Opt.Url!.TrimEnd('/')}/meshagents?id={id}&meshid={Uri.EscapeDataString(meshGroupId)}&installflags=0";
        var client = http.CreateClient(HttpClientName);
        client.Timeout = TimeSpan.FromMinutes(5);
        var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadAsStreamAsync(ct), os == "windows" ? "meshagent.exe" : "meshagent");
    }
}

/// <summary>Stores the MeshCentral node id reported after the MeshAgent is installed.</summary>
public sealed class MeshResultHandler(DranzoDbContext db) : IJobResultHandler
{
    public bool Handles(string kind) => kind is JobKinds.MeshInstall or JobKinds.MeshUninstall;

    public async Task HandleAsync(JobRun run, Device device, JsonElement result, CancellationToken ct)
    {
        if (run.Status != JobRunStatus.Succeeded)
        {
            return;
        }
        var nodeId = run.Kind == JobKinds.MeshInstall ? Agents.J.StrOrNull(result, "meshNodeId", 200) : null;
        // MeshCentral node ids look like "node/<domain>/<base64-ish>"; anything else is ignored.
        if (nodeId is not null && !System.Text.RegularExpressions.Regex.IsMatch(nodeId, @"^node/[A-Za-z0-9_-]*/[A-Za-z0-9@$_-]{16,128}$"))
        {
            nodeId = null;
        }
        await db.Devices.Where(d => d.Id == device.Id).ExecuteUpdateAsync(s => s.SetProperty(d => d.MeshNodeId, nodeId), ct);
    }
}
