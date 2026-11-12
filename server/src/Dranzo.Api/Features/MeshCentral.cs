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
    private MeshOptions Opt => options.Value.Mesh;

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

    public string DesktopUrl(string nodeId, string meshUser) =>
        $"{Opt.Url!.TrimEnd('/')}/?login={Uri.EscapeDataString(LoginToken(meshUser))}&gotonode={Uri.EscapeDataString(nodeId)}&viewmode=11&hide=31";

    /// <summary>Fetches the MeshAgent installer for a device from the MeshCentral server.</summary>
    public async Task<(Stream Content, string FileName)> DownloadAgentAsync(string os, string arch, string meshGroupId, CancellationToken ct)
    {
        if (!Opt.AgentIds.TryGetValue($"{os}-{arch}", out var id))
        {
            throw new InvalidOperationException($"No MeshCentral agent id configured for {os}-{arch}.");
        }
        var url = $"{Opt.Url!.TrimEnd('/')}/meshagents?id={id}&meshid={Uri.EscapeDataString(meshGroupId)}&installflags=0";
        var client = http.CreateClient();
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
