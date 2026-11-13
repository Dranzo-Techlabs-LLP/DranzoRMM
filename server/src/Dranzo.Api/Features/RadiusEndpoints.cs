using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Jobs;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

/// <summary>Issues the Wi-Fi certificate from the device's CSR and queues the profile installation.</summary>
public sealed class CertRequestResultHandler(DranzoDbContext db, NetworkCertificateAuthority netCa, JobService jobs, TimeProvider clock, ILogger<CertRequestResultHandler> log) : IJobResultHandler
{
    public bool Handles(string kind) => kind is JobKinds.NetworkCertRequest or JobKinds.NetworkWifiInstall;

    public async Task HandleAsync(JobRun run, Device device, JsonElement result, CancellationToken ct)
    {
        if (run.Status != JobRunStatus.Succeeded)
        {
            return;
        }
        if (run.Kind == JobKinds.NetworkWifiInstall)
        {
            // System scope: explicit partner and device predicates.
            await db.NetworkCertificates.IgnoreQueryFilters().Where(x => x.PartnerId == device.PartnerId && x.DeviceId == device.Id && x.RevokedAt == null && x.InstalledAt == null)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.InstalledAt, clock.GetUtcNow()), ct);
            return;
        }
        var config = await db.RadiusConfigs.IgnoreQueryFilters().FirstOrDefaultAsync(r => r.PartnerId == device.PartnerId && r.OrganizationId == device.OrganizationId, ct);
        var csr = result.Str("csr", 8192);
        if (config is null || csr.Length == 0 || device.Status != DeviceStatus.Active)
        {
            return;
        }
        string certPem, serial, thumbprint;
        DateTimeOffset notAfter;
        try
        {
            (certPem, serial, thumbprint, notAfter) = netCa.IssueClient(device.OrganizationId, csr, device.Id);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            log.LogWarning("Rejected Wi-Fi CSR from device {DeviceId}: {Error}", device.Id, ex.Message);
            return;
        }
        var now = clock.GetUtcNow();
        // A new certificate replaces the older ones of this device.
        await db.NetworkCertificates.IgnoreQueryFilters().Where(x => x.PartnerId == device.PartnerId && x.DeviceId == device.Id && x.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), ct);
        db.NetworkCertificates.Add(new NetworkCertificate
        {
            Id = Guid.NewGuid(), PartnerId = device.PartnerId, OrganizationId = device.OrganizationId, DeviceId = device.Id,
            SerialHex = serial, Thumbprint = thumbprint, IssuedAt = now, NotAfter = notAfter,
        });
        await db.SaveChangesAsync(ct);
        var job = await db.Jobs.IgnoreQueryFilters().AsNoTracking().FirstAsync(j => j.Id == run.JobId && j.PartnerId == device.PartnerId, ct);
        await jobs.CreateAsync(new NewJob("Install office Wi-Fi (802.1X)", JobKinds.NetworkWifiInstall, new JobTarget(DeviceIds: [device.Id]),
            new { ssid = config.OfficeSsid, caPem = netCa.CaPem(device.OrganizationId), certPem }, 300, IsSystem: true),
            [device], device.PartnerId, job.RequestedByUserId, job.RequestedByName, ct);
    }
}

public static class RadiusEndpoints
{
    public const string SecretPurpose = "radius";
    public sealed record RadiusRequest(Guid? OrganizationId, string? ClientsCidr, string? OfficeSsid);
    public sealed record UnifiRequest(Guid? ControllerId, string? RadiusHost, int? RadiusPort);
    public sealed record EnrollRequest(Guid[]? DeviceIds);

    /// <summary>Revokes the Wi-Fi certificates of a device (device revoked, deleted or blocked).</summary>
    public static Task<int> RevokeDeviceCertificatesAsync(DranzoDbContext db, Guid partnerId, Guid deviceId, DateTimeOffset now, CancellationToken ct) =>
        db.NetworkCertificates.IgnoreQueryFilters().Where(x => x.PartnerId == partnerId && x.DeviceId == deviceId && x.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), ct);

    private static bool ValidCidr(string? cidr) =>
        cidr is { Length: <= 49 } && System.Net.IPNetwork.TryParse(cidr.Trim(), out var n) && n.BaseAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
        && NetworkRules.IsPrivateIpv4(n.BaseAddress.ToString()) && n.PrefixLength >= 8;

    private static string Conf(string s) => s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);

    /// <summary>The FreeRADIUS 3.2 configuration for EAP-TLS with the organization's network CA.</summary>
    public static byte[] Bundle(RadiusConfig config, string secret, string caPem, string serverCertPem, string serverKeyPem, string crlUrl)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            void Add(string name, string content)
            {
                var e = zip.CreateEntry(name, CompressionLevel.Optimal);
                using var w = new StreamWriter(e.Open(), new UTF8Encoding(false));
                w.Write(content.Replace("\r\n", "\n", StringComparison.Ordinal));
            }
            Add("clients.conf", $"# DranzoRMM: access points / controller allowed to ask this server.\nclient dranzo_access_points {{\n\tipaddr = {config.ClientsCidr}\n\tsecret = \"{Conf(secret)}\"\n\tshortname = dranzo-aps\n\trequire_message_authenticator = yes\n}}\n");
            Add("eap", """
                # DranzoRMM: EAP-TLS only. Devices present a certificate from the organization's DranzoRMM network CA;
                # certificates on the CRL (revoked, deleted or blocked devices) are refused.
                eap {
                	default_eap_type = tls
                	timer_expire = 60
                	ignore_unknown_eap_types = no
                	max_sessions = ${max_requests}
                	tls-config tls-common {
                		private_key_file = /etc/freeradius/certs/dranzo/server.key
                		certificate_file = /etc/freeradius/certs/dranzo/server.pem
                		ca_path = /etc/freeradius/certs/dranzo/capath
                		check_crl = yes
                		cipher_list = "DEFAULT"
                		tls_min_version = "1.2"
                		tls_max_version = "1.2"
                		ecdh_curve = "prime256v1"
                	}
                	tls {
                		tls = tls-common
                	}
                }
                """);
            static string Pem(string p) => p.Trim() + "\n";
            Add("certs/ca.pem", Pem(caPem));
            Add("certs/server.pem", Pem(serverCertPem) + Pem(caPem));
            Add("certs/server.key", Pem(serverKeyPem));
            Add("Dockerfile", """
                # FreeRADIUS with curl for the CRL refresh.
                FROM freeradius/freeradius-server:3.2.7
                RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
                """);
            Add("update-crl.sh", $"""
                #!/bin/sh
                # Fetches the DranzoRMM CRL into the CA directory and reloads FreeRADIUS. Run every 5 minutes.
                set -eu
                dir=/etc/freeradius/certs/dranzo/capath
                mkdir -p "$dir"
                cp /etc/freeradius/certs/dranzo/ca.pem "$dir/ca.pem"
                tmp="$dir/crl.pem.new"
                if curl -fsS --max-time 20 -o "$tmp" "{crlUrl}"; then
                	grep -q "BEGIN X509 CRL" "$tmp" && mv "$tmp" "$dir/crl.pem"
                fi
                openssl rehash "$dir" >/dev/null 2>&1 || c_rehash "$dir" >/dev/null 2>&1 || true
                pkill -HUP freeradius 2>/dev/null || true
                """);
            Add("docker-compose.yml", """
                # FreeRADIUS for DranzoRMM 802.1X. Run in this folder: docker compose up -d
                # UDP 1812 must be reachable from the access points (and nothing else).
                services:
                  radius:
                    build: .
                    restart: unless-stopped
                    ports:
                      - "1812:1812/udp"
                    volumes:
                      - ./clients.conf:/etc/freeradius/clients.conf:ro
                      - ./eap:/etc/freeradius/mods-available/eap:ro
                      - ./certs:/etc/freeradius/certs/dranzo
                      - ./update-crl.sh:/usr/local/bin/update-crl.sh:ro
                    entrypoint: ["/bin/sh", "-c", "sh /usr/local/bin/update-crl.sh || true; (while sleep 300; do sh /usr/local/bin/update-crl.sh; done) & exec freeradius -f -l stdout"]
                """);
            Add("README.txt", $"""
                DranzoRMM 802.1X (EAP-TLS) RADIUS server for office Wi-Fi "{config.OfficeSsid}".

                This folder holds a private key and the RADIUS shared secret. Keep it like a password.

                1. Copy the folder to an always-on machine on the office network (Docker installed).
                2. docker compose up -d
                3. In DranzoRMM: Network > Wi-Fi & controllers > 802.1X > "Use on UniFi" with this machine's IP.
                4. Enroll devices: their certificates and Wi-Fi profiles are installed by the agent.

                Revoked, deleted and blocked devices are refused within 5 minutes (CRL from {crlUrl}).
                Access points allowed to ask: {config.ClientsCidr}.
                """);
        }
        return ms.ToArray();
    }

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/radius", async (Guid? organizationId, Ctx c, NetworkCertificateAuthority netCa, CancellationToken ct) =>
        {
            var configs = await c.Db.RadiusConfigs.AsNoTracking().Where(r => organizationId == null || r.OrganizationId == organizationId).ToListAsync(ct);
            var orgIds = configs.Select(r => r.OrganizationId).ToList();
            var certs = await c.Db.NetworkCertificates.AsNoTracking().Where(x => orgIds.Contains(x.OrganizationId))
                .GroupBy(x => x.OrganizationId)
                .Select(g => new { g.Key, Active = g.Count(x => x.RevokedAt == null), Installed = g.Count(x => x.RevokedAt == null && x.InstalledAt != null), Revoked = g.Count(x => x.RevokedAt != null) })
                .ToDictionaryAsync(x => x.Key, ct);
            return Results.Ok(configs.Select(r => new
            {
                r.Id, r.OrganizationId, r.ClientsCidr, r.OfficeSsid, r.CreatedAt, r.UpdatedAt,
                caPem = netCa.CaPem(r.OrganizationId),
                activeCertificates = certs.GetValueOrDefault(r.OrganizationId)?.Active ?? 0,
                installedCertificates = certs.GetValueOrDefault(r.OrganizationId)?.Installed ?? 0,
                revokedCertificates = certs.GetValueOrDefault(r.OrganizationId)?.Revoked ?? 0,
            }));
        }).RequirePermission(Permissions.NetworkRead);

        api.MapPost("/radius", async (RadiusRequest req, Ctx c, NetworkCertificateAuthority netCa, SecretProtector protector, CancellationToken ct) =>
        {
            if (req.OrganizationId is not { } orgId || !await c.Db.Organizations.AnyAsync(o => o.Id == orgId, ct))
            {
                return Api.NotFound();
            }
            if (!ValidCidr(req.ClientsCidr))
            {
                return Api.BadRequest("Give the private address range of the access points or controller, for example 192.168.1.0/24.");
            }
            if (req.OfficeSsid is not { Length: >= 1 and <= 32 } ssid || ssid.Any(char.IsControl))
            {
                return Api.BadRequest("Give the office Wi-Fi name (1-32 characters).");
            }
            var config = await c.Db.RadiusConfigs.FirstOrDefaultAsync(r => r.OrganizationId == orgId, ct);
            var created = config is null;
            if (config is null)
            {
                config = new RadiusConfig
                {
                    Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = orgId, ClientsCidr = "", OfficeSsid = "",
                    SharedSecretProtected = protector.Protect(SecretPurpose, Convert.ToBase64String(RandomNumberGenerator.GetBytes(24))), CreatedAt = c.Now,
                };
                c.Db.RadiusConfigs.Add(config);
            }
            config.ClientsCidr = req.ClientsCidr!.Trim();
            config.OfficeSsid = ssid;
            config.UpdatedAt = c.Now;
            netCa.GetOrCreate(orgId).Dispose();
            await c.Db.SaveChangesAsync(ct);
            await c.Audit(created ? "radius.enable" : "radius.update", organizationId: orgId, targetType: "radius", targetId: config.Id, detail: new { config.ClientsCidr, config.OfficeSsid }, ct: ct);
            return Results.Ok(new { config.Id, config.OrganizationId, config.ClientsCidr, config.OfficeSsid });
        }).RequirePermission(Permissions.NetworkConfigure, partnerWide: true).RequireStepUp();

        // Holds the RADIUS server's private key and shared secret: step-up, audited.
        api.MapGet("/radius/{id:guid}/bundle.zip", async (Guid id, Ctx c, NetworkCertificateAuthority netCa, SecretProtector protector, HttpContext http, CancellationToken ct) =>
        {
            var config = await c.Db.RadiusConfigs.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct);
            if (config is null)
            {
                return Api.NotFound();
            }
            var secret = protector.Unprotect(SecretPurpose, config.SharedSecretProtected) ?? throw new InvalidOperationException("RADIUS secret unreadable.");
            var (certPem, keyPem) = netCa.IssueServer(config.OrganizationId);
            var crlUrl = $"{http.Request.Scheme}://{http.Request.Host}/api/v1/pki/network/{config.OrganizationId:D}/crl.pem";
            await c.Audit("radius.bundle_download", organizationId: config.OrganizationId, targetType: "radius", targetId: id, ct: ct);
            return Results.File(Bundle(config, secret, netCa.CaPem(config.OrganizationId), certPem, keyPem, crlUrl), "application/zip", "dranzo-radius.zip");
        }).RequirePermission(Permissions.NetworkConfigure, partnerWide: true).RequireStepUp();

        // Public: a CRL is meant to be fetched by anyone who validates certificates.
        api.MapGet("/pki/network/{organizationId:guid}/crl.pem", async (Guid organizationId, Ctx c, NetworkCertificateAuthority netCa, CancellationToken ct) =>
        {
            // Anonymous: the tenant filter is empty, so the config is looked up explicitly by organization.
            var config = await c.Db.RadiusConfigs.IgnoreQueryFilters().AsNoTracking().FirstOrDefaultAsync(r => r.OrganizationId == organizationId, ct);
            if (config is null)
            {
                return Api.NotFound();
            }
            var revoked = await c.Db.NetworkCertificates.IgnoreQueryFilters().AsNoTracking()
                .Where(x => x.PartnerId == config.PartnerId && x.OrganizationId == organizationId && x.RevokedAt != null && x.NotAfter > c.Now)
                .Select(x => new { x.SerialHex, x.RevokedAt }).ToListAsync(ct);
            var number = c.Now.ToUnixTimeSeconds();
            return Results.Text(netCa.CrlPem(organizationId, revoked.Select(r => (r.SerialHex, r.RevokedAt!.Value)), number, c.Now), "application/x-pem-file");
        }).Anonymous();

        api.MapPost("/radius/{id:guid}/enroll", async (Guid id, EnrollRequest req, Ctx c, JobService jobs, CancellationToken ct) =>
        {
            var config = await c.Db.RadiusConfigs.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct);
            if (config is null)
            {
                return Api.NotFound();
            }
            var q = c.Db.Devices.Where(d => d.OrganizationId == config.OrganizationId && d.Status == DeviceStatus.Active && (d.Os == "windows" || d.Os == "linux"));
            if (req.DeviceIds is { Length: > 0 } ids)
            {
                q = q.Where(d => ids.Contains(d.Id));
            }
            var devices = await q.Take(5000).ToListAsync(ct);
            if (devices.Count == 0)
            {
                return Api.Conflict("No Windows or Linux device to enroll in this organization (macOS needs a configuration profile).");
            }
            var created = await jobs.CreateAsync(new NewJob("Request Wi-Fi certificate (802.1X)", JobKinds.NetworkCertRequest, new JobTarget(DeviceIds: [.. devices.Select(d => d.Id)]), new { }, 300),
                devices, c.Who.PartnerId, c.Who.UserId, c.Who.Name, ct);
            await c.Audit("radius.enroll", organizationId: config.OrganizationId, targetType: "job", targetId: created.Job.Id, detail: new { devices = devices.Count }, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id, deviceCount = devices.Count });
        }).RequirePermission(Permissions.NetworkConfigure, partnerWide: true).RequireStepUp();

        // Office Wi-Fi to WPA2-Enterprise with this RADIUS server.
        api.MapPost("/radius/{id:guid}/unifi", async (Guid id, UnifiRequest req, Ctx c, UniFiFactory unifi, SecretProtector protector, CancellationToken ct) =>
        {
            var config = await c.Db.RadiusConfigs.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id, ct);
            var controller = req.ControllerId is { } cid ? await c.Db.NetworkControllers.AsNoTracking().FirstOrDefaultAsync(x => x.Id == cid, ct) : null;
            if (config is null || controller is null || controller.OrganizationId != config.OrganizationId)
            {
                return Api.NotFound();
            }
            if (NetworkRules.Ipv4OrNull(req.RadiusHost) is not { } host || !NetworkRules.IsPrivateIpv4(host))
            {
                return Api.BadRequest("Give the private IPv4 address of the RADIUS server.");
            }
            var port = req.RadiusPort ?? 1812;
            if (port is < 1 or > 65535)
            {
                return Api.BadRequest("Invalid port.");
            }
            var secret = protector.Unprotect(SecretPurpose, config.SharedSecretProtected)!;
            try
            {
                using var client = unifi.Open(controller);
                var wlan = (await client.WlansAsync(ct)).FirstOrDefault(w => w.Str("name", 64) == config.OfficeSsid);
                if (wlan.ValueKind != JsonValueKind.Object)
                {
                    return Api.Conflict($"The controller has no Wi-Fi named \"{config.OfficeSsid}\". Set up the office Wi-Fi first.");
                }
                var profileName = "DranzoRMM 802.1X";
                var profile = (await client.RadiusProfilesAsync(ct)).FirstOrDefault(p => p.Str("name", 64) == profileName);
                var profileId = profile.ValueKind == JsonValueKind.Object ? profile.Str("_id", 64)
                    : (await client.CreateRadiusProfileAsync(new { name = profileName, auth_servers = new[] { new { ip = host, port, x_secret = secret } } }, ct)).FirstOrDefault().Str("_id", 64);
                await client.UpdateWlanAsync(wlan.Str("_id", 64), new { security = "wpaeap", wpa_mode = "wpa2", wpa_enc = "ccmp", radiusprofile_id = profileId }, ct);
            }
            catch (Exception ex) when (ex is UniFiException or HttpRequestException or TaskCanceledException or JsonException)
            {
                return Api.Error(502, "controller_error", ex.Message);
            }
            await c.Audit("radius.unifi", organizationId: config.OrganizationId, targetType: "network_controller", targetId: controller.Id, detail: new { config.OfficeSsid, host, port }, ct: ct);
            return Results.Ok(new { ssid = config.OfficeSsid, security = "WPA2-Enterprise (802.1X)" });
        }).RequirePermission(Permissions.NetworkConfigure, partnerWide: true).RequireStepUp();
    }
}
