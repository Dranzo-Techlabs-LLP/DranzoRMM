using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Services;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

/// <summary>Applies approval-list decisions on the site's network controller (block / unblock the Wi-Fi client).</summary>
public sealed class NetworkEnforcer(DranzoDbContext db, UniFiFactory unifi, ILogger<NetworkEnforcer> log)
{
    /// <summary>Returns what happened, for the response; never throws for controller problems.</summary>
    public async Task<string> ApplyAsync(IReadOnlyCollection<NetworkDevice> rows, CancellationToken ct)
    {
        var siteIds = rows.Select(r => r.SiteId).Distinct().ToList();
        if (rows.Count == 0)
        {
            return "nothing to apply";
        }
        var partnerId = rows.First().PartnerId;
        // A blocked company device also loses its 802.1X certificate (refused by RADIUS within minutes).
        foreach (var managed in rows.Where(r => r.Status == NetworkDeviceStatus.Blocked && r.ManagedDeviceId is not null))
        {
            await RadiusEndpoints.RevokeDeviceCertificatesAsync(db, partnerId, managed.ManagedDeviceId!.Value, DateTimeOffset.UtcNow, ct);
        }
        // Explicit partner predicate: the rows were loaded through the caller's tenant filter already.
        var controllers = await db.NetworkControllers.IgnoreQueryFilters().Where(c => c.PartnerId == partnerId && c.SiteId != null && siteIds.Contains(c.SiteId.Value)).ToListAsync(ct);
        if (controllers.Count == 0)
        {
            return "no network controller is connected for this site, so the decision is recorded only";
        }
        var done = 0;
        var failed = new List<string>();
        foreach (var c in controllers)
        {
            try
            {
                using var client = unifi.Open(c);
                foreach (var row in rows.Where(r => r.SiteId == c.SiteId && r.Status != NetworkDeviceStatus.Unknown))
                {
                    await client.BlockClientAsync(row.Mac, row.Status == NetworkDeviceStatus.Blocked, ct);
                    done++;
                }
            }
            catch (Exception ex) when (ex is UniFiException or HttpRequestException or TaskCanceledException or JsonException)
            {
                log.LogWarning("Applying network decisions on controller {Controller} failed: {Error}", c.Id, ex.Message);
                failed.Add($"{c.Name}: {ex.Message}");
            }
        }
        return failed.Count == 0 ? $"applied on the controller ({done})" : "controller not updated: " + string.Join("; ", failed);
    }
}

/// <summary>Pulls clients from every controller: links them to discovered devices and flags company devices on guest Wi-Fi.</summary>
public sealed class NetworkControllerSync(IServiceScopeFactory scopes, ILogger<NetworkControllerSync> log) : PeriodicService(scopes, log, TimeSpan.FromMinutes(5))
{
    protected override Task TickAsync(IServiceProvider sp, CancellationToken ct) => SyncAllAsync(sp, ct);

    public static async Task SyncAllAsync(IServiceProvider sp, CancellationToken ct)
    {
        var db = sp.GetRequiredService<DranzoDbContext>();
        foreach (var id in await db.NetworkControllers.IgnoreQueryFilters().Select(c => c.Id).ToListAsync(ct))
        {
            await SyncAsync(sp, id, ct);
        }
    }

    public static async Task SyncAsync(IServiceProvider sp, Guid controllerId, CancellationToken ct)
    {
        var db = sp.GetRequiredService<DranzoDbContext>();
        var unifi = sp.GetRequiredService<UniFiFactory>();
        var alerts = sp.GetRequiredService<AlertEngine>();
        var now = sp.GetRequiredService<TimeProvider>().GetUtcNow();
        // System scope (background service): every query below names the controller's partner and organization.
        var c = await db.NetworkControllers.IgnoreQueryFilters().FirstAsync(x => x.Id == controllerId, ct);
        try
        {
            JsonElement[] clients;
            using (var client = unifi.Open(c))
            {
                clients = await client.ClientsAsync(ct);
            }
            var seen = clients.Select(x => (Mac: NetworkRules.NormalizeMac(x.Str("mac", 32)), x))
                .Where(x => x.Mac is not null).GroupBy(x => x.Mac!).ToDictionary(g => g.Key, g => g.First().x);
            var macs = seen.Keys.ToList();
            var managed = await db.Devices.IgnoreQueryFilters()
                .Where(d => d.PartnerId == c.PartnerId && d.OrganizationId == c.OrganizationId && d.Status == DeviceStatus.Active && d.MacAddresses.Any(m => macs.Contains(m)))
                .ToListAsync(ct);
            foreach (var d in managed)
            {
                var mac = d.MacAddresses.First(m => seen.ContainsKey(m));
                var cl = seen[mac];
                if (cl.Str("essid", 64) is { Length: > 0 } essid)
                {
                    d.WifiSsid = essid; // the controller knows the SSID even when the OS hides it
                }
                if (cl.Bool("is_guest"))
                {
                    await alerts.RaiseAsync(d, AlertTypes.NetworkDeviceOnGuest, $"guest:{mac}", $"{d.Hostname} is on the guest Wi-Fi",
                        $"Company device {d.Hostname} ({mac}) is connected to guest network \"{cl.Str("essid", 64)}\". Company devices belong on the office network.", ct);
                }
            }
            if (c.SiteId is { } siteId)
            {
                var existing = await db.NetworkDevices.IgnoreQueryFilters().Where(n => n.PartnerId == c.PartnerId && n.SiteId == siteId && macs.Contains(n.Mac)).ToDictionaryAsync(n => n.Mac, ct);
                foreach (var (mac, cl) in seen)
                {
                    if (!existing.TryGetValue(mac, out var row))
                    {
                        row = new NetworkDevice
                        {
                            Id = Guid.NewGuid(), PartnerId = c.PartnerId, OrganizationId = c.OrganizationId, SiteId = siteId, Mac = mac,
                            FirstSeenAt = now, Randomized = NetworkRules.Randomized(mac), Status = NetworkDeviceStatus.Unknown,
                        };
                        db.NetworkDevices.Add(row);
                    }
                    row.Ip = NetworkRules.Ipv4OrNull(cl.Str("ip", 15)) ?? row.Ip;
                    row.Hostname = NetworkRules.CleanHostname(cl.StrOrNull("hostname", 253) ?? cl.StrOrNull("name", 253)) ?? row.Hostname;
                    row.Vendor = cl.StrOrNull("oui", 64) is { Length: > 0 } oui && !oui.Any(char.IsControl) ? oui : row.Vendor;
                    row.LastSeenAt = now;
                    row.ManagedDeviceId = managed.FirstOrDefault(d => d.MacAddresses.Contains(mac))?.Id ?? row.ManagedDeviceId;
                }
            }
            c.LastSyncAt = now;
            c.LastError = null;
        }
        catch (Exception ex) when (ex is UniFiException or HttpRequestException or TaskCanceledException or JsonException or IOException)
        {
            c.LastError = ex.Message.Length > 500 ? ex.Message[..500] : ex.Message;
        }
        await db.SaveChangesAsync(ct);
    }
}

public static partial class NetworkControllerEndpoints
{
    public sealed record ControllerRequest(
        Guid? OrganizationId, Guid? SiteId, string? Name, string? BaseUrl, string? UnifiSite, bool? UnifiOs,
        string? AuthMode, string? Username, string? Secret, string? CertificateSha256);

    public sealed record WifiNetworkRequest(string? Ssid, string? Passphrase, int? Vlan, string? Subnet, bool? ClientIsolation);
    public sealed record WifiSetupRequest(WifiNetworkRequest? Office, WifiNetworkRequest? Guest);

    [GeneratedRegex("^[A-Za-z0-9._-]{1,64}$")]
    private static partial Regex SiteRegex();

    [GeneratedRegex("^[0-9A-Fa-f]{64}$")]
    private static partial Regex PinRegex();

    private static object View(NetworkController c) => new
    {
        c.Id, c.OrganizationId, c.SiteId, c.Name, c.Kind, c.BaseUrl, c.UnifiSite, c.UnifiOs, c.AuthMode, c.Username,
        pinned = c.CertificateSha256 != null, c.CreatedAt, c.LastSyncAt, c.LastError,
    };

    /// <summary>Applies a request to a controller; null on success, otherwise the problem.</summary>
    private static async Task<string?> ApplyAsync(NetworkController c, ControllerRequest req, bool creating, Ctx ctx, UniFiFactory unifi, CancellationToken ct)
    {
        if (req.Name is not null || creating)
        {
            if (Api.CleanName(req.Name, 100) is not { } name)
            {
                return "Give the controller a name.";
            }
            c.Name = name;
        }
        if (req.BaseUrl is not null || creating)
        {
            if (UniFiRules.NormalizeBaseUrl(req.BaseUrl) is not { } url)
            {
                return "The address must be https://host[:port] (no path), and not a loopback or link-local address.";
            }
            c.BaseUrl = url;
        }
        if (req.UnifiSite is not null)
        {
            if (!SiteRegex().IsMatch(req.UnifiSite))
            {
                return "The UniFi site name is the short id (usually \"default\").";
            }
            c.UnifiSite = req.UnifiSite;
        }
        c.UnifiOs = req.UnifiOs ?? c.UnifiOs;
        if (req.AuthMode is not null)
        {
            if (req.AuthMode is not ("apikey" or "password"))
            {
                return "authMode must be apikey or password.";
            }
            c.AuthMode = req.AuthMode;
        }
        if (c.AuthMode == "password")
        {
            var user = req.Username ?? c.Username;
            if (string.IsNullOrWhiteSpace(user) || user.Length > 128 || user.Any(char.IsControl))
            {
                return "A local controller account name is required for password sign-in.";
            }
            c.Username = user.Trim();
        }
        else
        {
            c.Username = null;
        }
        if (req.Secret is not null || creating)
        {
            if (string.IsNullOrEmpty(req.Secret) || req.Secret.Length > 512 || req.Secret.Any(char.IsControl))
            {
                return "Enter the API key or password (up to 512 characters).";
            }
            c.SecretProtected = unifi.Protect(req.Secret);
        }
        if (req.CertificateSha256 is not null)
        {
            var pin = req.CertificateSha256.Replace(":", "", StringComparison.Ordinal).Trim();
            if (pin.Length > 0 && !PinRegex().IsMatch(pin))
            {
                return "The certificate fingerprint is the 64-digit SHA-256 hex value.";
            }
            c.CertificateSha256 = pin.Length == 0 ? null : pin.ToUpperInvariant();
        }
        if (req.SiteId is { } siteId)
        {
            if (siteId == Guid.Empty)
            {
                c.SiteId = null;
            }
            else if (!await ctx.Db.Sites.AnyAsync(s => s.Id == siteId && s.OrganizationId == c.OrganizationId, ct))
            {
                return "The site must belong to the controller's organization.";
            }
            else
            {
                c.SiteId = siteId;
            }
        }
        return null;
    }

    /// <summary>Gateway address and DHCP range for "192.168.10.1/24".</summary>
    public static (string Subnet, string Start, string Stop)? ParseSubnet(string? cidr)
    {
        var parts = (cidr ?? "").Trim().Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var gw) || gw.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
            || !int.TryParse(parts[1], out var bits) || bits is < 16 or > 28 || !NetworkRules.IsPrivateIpv4(gw.ToString()))
        {
            return null;
        }
        var g = BitConverter.ToUInt32([.. gw.GetAddressBytes().Reverse()]);
        var mask = uint.MaxValue << (32 - bits);
        var network = g & mask;
        var broadcast = network | ~mask;
        if (g == network || g == broadcast)
        {
            return null;
        }
        static string Ip(uint v) => new IPAddress(BitConverter.GetBytes(v).Reverse().ToArray()).ToString();
        var start = Math.Min(network + 10, broadcast - 2);
        return ($"{gw}/{bits}", Ip(start == g ? start + 1 : start), Ip(broadcast - 1));
    }

    private static string? ValidateWifi(WifiNetworkRequest? w, string which, bool passphraseRequired)
    {
        if (w is null)
        {
            return null;
        }
        if (w.Ssid is not { Length: >= 1 and <= 32 } || w.Ssid.Any(char.IsControl))
        {
            return $"{which}: the network name (SSID) must be 1-32 characters.";
        }
        if ((passphraseRequired || !string.IsNullOrEmpty(w.Passphrase)) && w.Passphrase is not { Length: >= 8 and <= 63 })
        {
            return $"{which}: the Wi-Fi password must be 8-63 characters.";
        }
        if (w.Vlan is not (>= 2 and <= 4094))
        {
            return $"{which}: choose a VLAN from 2 to 4094.";
        }
        return ParseSubnet(w.Subnet) is null ? $"{which}: the subnet must be the gateway address with prefix, for example 192.168.20.1/24 (private, /16 to /28)." : null;
    }

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/network-controllers", async (Guid? organizationId, Ctx c, CancellationToken ct) =>
            Results.Ok((await c.Db.NetworkControllers.AsNoTracking().Where(x => organizationId == null || x.OrganizationId == organizationId).OrderBy(x => x.Name).ToListAsync(ct)).Select(View)))
            .RequirePermission(Permissions.NetworkRead);

        api.MapPost("/network-controllers", async (ControllerRequest req, Ctx c, UniFiFactory unifi, CancellationToken ct) =>
        {
            if (req.OrganizationId is not { } orgId || !await c.Db.Organizations.AnyAsync(o => o.Id == orgId, ct))
            {
                return Api.NotFound();
            }
            var controller = new NetworkController { Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = orgId, Name = "", BaseUrl = "", CreatedAt = c.Now };
            if (await ApplyAsync(controller, req, true, c, unifi, ct) is { } problem)
            {
                return Api.BadRequest(problem);
            }
            c.Db.NetworkControllers.Add(controller);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("network_controller.create", organizationId: orgId, targetType: "network_controller", targetId: controller.Id,
                detail: new { controller.Name, controller.BaseUrl, controller.AuthMode, secretSha256 = UniFiFactory.Hash(req.Secret!) }, ct: ct);
            return Results.Created($"/api/v1/network-controllers/{controller.Id}", View(controller));
        }).RequirePermission(Permissions.NetworkConfigure, partnerWide: true).RequireStepUp();

        api.MapPatch("/network-controllers/{id:guid}", async (Guid id, ControllerRequest req, Ctx c, UniFiFactory unifi, CancellationToken ct) =>
        {
            var controller = await c.Db.NetworkControllers.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (controller is null)
            {
                return Api.NotFound();
            }
            if (await ApplyAsync(controller, req, false, c, unifi, ct) is { } problem)
            {
                return Api.BadRequest(problem);
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("network_controller.update", organizationId: controller.OrganizationId, targetType: "network_controller", targetId: id,
                detail: new { controller.Name, controller.BaseUrl, controller.AuthMode, secretChanged = req.Secret is not null }, ct: ct);
            return Results.Ok(View(controller));
        }).RequirePermission(Permissions.NetworkConfigure, partnerWide: true).RequireStepUp();

        api.MapDelete("/network-controllers/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var controller = await c.Db.NetworkControllers.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (controller is null)
            {
                return Api.NotFound();
            }
            c.Db.NetworkControllers.Remove(controller);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("network_controller.delete", organizationId: controller.OrganizationId, targetType: "network_controller", targetId: id, detail: new { controller.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.NetworkConfigure, partnerWide: true).RequireStepUp();

        api.MapPost("/network-controllers/{id:guid}/sync", async (Guid id, Ctx c, IServiceProvider sp, CancellationToken ct) =>
        {
            if (!await c.Db.NetworkControllers.AnyAsync(x => x.Id == id, ct))
            {
                return Api.NotFound();
            }
            await NetworkControllerSync.SyncAsync(sp, id, ct);
            var controller = await c.Db.NetworkControllers.AsNoTracking().FirstAsync(x => x.Id == id, ct);
            return Results.Ok(View(controller));
        }).RequirePermission(Permissions.NetworkManage);

        api.MapGet("/network-controllers/{id:guid}/overview", async (Guid id, Ctx c, UniFiFactory unifi, CancellationToken ct) =>
        {
            var controller = await c.Db.NetworkControllers.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
            if (controller is null)
            {
                return Api.NotFound();
            }
            try
            {
                using var client = unifi.Open(controller);
                var devices = await client.DevicesAsync(ct);
                var wlans = await client.WlansAsync(ct);
                var networks = await client.NetworksAsync(ct);
                var clients = await client.ClientsAsync(ct);
                var networkNames = networks.ToDictionary(n => n.Str("_id", 64), n => n.Str("name", 64));
                return Results.Ok(new
                {
                    reachable = true,
                    devices = devices.Select(d => new
                    {
                        mac = d.Str("mac", 32), name = d.Str("name", 128), model = d.Str("model", 64), type = d.Str("type", 16), ip = d.Str("ip", 45),
                        version = d.Str("version", 64), state = d.Num("state") is { } st ? (st == 1 ? "online" : st == 0 ? "offline" : "busy") : "unknown",
                        uptimeSeconds = d.Long("uptime"), clients = d.Long("num_sta"), upgradable = d.Bool("upgradable"),
                    }),
                    wlans = wlans.Select(w => new
                    {
                        id = w.Str("_id", 64), name = w.Str("name", 64), security = w.Str("security", 16), enabled = w.BoolOrNull("enabled") ?? true,
                        isGuest = w.Bool("is_guest"), clientIsolation = w.Bool("l2_isolation"), network = networkNames.GetValueOrDefault(w.Str("networkconf_id", 64)),
                    }),
                    networks = networks.Select(n => new
                    {
                        id = n.Str("_id", 64), name = n.Str("name", 64), purpose = n.Str("purpose", 32), vlan = n.Long("vlan"), subnet = n.Str("ip_subnet", 64),
                    }),
                    clientCount = clients.Length, guestClientCount = clients.Count(x => x.Bool("is_guest")),
                });
            }
            catch (Exception ex) when (ex is UniFiException or HttpRequestException or TaskCanceledException or JsonException)
            {
                return Results.Ok(new { reachable = false, error = ex.Message });
            }
        }).RequirePermission(Permissions.NetworkRead);

        api.MapPost("/network-controllers/{id:guid}/devices/{mac}/restart", async (Guid id, string mac, Ctx c, UniFiFactory unifi, CancellationToken ct) =>
        {
            var controller = await c.Db.NetworkControllers.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
            if (controller is null)
            {
                return Api.NotFound();
            }
            if (NetworkRules.NormalizeMac(mac) is not { } m)
            {
                return Api.BadRequest("Invalid MAC address.");
            }
            try
            {
                using var client = unifi.Open(controller);
                await client.RestartDeviceAsync(m, ct);
            }
            catch (Exception ex) when (ex is UniFiException or HttpRequestException or TaskCanceledException or JsonException)
            {
                return Api.Error(502, "controller_error", ex.Message);
            }
            await c.Audit("network_controller.device_restart", organizationId: controller.OrganizationId, targetType: "network_controller", targetId: id, detail: new { mac = m }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.NetworkManage).RequireStepUp();

        // Separate office and guest Wi-Fi: each on its own VLAN and subnet; the guest network uses UniFi's guest policies
        // (no access to the office LAN) and optional client isolation. Existing networks and SSIDs are left unchanged.
        api.MapPost("/network-controllers/{id:guid}/wifi-setup", async (Guid id, WifiSetupRequest req, Ctx c, UniFiFactory unifi, CancellationToken ct) =>
        {
            var controller = await c.Db.NetworkControllers.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
            if (controller is null)
            {
                return Api.NotFound();
            }
            if (req.Office is null && req.Guest is null)
            {
                return Api.BadRequest("Describe the office network, the guest network or both.");
            }
            if ((ValidateWifi(req.Office, "Office", passphraseRequired: true) ?? ValidateWifi(req.Guest, "Guest", passphraseRequired: false)) is { } problem)
            {
                return Api.BadRequest(problem);
            }
            if (req.Office is not null && req.Guest is not null && (req.Office.Vlan == req.Guest.Vlan || string.Equals(req.Office.Ssid, req.Guest.Ssid, StringComparison.Ordinal)))
            {
                return Api.BadRequest("Office and guest need different VLANs and different network names.");
            }
            var steps = new List<string>();
            try
            {
                using var client = unifi.Open(controller);
                var networks = await client.NetworksAsync(ct);
                var wlans = await client.WlansAsync(ct);
                var userGroup = (await client.UserGroupsAsync(ct)).Select(g => g.Str("_id", 64)).FirstOrDefault(x => x.Length > 0);
                var apGroups = await client.ApGroupIdsAsync(ct);
                foreach (var (w, guest) in new[] { (req.Office, false), (req.Guest, true) })
                {
                    if (w is null)
                    {
                        continue;
                    }
                    var label = guest ? "Guest" : "Office";
                    var netName = $"{label} (DranzoRMM)";
                    var net = networks.FirstOrDefault(n => n.Long("vlan") == w.Vlan);
                    string netId;
                    if (net.ValueKind == JsonValueKind.Object)
                    {
                        netId = net.Str("_id", 64);
                        steps.Add($"{label}: VLAN {w.Vlan} already exists as \"{net.Str("name", 64)}\"; reused.");
                    }
                    else
                    {
                        var (subnet, start, stop) = ParseSubnet(w.Subnet)!.Value;
                        var created = await client.CreateNetworkAsync(new
                        {
                            name = netName, purpose = guest ? "guest" : "corporate", networkgroup = "LAN", enabled = true,
                            vlan_enabled = true, vlan = w.Vlan, ip_subnet = subnet, dhcpd_enabled = true, dhcpd_start = start, dhcpd_stop = stop,
                        }, ct);
                        netId = created.FirstOrDefault().Str("_id", 64);
                        steps.Add($"{label}: created network \"{netName}\" on VLAN {w.Vlan} ({subnet}).");
                    }
                    if (wlans.Any(x => x.Str("name", 64) == w.Ssid))
                    {
                        steps.Add($"{label}: Wi-Fi \"{w.Ssid}\" already exists; left unchanged.");
                        continue;
                    }
                    var open = string.IsNullOrEmpty(w.Passphrase);
                    await client.CreateWlanAsync(new
                    {
                        name = w.Ssid, enabled = true, networkconf_id = netId, usergroup_id = userGroup, ap_group_ids = apGroups,
                        security = open ? "open" : "wpapsk", wpa_mode = "wpa2", wpa_enc = "ccmp", x_passphrase = open ? null : w.Passphrase,
                        is_guest = guest, l2_isolation = guest && (w.ClientIsolation ?? true), hide_ssid = false, wlan_band = "both",
                    }, ct);
                    steps.Add($"{label}: created Wi-Fi \"{w.Ssid}\"{(open ? " (open)" : " (WPA2)")}{(guest ? ", guest policies on, devices cannot reach the office network" : "")}.");
                }
            }
            catch (Exception ex) when (ex is UniFiException or HttpRequestException or TaskCanceledException or JsonException)
            {
                await c.Audit("network_controller.wifi_setup", "failure", controller.OrganizationId, targetType: "network_controller", targetId: id, detail: new { steps, error = ex.Message }, ct: ct);
                return Api.Error(502, "controller_error", ex.Message + (steps.Count > 0 ? " Done before the error: " + string.Join(" ", steps) : ""));
            }
            // Passwords are never stored or logged: the audit has the names and VLANs only.
            await c.Audit("network_controller.wifi_setup", organizationId: controller.OrganizationId, targetType: "network_controller", targetId: id,
                detail: new { office = req.Office is null ? null : new { req.Office.Ssid, req.Office.Vlan }, guest = req.Guest is null ? null : new { req.Guest.Ssid, req.Guest.Vlan }, steps }, ct: ct);
            return Results.Ok(new { steps });
        }).RequirePermission(Permissions.NetworkConfigure, partnerWide: true).RequireStepUp();
    }
}
