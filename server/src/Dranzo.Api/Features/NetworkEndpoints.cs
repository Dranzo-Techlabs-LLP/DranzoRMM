using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Jobs;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

/// <summary>Validation shared by the network features. Agent input is untrusted.</summary>
public static partial class NetworkRules
{
    [GeneratedRegex("^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")]
    private static partial Regex MacRegex();

    /// <summary>Lowercase colon-separated unicast MAC, or null.</summary>
    public static string? NormalizeMac(string? mac)
    {
        var m = (mac ?? "").Trim().ToLowerInvariant().Replace('-', ':');
        if (!MacRegex().IsMatch(m) || m == "00:00:00:00:00:00")
        {
            return null;
        }
        var first = Convert.ToByte(m[..2], 16);
        return (first & 1) == 0 ? m : null; // group bit: multicast / broadcast
    }

    public static bool Randomized(string mac) => (Convert.ToByte(mac[..2], 16) & 2) != 0;

    public static string? Ipv4OrNull(string? ip) =>
        IPAddress.TryParse(ip, out var a) && a.AddressFamily == AddressFamily.InterNetwork && ip!.Count(ch => ch == '.') == 3 ? a.ToString() : null;

    /// <summary>RFC 1918 or shared (CGNAT) IPv4: the only addresses a LAN scan may report.</summary>
    public static bool IsPrivateIpv4(string ip)
    {
        if (Ipv4OrNull(ip) is not { } v)
        {
            return false;
        }
        var b = IPAddress.Parse(v).GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 100 && b[1] is >= 64 and <= 127);
    }

    public static string? CleanHostname(string? name)
    {
        var n = (name ?? "").Trim().TrimEnd('.');
        return n.Length is > 0 and <= 253 && n.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '.' or '-' or '_') ? n : null;
    }
}

/// <summary>Stores network.scan results as <see cref="NetworkDevice"/> rows of the scanning device's site.</summary>
public sealed class NetworkScanResultHandler(DranzoDbContext db, AlertEngine alerts, TimeProvider clock) : IJobResultHandler
{
    public const int MaxNeighbors = 1024;

    public bool Handles(string kind) => kind == JobKinds.NetworkScan;

    public async Task HandleAsync(JobRun run, Device device, JsonElement result, CancellationToken ct)
    {
        if (run.Status != JobRunStatus.Succeeded || result.ValueKind != JsonValueKind.Object)
        {
            return;
        }
        var now = clock.GetUtcNow();
        var gateway = NetworkRules.Ipv4OrNull(result.Str("gateway", 15));
        var seen = new Dictionary<string, (string Ip, string? Host)>();
        foreach (var n in result.Arr("neighbors", MaxNeighbors))
        {
            var mac = NetworkRules.NormalizeMac(n.Str("mac", 32));
            var ip = n.Str("ip", 15);
            if (mac is null || !NetworkRules.IsPrivateIpv4(ip))
            {
                continue;
            }
            seen[mac] = (NetworkRules.Ipv4OrNull(ip)!, NetworkRules.CleanHostname(n.StrOrNull("hostname", 253)));
        }
        if (seen.Count == 0)
        {
            return;
        }

        // System-scoped: explicit partner and site predicates.
        var macs = seen.Keys.ToList();
        var existing = await db.NetworkDevices.IgnoreQueryFilters()
            .Where(x => x.PartnerId == device.PartnerId && x.SiteId == device.SiteId && macs.Contains(x.Mac)).ToDictionaryAsync(x => x.Mac, ct);
        var managed = await db.Devices.IgnoreQueryFilters()
            .Where(d => d.PartnerId == device.PartnerId && d.OrganizationId == device.OrganizationId && d.Status == DeviceStatus.Active && d.MacAddresses.Any(m => macs.Contains(m)))
            .Select(d => new { d.Id, d.MacAddresses }).ToListAsync(ct);
        Guid? ManagedFor(string mac) => managed.FirstOrDefault(d => d.MacAddresses.Contains(mac))?.Id;

        var added = new List<NetworkDevice>();
        foreach (var (mac, (ip, host)) in seen)
        {
            if (!existing.TryGetValue(mac, out var row))
            {
                row = new NetworkDevice
                {
                    Id = Guid.NewGuid(), PartnerId = device.PartnerId, OrganizationId = device.OrganizationId, SiteId = device.SiteId,
                    Mac = mac, FirstSeenAt = now, Randomized = NetworkRules.Randomized(mac), Status = NetworkDeviceStatus.Unknown,
                };
                db.NetworkDevices.Add(row);
                added.Add(row);
            }
            row.Ip = ip;
            row.Hostname = host ?? row.Hostname;
            row.IsGateway = ip == gateway;
            row.LastSeenAt = now;
            row.SeenByDeviceId = device.Id;
            row.ManagedDeviceId = ManagedFor(mac);
        }
        await db.SaveChangesAsync(ct);

        // One alert per new device that is not one of ours. A first scan of a site reports everything as new, so it
        // raises a single summary alert instead.
        var unknown = added.Where(a => a.ManagedDeviceId is null && !a.IsGateway).ToList();
        var firstScan = existing.Count == 0 && !await db.NetworkDevices.IgnoreQueryFilters()
            .AnyAsync(x => x.PartnerId == device.PartnerId && x.SiteId == device.SiteId && x.FirstSeenAt < now, ct);
        if (unknown.Count > 0 && firstScan)
        {
            await alerts.RaiseAsync(device, AlertTypes.NetworkUnknownDevice, $"network-baseline:{device.SiteId:N}",
                $"First network scan: {unknown.Count} unknown devices", "Review them on the Network page and approve or block each one.", ct);
        }
        else
        {
            foreach (var n in unknown.Take(20))
            {
                await alerts.RaiseAsync(device, AlertTypes.NetworkUnknownDevice, $"network:{n.Mac}",
                    $"New device on the network: {n.Hostname ?? n.Mac} ({n.Ip})",
                    $"MAC {n.Mac}{(n.Randomized ? " (private address, typically a phone or laptop)" : "")}, first seen by {device.Hostname}.", ct);
            }
        }
    }
}

public static class NetworkEndpoints
{
    public sealed record ScanRequest(Guid? SiteId, Guid? DeviceId);
    public sealed record StatusRequest(string? Status, string? Note);
    public sealed record BulkStatusRequest(Guid[]? Ids, string? Status);

    private static NetworkDeviceStatus? ParseStatus(string? s) => s?.Trim().ToLowerInvariant() switch
    {
        "unknown" => NetworkDeviceStatus.Unknown,
        "approved" => NetworkDeviceStatus.Approved,
        "blocked" => NetworkDeviceStatus.Blocked,
        _ => null,
    };

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/network/devices", async (Guid? organizationId, Guid? siteId, string? status, string? search, int? page, int? pageSize, Ctx c, CancellationToken ct) =>
        {
            var (skip, take, p) = Api.Paging(page, pageSize);
            var q = c.Db.NetworkDevices.AsNoTracking().Where(n => (organizationId == null || n.OrganizationId == organizationId) && (siteId == null || n.SiteId == siteId));
            var counts = await q.GroupBy(n => n.Status).Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.Count, ct);
            var lastScanAt = await q.MaxAsync(n => (DateTimeOffset?)n.LastSeenAt, ct);
            if (ParseStatus(status) is { } st)
            {
                q = q.Where(n => n.Status == st);
            }
            if (!string.IsNullOrWhiteSpace(search))
            {
                var like = "%" + Api.LikeLiteral(search.Trim().ToLowerInvariant()) + "%";
                q = q.Where(n => EF.Functions.Like(n.Mac, like, Api.LikeEscape) || EF.Functions.Like(n.Ip, like, Api.LikeEscape)
                    || (n.Hostname != null && EF.Functions.ILike(n.Hostname, like, Api.LikeEscape)) || (n.Vendor != null && EF.Functions.ILike(n.Vendor, like, Api.LikeEscape)));
            }
            var total = await q.CountAsync(ct);
            var rows = await q.OrderBy(n => n.Status == NetworkDeviceStatus.Unknown ? 0 : n.Status == NetworkDeviceStatus.Blocked ? 1 : 2)
                .ThenByDescending(n => n.LastSeenAt).ThenBy(n => n.Mac).Skip(skip).Take(take).ToListAsync(ct);
            var deviceIds = rows.SelectMany(r => new[] { r.ManagedDeviceId, r.SeenByDeviceId }).OfType<Guid>().Distinct().ToList();
            var hostnames = await c.Db.Devices.AsNoTracking().Where(d => deviceIds.Contains(d.Id)).ToDictionaryAsync(d => d.Id, d => d.Hostname, ct);
            var sites = await c.Db.Sites.AsNoTracking().ToDictionaryAsync(s => s.Id, s => s.Name, ct);
            return Results.Ok(new
            {
                total, page = p, pageSize = take, lastScanAt,
                counts = new
                {
                    unknown = counts.GetValueOrDefault(NetworkDeviceStatus.Unknown), approved = counts.GetValueOrDefault(NetworkDeviceStatus.Approved),
                    blocked = counts.GetValueOrDefault(NetworkDeviceStatus.Blocked),
                },
                items = rows.Select(n => new
                {
                    n.Id, n.OrganizationId, n.SiteId, siteName = sites.GetValueOrDefault(n.SiteId), n.Mac, n.Ip, n.Hostname, n.Vendor, n.Randomized, n.IsGateway,
                    n.FirstSeenAt, n.LastSeenAt, status = n.Status.ToString().ToLowerInvariant(), n.Note, n.StatusChangedAt, n.StatusChangedBy,
                    n.ManagedDeviceId, managedHostname = n.ManagedDeviceId is { } m ? hostnames.GetValueOrDefault(m) : null,
                    n.SeenByDeviceId, seenByHostname = n.SeenByDeviceId is { } s ? hostnames.GetValueOrDefault(s) : null,
                }),
            });
        }).RequirePermission(Permissions.NetworkRead);

        api.MapPost("/network/scan", async (ScanRequest req, Ctx c, JobService jobs, CancellationToken ct) =>
        {
            Device? device;
            if (req.DeviceId is { } id)
            {
                device = await c.Db.Devices.FirstOrDefaultAsync(d => d.Id == id, ct);
                if (device is null)
                {
                    return Api.NotFound();
                }
                if (device.Status != DeviceStatus.Active)
                {
                    return Api.Conflict("This device is revoked.");
                }
            }
            else if (req.SiteId is { } siteId)
            {
                if (!await c.Db.Sites.AnyAsync(s => s.Id == siteId, ct))
                {
                    return Api.NotFound();
                }
                // The scanner: an online device of the site with an agent that can scan, most recently seen first.
                device = await c.Db.Devices.Where(d => d.SiteId == siteId && d.Status == DeviceStatus.Active && d.IsOnline && d.Capabilities.Contains(JobKinds.NetworkScan))
                    .OrderByDescending(d => d.LastSeenAt).FirstOrDefaultAsync(ct);
                if (device is null)
                {
                    return Api.Conflict("No online device in this site can scan the network. Update the agent or bring a device online.");
                }
            }
            else
            {
                return Api.BadRequest("siteId or deviceId is required.");
            }
            var created = await jobs.CreateAsync(new NewJob("Network scan", JobKinds.NetworkScan, new JobTarget(DeviceIds: [device.Id]), new { resolveNames = true }, 300),
                [device], c.Who.PartnerId, c.Who.UserId, c.Who.Name, ct);
            await c.Audit("network.scan", organizationId: device.OrganizationId, deviceId: device.Id, targetType: "job", targetId: created.Job.Id, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id, deviceId = device.Id, hostname = device.Hostname });
        }).RequirePermission(Permissions.NetworkManage);

        api.MapPost("/network/devices/{id:guid}/status", async (Guid id, StatusRequest req, Ctx c, NetworkEnforcer enforcer, CancellationToken ct) =>
        {
            var row = await c.Db.NetworkDevices.FirstOrDefaultAsync(n => n.Id == id, ct);
            if (row is null)
            {
                return Api.NotFound();
            }
            if (ParseStatus(req.Status) is not { } status)
            {
                return Api.BadRequest("status must be unknown, approved or blocked.");
            }
            if ((req.Note?.Length ?? 0) > 500)
            {
                return Api.BadRequest("The note is limited to 500 characters.");
            }
            var from = row.Status;
            row.Status = status;
            row.Note = string.IsNullOrWhiteSpace(req.Note) ? row.Note : req.Note.Trim();
            row.StatusChangedAt = c.Now;
            row.StatusChangedBy = c.Who.Name;
            await c.Db.SaveChangesAsync(ct);
            var controller = from == status ? "unchanged" : await enforcer.ApplyAsync([row], ct);
            await c.Audit("network_device.status", organizationId: row.OrganizationId, targetType: "network_device", targetId: row.Id,
                detail: new { row.Mac, row.Ip, from = from.ToString(), to = status.ToString(), controller }, ct: ct);
            return Results.Ok(new { controller });
        }).RequirePermission(Permissions.NetworkManage);

        api.MapPost("/network/devices/status", async (BulkStatusRequest req, Ctx c, NetworkEnforcer enforcer, CancellationToken ct) =>
        {
            var ids = (req.Ids ?? []).Distinct().ToList();
            if (ids.Count is 0 or > 500)
            {
                return Api.BadRequest("Give between 1 and 500 ids.");
            }
            // Load first: ids outside the caller's scope are simply not found.
            var rows = await c.Db.NetworkDevices.Where(n => ids.Contains(n.Id)).ToListAsync(ct);
            if (rows.Count != ids.Count)
            {
                return Api.NotFound();
            }
            if (ParseStatus(req.Status) is not { } status)
            {
                return Api.BadRequest("status must be unknown, approved or blocked.");
            }
            foreach (var row in rows)
            {
                row.Status = status;
                row.StatusChangedAt = c.Now;
                row.StatusChangedBy = c.Who.Name;
            }
            await c.Db.SaveChangesAsync(ct);
            var controller = await enforcer.ApplyAsync(rows, ct);
            foreach (var org in rows.GroupBy(r => r.OrganizationId))
            {
                await c.Audit("network_device.status", organizationId: org.Key, targetType: "network_device",
                    detail: new { count = org.Count(), macs = org.Select(r => r.Mac).Take(100), to = status.ToString(), controller }, ct: ct);
            }
            return Results.Ok(new { updated = rows.Count, controller });
        }).RequirePermission(Permissions.NetworkManage);

        api.MapDelete("/network/devices/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var row = await c.Db.NetworkDevices.FirstOrDefaultAsync(n => n.Id == id, ct);
            if (row is null)
            {
                return Api.NotFound();
            }
            c.Db.NetworkDevices.Remove(row);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("network_device.delete", organizationId: row.OrganizationId, targetType: "network_device", targetId: row.Id, detail: new { row.Mac, row.Ip }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.NetworkManage);
    }
}
