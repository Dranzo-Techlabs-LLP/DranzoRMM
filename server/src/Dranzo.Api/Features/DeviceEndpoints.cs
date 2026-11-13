using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Domain;
using Dranzo.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

/// <summary>Device selection used by the device list, saved filters and job targeting.</summary>
public sealed record DeviceFilter(Guid? OrganizationId = null, Guid? SiteId = null, Guid? GroupId = null, string? Os = null, bool? Online = null, string? Search = null, string? Tag = null)
{
    public IQueryable<Device> Apply(IQueryable<Device> q)
    {
        if (OrganizationId is { } org)
        {
            q = q.Where(d => d.OrganizationId == org);
        }
        if (SiteId is { } site)
        {
            q = q.Where(d => d.SiteId == site);
        }
        if (GroupId is { } group)
        {
            q = q.Where(d => d.GroupId == group);
        }
        if (!string.IsNullOrWhiteSpace(Os))
        {
            q = q.Where(d => d.Os == Os);
        }
        if (Online is { } online)
        {
            q = q.Where(d => d.IsOnline == online);
        }
        if (!string.IsNullOrWhiteSpace(Tag))
        {
            q = q.Where(d => d.Tags.Contains(Tag));
        }
        if (!string.IsNullOrWhiteSpace(Search))
        {
            var like = "%" + Api.LikeLiteral(Search.Trim()) + "%";
            q = q.Where(d => EF.Functions.ILike(d.Hostname, like, Api.LikeEscape) || EF.Functions.ILike(d.Serial, like, Api.LikeEscape) || EF.Functions.ILike(d.Model, like, Api.LikeEscape)
                || EF.Functions.ILike(d.OsName, like, Api.LikeEscape) || (d.ConsoleUser != null && EF.Functions.ILike(d.ConsoleUser, like, Api.LikeEscape)));
        }
        return q;
    }
}

public static class DeviceEndpoints
{
    public sealed record TokenRequest(Guid SiteId, Guid? GroupId, string? Name, int? ExpiresInHours, int? MaxUses);

    public sealed record DeviceUpdateRequest(string[]? Tags, Guid? GroupId, bool? ClearGroup, Guid? SiteId);

    public static void Map(RouteGroupBuilder api)
    {
        // ----- Enrollment tokens -----
        api.MapGet("/enrollment-tokens", async (Guid? organizationId, Ctx c, CancellationToken ct) =>
        {
            var tokens = await c.Db.EnrollmentTokens.AsNoTracking().Where(t => organizationId == null || t.OrganizationId == organizationId).OrderByDescending(t => t.CreatedAt).ToListAsync(ct);
            // Names of the sites and groups these (already scope-filtered) tokens point at.
            var siteIds = tokens.Select(t => t.SiteId).Distinct().ToList();
            var groupIds = tokens.Where(t => t.GroupId != null).Select(t => t.GroupId!.Value).Distinct().ToList();
            var sites = await c.Db.Sites.IgnoreQueryFilters().AsNoTracking().Where(s => s.PartnerId == c.Who.PartnerId && siteIds.Contains(s.Id)).ToDictionaryAsync(s => s.Id, s => s.Name, ct);
            var groups = await c.Db.DeviceGroups.IgnoreQueryFilters().AsNoTracking().Where(g => g.PartnerId == c.Who.PartnerId && groupIds.Contains(g.Id)).ToDictionaryAsync(g => g.Id, g => g.Name, ct);
            return Results.Ok(tokens.Select(t => new
            {
                t.Id, t.OrganizationId, t.SiteId, siteName = sites.GetValueOrDefault(t.SiteId), t.GroupId, groupName = t.GroupId is { } g ? groups.GetValueOrDefault(g) : null,
                t.Name, t.TokenPrefix, t.ExpiresAt, t.MaxUses, t.Uses, t.RevokedAt, t.CreatedAt,
            }));
        }).RequirePermission(Permissions.EnrollmentManage);

        // Sites and groups an enrollment manager may create tokens for (so the UI does not also need tenants.read).
        api.MapGet("/enrollment-tokens/targets", async (Ctx c, CancellationToken ct) => Results.Ok(new
        {
            sites = await c.Db.Sites.AsNoTracking().OrderBy(s => s.Name).Select(s => new { s.Id, s.OrganizationId, s.Name }).ToListAsync(ct),
            groups = await c.Db.DeviceGroups.AsNoTracking().OrderBy(g => g.Name).Select(g => new { g.Id, g.SiteId, g.Name }).ToListAsync(ct),
        })).RequirePermission(Permissions.EnrollmentManage);

        api.MapPost("/enrollment-tokens", async (TokenRequest req, Ctx c, CancellationToken ct) =>
        {
            if (Api.CleanName(req.Name) is not { } name)
            {
                return Api.BadRequest("Name is required.");
            }
            var hours = req.ExpiresInHours ?? 72;
            var maxUses = req.MaxUses ?? 25;
            if (hours is < 1 or > 24 * 90 || maxUses is < 1 or > 10000)
            {
                return Api.BadRequest("expiresInHours must be 1..2160 and maxUses 1..10000.");
            }
            var site = await c.Db.Sites.FirstOrDefaultAsync(s => s.Id == req.SiteId, ct);
            if (site is null || !c.Tenant.CoversOrganization(site.OrganizationId))
            {
                return Api.NotFound();
            }
            if (req.GroupId is { } gid && !await c.Db.DeviceGroups.AnyAsync(g => g.Id == gid && g.SiteId == site.Id, ct))
            {
                return Api.BadRequest("Group does not belong to the site.");
            }
            var secret = Hashing.NewToken("dz_enroll_");
            var token = new EnrollmentToken
            {
                Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = site.OrganizationId, SiteId = site.Id, GroupId = req.GroupId,
                Name = name, TokenHash = Hashing.Sha256Hex(secret), TokenPrefix = secret[..18], ExpiresAt = c.Now.AddHours(hours), MaxUses = maxUses,
                CreatedByUserId = c.Who.UserId, CreatedAt = c.Now,
            };
            c.Db.EnrollmentTokens.Add(token);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("enrollment_token.create", organizationId: token.OrganizationId, targetType: "enrollment_token", targetId: token.Id,
                detail: new { name, token.ExpiresAt, maxUses }, ct: ct);
            // The secret is returned exactly once; only its hash is stored.
            return Results.Created($"/api/v1/enrollment-tokens/{token.Id}", new { token.Id, token = secret, token.ExpiresAt, token.MaxUses });
        }).RequirePermission(Permissions.EnrollmentManage);

        api.MapDelete("/enrollment-tokens/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var token = await c.Db.EnrollmentTokens.FirstOrDefaultAsync(t => t.Id == id, ct);
            if (token is null)
            {
                return Api.NotFound();
            }
            token.RevokedAt ??= c.Now;
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("enrollment_token.revoke", organizationId: token.OrganizationId, targetType: "enrollment_token", targetId: id, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.EnrollmentManage);

        // Public trust anchors and install commands for packaging / manual installs.
        api.MapGet("/agent/install-info", (CertificateAuthority ca, ICommandSigner signer, IOptions<DranzoOptions> opt) =>
        {
            var url = opt.Value.PublicAgentUrl;
            return Results.Ok(new
            {
                serverUrl = url,
                caCertificatePem = ca.CaCertificatePem,
                trust = new { commandKeys = new[] { new { kid = signer.KeyId, alg = "ed25519", publicKey = Convert.ToBase64String(signer.PublicKey) } } },
                // Plain-binary commands work today. Package commands apply once signed installers are published
                // (Releases → installers). ca.pem and trust.json are the two files shown next to these commands; the
                // agent refuses to talk to any server it cannot verify with them.
                commands = new
                {
                    windows = $"dranzo-agent.exe install --server {url} --token <token> --ca-file ca.pem --trust-file trust.json   (elevated prompt)",
                    macos = $"sudo ./dranzo-agent install --server {url} --token <token> --ca-file ca.pem --trust-file trust.json",
                    linux = $"sudo ./dranzo-agent install --server {url} --token <token> --ca-file ca.pem --trust-file trust.json",
                    windowsMsi = $"msiexec /i DranzoAgent-<arch>.msi /qn SERVERURL=\"{url}\" ENROLLTOKEN=\"<token>\"",
                    linuxDeb = $"sudo dpkg -i dranzo-agent_<version>_<arch>.deb && sudo dranzo-agent install --server {url} --token <token> --ca-file ca.pem --trust-file trust.json",
                    linuxRpm = $"sudo rpm -i dranzo-agent-<version>-1.<x86_64|aarch64>.rpm && sudo dranzo-agent install --server {url} --token <token> --ca-file ca.pem --trust-file trust.json",
                    check = $"curl -k {url}/agent/v1/healthz   (Windows: curl.exe -k ...; must print {{\"status\":\"ok\"}})",
                },
            });
        }).RequirePermission(Permissions.EnrollmentManage);

        // ----- Devices -----
        api.MapGet("/devices", async ([AsParameters] DeviceListQuery query, Ctx c, CancellationToken ct) =>
        {
            var (skip, take, page) = Api.Paging(query.Page, query.PageSize);
            var q = new DeviceFilter(query.OrganizationId, query.SiteId, query.GroupId, query.Os, query.Online, query.Search, query.Tag).Apply(c.Db.Devices.AsNoTracking());
            if (query.PendingReboot is { } reboot)
            {
                q = q.Where(d => d.PendingReboot == reboot);
            }
            var total = await q.CountAsync(ct);
            var online = await q.CountAsync(d => d.IsOnline, ct);
            q = query.Sort switch
            {
                "lastSeen" => q.OrderByDescending(d => d.LastSeenAt).ThenBy(d => d.Id),
                "os" => q.OrderBy(d => d.Os).ThenBy(d => d.Hostname).ThenBy(d => d.Id),
                "status" => q.OrderBy(d => d.IsOnline).ThenBy(d => d.Hostname).ThenBy(d => d.Id),
                _ => q.OrderBy(d => d.Hostname).ThenBy(d => d.Id),
            };
            var items = await q.Skip(skip).Take(take).Select(d => new
            {
                d.Id, d.OrganizationId, d.SiteId, d.GroupId, d.Hostname, d.Os, d.OsName, d.OsVersion, d.Arch, d.Serial, d.Model, d.AgentVersion,
                status = d.Status.ToString().ToLowerInvariant(), d.IsOnline, d.LastSeenAt, d.Tags, d.ConsoleUser, d.PendingReboot, d.CpuPercent, d.MemUsedPercent,
            }).ToListAsync(ct);
            return Results.Ok(new { total, online, page, pageSize = take, items });
        }).RequirePermission(Permissions.DevicesRead);

        api.MapGet("/devices/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var d = await c.Db.Devices.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
            if (d is null)
            {
                return Api.NotFound();
            }
            var inventory = await c.Db.InventorySnapshots.AsNoTracking().Where(i => i.DeviceId == id && i.IsLatest)
                .Select(i => new { i.CollectedAt, i.DataJson }).FirstOrDefaultAsync(ct);
            return Results.Ok(new
            {
                d.Id, d.OrganizationId, d.SiteId, d.GroupId, d.Hostname, d.Os, d.OsName, d.OsVersion, d.Arch, d.Serial, d.Manufacturer, d.Model, d.AgentVersion,
                d.MachineId, status = d.Status.ToString().ToLowerInvariant(), d.EnrolledAt, d.IsOnline, d.LastSeenAt, d.Tags, d.ConsoleUser, d.PendingReboot,
                d.CpuPercent, d.MemUsedPercent, d.AgentRssBytes, d.CertNotAfter, d.PossibleDuplicateOfDeviceId, d.Capabilities, d.LastIp, d.UninstallCodeSet,
                d.LastPatchScanAt, d.LastPatchInstallAt, meshInstalled = d.MeshNodeId != null, d.MacAddresses, d.DefaultGateway, d.WifiSsid,
                inventoryCollectedAt = inventory?.CollectedAt,
                inventory = inventory is null ? null : System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement?>(inventory.DataJson),
            });
        }).RequirePermission(Permissions.DevicesRead);

        api.MapPatch("/devices/{id:guid}", async (Guid id, DeviceUpdateRequest req, Ctx c, CancellationToken ct) =>
        {
            var d = await c.Db.Devices.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (d is null)
            {
                return Api.NotFound();
            }
            if (req.Tags is not null)
            {
                var tags = req.Tags.Select(t => t.Trim()).Where(t => t.Length > 0).Distinct().ToArray();
                if (tags.Length > 32 || tags.Any(t => t.Length > 48 || t.Any(char.IsControl)))
                {
                    return Api.BadRequest("At most 32 tags of up to 48 characters.");
                }
                d.Tags = tags;
            }
            if (req.SiteId is { } siteId && siteId != d.SiteId)
            {
                // Moves stay inside the organization, and the caller must have scope over the destination too.
                var site = await c.Db.Sites.FirstOrDefaultAsync(s => s.Id == siteId && s.OrganizationId == d.OrganizationId, ct);
                if (site is null || !c.Tenant.CoversSite(site.OrganizationId, site.Id))
                {
                    return Api.BadRequest("Destination site not found in this organization.");
                }
                d.SiteId = siteId;
                d.GroupId = null;
            }
            if (req.ClearGroup == true)
            {
                d.GroupId = null;
            }
            else if (req.GroupId is { } groupId)
            {
                if (!await c.Db.DeviceGroups.AnyAsync(g => g.Id == groupId && g.SiteId == d.SiteId, ct))
                {
                    return Api.BadRequest("Group not found in the device's site.");
                }
                d.GroupId = groupId;
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("device.update", organizationId: d.OrganizationId, deviceId: id, targetType: "device", targetId: id,
                detail: new { d.Tags, d.SiteId, d.GroupId }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.DevicesManage);

        // Revoking invalidates the device certificate immediately and drops the connection.
        api.MapPost("/devices/{id:guid}/revoke", async (Guid id, Ctx c, AgentRegistry registry, CancellationToken ct) =>
        {
            var d = await c.Db.Devices.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (d is null)
            {
                return Api.NotFound();
            }
            d.Status = DeviceStatus.Revoked;
            d.CertThumbprint = null;
            d.PrevCertThumbprint = null;
            d.IsOnline = false;
            await c.Db.SaveChangesAsync(ct);
            registry.Disconnect(id, "revoked");
            await c.Audit("device.revoke", organizationId: d.OrganizationId, deviceId: id, targetType: "device", targetId: id, detail: new { d.Hostname }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.DevicesRevoke).RequireStepUp();

        api.MapDelete("/devices/{id:guid}", async (Guid id, Ctx c, AgentRegistry registry, CancellationToken ct) =>
        {
            var d = await c.Db.Devices.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (d is null)
            {
                return Api.NotFound();
            }
            c.Db.Devices.Remove(d);
            await c.Db.SaveChangesAsync(ct);
            registry.Disconnect(id, "deleted");
            await c.Audit("device.delete", organizationId: d.OrganizationId, deviceId: id, targetType: "device", targetId: id, detail: new { d.Hostname }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.DevicesRevoke).RequireStepUp();
    }

    public sealed class DeviceListQuery
    {
        public Guid? OrganizationId { get; set; }
        public Guid? SiteId { get; set; }
        public Guid? GroupId { get; set; }
        public string? Os { get; set; }
        public bool? Online { get; set; }
        public string? Search { get; set; }
        public string? Tag { get; set; }
        public bool? PendingReboot { get; set; }
        public string? Sort { get; set; }
        public int? Page { get; set; }
        public int? PageSize { get; set; }
    }
}
