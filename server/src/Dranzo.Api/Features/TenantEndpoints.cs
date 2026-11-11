using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Domain;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

public static class TenantEndpoints
{
    public sealed record OrgRequest(string? Name, string? TimeZone, string? ConsentMode, bool? RequireSignedPowerShell);

    public sealed record SiteRequest(Guid OrganizationId, string? Name);

    public sealed record GroupRequest(Guid SiteId, string? Name, string? UpdateRing);

    public sealed record RenameRequest(string? Name, string? UpdateRing);

    private static readonly string[] Rings = ["test", "pilot", "all"];

    public static void Map(RouteGroupBuilder api)
    {
        // ----- Organizations -----
        api.MapGet("/organizations", async (Ctx c, CancellationToken ct) =>
        {
            var orgs = await c.Db.Organizations.AsNoTracking().OrderBy(o => o.Name).ToListAsync(ct);
            var counts = await c.Db.Devices.GroupBy(d => d.OrganizationId)
                .Select(g => new { g.Key, Total = g.Count(), Online = g.Count(d => d.IsOnline) }).ToDictionaryAsync(x => x.Key, ct);
            return Results.Ok(orgs.Select(o => new
            {
                o.Id, o.Name, o.TimeZone, consentMode = o.ConsentMode.ToString().ToLowerInvariant(), o.RequireSignedPowerShell, o.CreatedAt,
                deviceCount = counts.GetValueOrDefault(o.Id)?.Total ?? 0,
                onlineCount = counts.GetValueOrDefault(o.Id)?.Online ?? 0,
            }));
        }).RequirePermission(Permissions.TenantsRead);

        api.MapPost("/organizations", async (OrgRequest req, Ctx c, CancellationToken ct) =>
        {
            if (Api.CleanName(req.Name) is not { } name)
            {
                return Api.BadRequest("Name is required (max 120 characters).");
            }
            if (!TryTimeZone(req.TimeZone ?? "UTC", out var tz))
            {
                return Api.BadRequest("Unknown time zone.");
            }
            if (!TryConsent(req.ConsentMode ?? "require", out var consent))
            {
                return Api.BadRequest("consentMode must be none, notify or require.");
            }
            var org = new Organization
            {
                Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, Name = name, TimeZone = tz, ConsentMode = consent,
                RequireSignedPowerShell = req.RequireSignedPowerShell ?? false, CreatedAt = c.Now,
            };
            c.Db.Organizations.Add(org);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("organization.create", organizationId: org.Id, targetType: "organization", targetId: org.Id, detail: new { name }, ct: ct);
            return Results.Created($"/api/v1/organizations/{org.Id}", new { org.Id, org.Name });
        }).RequirePermission(Permissions.TenantsManage, partnerWide: true);

        api.MapPatch("/organizations/{id:guid}", async (Guid id, OrgRequest req, Ctx c, CancellationToken ct) =>
        {
            var org = await c.Db.Organizations.FirstOrDefaultAsync(o => o.Id == id, ct);
            if (org is null || !c.Tenant.CoversOrganization(id))
            {
                return Api.NotFound();
            }
            if (req.Name is not null)
            {
                if (Api.CleanName(req.Name) is not { } name)
                {
                    return Api.BadRequest("Invalid name.");
                }
                org.Name = name;
            }
            if (req.TimeZone is not null)
            {
                if (!TryTimeZone(req.TimeZone, out var tz))
                {
                    return Api.BadRequest("Unknown time zone.");
                }
                org.TimeZone = tz;
            }
            if (req.ConsentMode is not null)
            {
                if (!TryConsent(req.ConsentMode, out var consent))
                {
                    return Api.BadRequest("consentMode must be none, notify or require.");
                }
                org.ConsentMode = consent;
            }
            org.RequireSignedPowerShell = req.RequireSignedPowerShell ?? org.RequireSignedPowerShell;
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("organization.update", organizationId: id, targetType: "organization", targetId: id,
                detail: new { org.Name, org.TimeZone, consentMode = org.ConsentMode.ToString(), org.RequireSignedPowerShell }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.TenantsManage);

        api.MapDelete("/organizations/{id:guid}", async (Guid id, Ctx c, AgentRegistry registry, CancellationToken ct) =>
        {
            var org = await c.Db.Organizations.FirstOrDefaultAsync(o => o.Id == id, ct);
            if (org is null)
            {
                return Api.NotFound();
            }
            // Deleting an organization revokes every device certificate and removes its operational data.
            // Audit events are kept.
            var deviceIds = await c.Db.Devices.Where(d => d.OrganizationId == id).Select(d => d.Id).ToListAsync(ct);
            await c.Db.Devices.Where(d => d.OrganizationId == id).ExecuteDeleteAsync(ct);
            await c.Db.EnrollmentTokens.Where(t => t.OrganizationId == id).ExecuteDeleteAsync(ct);
            await c.Db.DeviceGroups.Where(t => t.OrganizationId == id).ExecuteDeleteAsync(ct);
            await c.Db.Sites.Where(t => t.OrganizationId == id).ExecuteDeleteAsync(ct);
            await c.Db.RoleAssignments.Where(a => a.ScopeType == ScopeType.Organization && a.ScopeId == id).ExecuteDeleteAsync(ct);
            org.DeletedAt = c.Now;
            await c.Db.SaveChangesAsync(ct);
            foreach (var deviceId in deviceIds)
            {
                registry.Disconnect(deviceId, "organization deleted");
            }
            await c.Audit("organization.delete", organizationId: id, targetType: "organization", targetId: id, detail: new { org.Name, devices = deviceIds.Count }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.TenantsManage, partnerWide: true).RequireStepUp();

        // ----- Sites -----
        api.MapGet("/sites", async (Guid? organizationId, Ctx c, CancellationToken ct) =>
            Results.Ok(await c.Db.Sites.AsNoTracking().Where(s => organizationId == null || s.OrganizationId == organizationId)
                .OrderBy(s => s.Name).Select(s => new { s.Id, s.OrganizationId, s.Name }).ToListAsync(ct)))
            .RequirePermission(Permissions.TenantsRead);

        api.MapPost("/sites", async (SiteRequest req, Ctx c, CancellationToken ct) =>
        {
            if (Api.CleanName(req.Name) is not { } name)
            {
                return Api.BadRequest("Name is required.");
            }
            if (!c.Tenant.CoversOrganization(req.OrganizationId) || !await c.Db.Organizations.AnyAsync(o => o.Id == req.OrganizationId, ct))
            {
                return Api.NotFound();
            }
            var site = new Site { Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = req.OrganizationId, Name = name, CreatedAt = c.Now };
            c.Db.Sites.Add(site);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("site.create", organizationId: site.OrganizationId, targetType: "site", targetId: site.Id, detail: new { name }, ct: ct);
            return Results.Created($"/api/v1/sites/{site.Id}", new { site.Id, site.Name });
        }).RequirePermission(Permissions.TenantsManage);

        api.MapPatch("/sites/{id:guid}", async (Guid id, RenameRequest req, Ctx c, CancellationToken ct) =>
        {
            var site = await c.Db.Sites.FirstOrDefaultAsync(s => s.Id == id, ct);
            if (site is null || !c.Tenant.CoversOrganization(site.OrganizationId))
            {
                return Api.NotFound();
            }
            if (Api.CleanName(req.Name) is not { } name)
            {
                return Api.BadRequest("Invalid name.");
            }
            site.Name = name;
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("site.update", organizationId: site.OrganizationId, targetType: "site", targetId: id, detail: new { name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.TenantsManage);

        api.MapDelete("/sites/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var site = await c.Db.Sites.FirstOrDefaultAsync(s => s.Id == id, ct);
            if (site is null || !c.Tenant.CoversOrganization(site.OrganizationId))
            {
                return Api.NotFound();
            }
            if (await c.Db.Devices.IgnoreQueryFilters().AnyAsync(d => d.SiteId == id, ct))
            {
                return Api.Conflict("Move or remove the site's devices first.");
            }
            await c.Db.DeviceGroups.Where(g => g.SiteId == id).ExecuteDeleteAsync(ct);
            await c.Db.EnrollmentTokens.Where(t => t.SiteId == id).ExecuteDeleteAsync(ct);
            c.Db.Sites.Remove(site);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("site.delete", organizationId: site.OrganizationId, targetType: "site", targetId: id, detail: new { site.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.TenantsManage);

        // ----- Device groups -----
        api.MapGet("/groups", async (Guid? organizationId, Guid? siteId, Ctx c, CancellationToken ct) =>
            Results.Ok(await c.Db.DeviceGroups.AsNoTracking()
                .Where(g => (organizationId == null || g.OrganizationId == organizationId) && (siteId == null || g.SiteId == siteId))
                .OrderBy(g => g.Name).Select(g => new { g.Id, g.OrganizationId, g.SiteId, g.Name, g.UpdateRing }).ToListAsync(ct)))
            .RequirePermission(Permissions.TenantsRead);

        api.MapPost("/groups", async (GroupRequest req, Ctx c, CancellationToken ct) =>
        {
            if (Api.CleanName(req.Name) is not { } name)
            {
                return Api.BadRequest("Name is required.");
            }
            var ring = req.UpdateRing ?? "all";
            if (!Rings.Contains(ring))
            {
                return Api.BadRequest("updateRing must be test, pilot or all.");
            }
            var site = await c.Db.Sites.FirstOrDefaultAsync(s => s.Id == req.SiteId, ct);
            if (site is null || !c.Tenant.CoversSite(site.OrganizationId, site.Id))
            {
                return Api.NotFound();
            }
            var group = new DeviceGroup { Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = site.OrganizationId, SiteId = site.Id, Name = name, UpdateRing = ring, CreatedAt = c.Now };
            c.Db.DeviceGroups.Add(group);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("group.create", organizationId: group.OrganizationId, targetType: "group", targetId: group.Id, detail: new { name, ring }, ct: ct);
            return Results.Created($"/api/v1/groups/{group.Id}", new { group.Id, group.Name });
        }).RequirePermission(Permissions.TenantsManage);

        api.MapPatch("/groups/{id:guid}", async (Guid id, RenameRequest req, Ctx c, CancellationToken ct) =>
        {
            var group = await c.Db.DeviceGroups.FirstOrDefaultAsync(g => g.Id == id, ct);
            if (group is null || !c.Tenant.CoversSite(group.OrganizationId, group.SiteId))
            {
                return Api.NotFound();
            }
            if (req.Name is not null)
            {
                if (Api.CleanName(req.Name) is not { } name)
                {
                    return Api.BadRequest("Invalid name.");
                }
                group.Name = name;
            }
            if (req.UpdateRing is not null)
            {
                if (!Rings.Contains(req.UpdateRing))
                {
                    return Api.BadRequest("updateRing must be test, pilot or all.");
                }
                group.UpdateRing = req.UpdateRing;
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("group.update", organizationId: group.OrganizationId, targetType: "group", targetId: id, detail: new { group.Name, group.UpdateRing }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.TenantsManage);

        api.MapDelete("/groups/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var group = await c.Db.DeviceGroups.FirstOrDefaultAsync(g => g.Id == id, ct);
            if (group is null || !c.Tenant.CoversSite(group.OrganizationId, group.SiteId))
            {
                return Api.NotFound();
            }
            await c.Db.Devices.IgnoreQueryFilters().Where(d => d.GroupId == id).ExecuteUpdateAsync(s => s.SetProperty(d => d.GroupId, (Guid?)null), ct);
            c.Db.DeviceGroups.Remove(group);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("group.delete", organizationId: group.OrganizationId, targetType: "group", targetId: id, detail: new { group.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.TenantsManage);
    }

    public static bool TryTimeZone(string id, out string normalized)
    {
        normalized = id;
        return id.Length <= 64 && TimeZoneInfo.TryFindSystemTimeZoneById(id, out _);
    }

    private static bool TryConsent(string value, out ConsentMode mode) =>
        Enum.TryParse(value, ignoreCase: true, out mode) && Enum.IsDefined(mode) && !int.TryParse(value, out _);
}
