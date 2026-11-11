using System.Net;
using System.Text.Json;
using Dranzo.Api.Auth;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Dranzo.Tests;

[Collection("server")]
public class TenantIsolationTests(ServerFixture fx)
{
    private static List<Guid> Ids(JsonElement array, string property = "id") => [.. array.EnumerateArray().Select(x => x.GetProperty(property).GetGuid())];

    [Fact]
    public async Task Org_technician_sees_and_changes_only_their_organization()
    {
        var a = await fx.SeedOrgAsync("IsoA " + Guid.NewGuid().ToString("N")[..6]);
        var b = await fx.SeedOrgAsync("IsoB " + Guid.NewGuid().ToString("N")[..6]);
        await using var devA = await TestAgent.EnrollAsync(fx, a.Token, "iso-a", connect: false);
        await using var devB = await TestAgent.EnrollAsync(fx, b.Token, "iso-b", connect: false);
        var tech = await fx.CreateUserAsync($"tech-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, a.OrgId);

        Assert.Equal([a.OrgId], Ids(await tech.GetJsonAsync("/api/v1/organizations")));
        Assert.Equal([a.SiteId], Ids(await tech.GetJsonAsync("/api/v1/sites")));
        Assert.Equal([a.GroupId], Ids(await tech.GetJsonAsync("/api/v1/groups")));
        Assert.Equal([devA.DeviceId], Ids((await tech.GetJsonAsync("/api/v1/devices")).GetProperty("items")));
        Assert.Empty(Ids((await tech.GetJsonAsync($"/api/v1/devices?organizationId={b.OrgId}")).GetProperty("items")));
        Assert.Empty(Ids(await tech.GetJsonAsync($"/api/v1/sites?organizationId={b.OrgId}")));
        Assert.All((await tech.GetJsonAsync("/api/v1/enrollment-tokens")).EnumerateArray(), t => Assert.Equal(a.OrgId, t.GetProperty("organizationId").GetGuid()));

        Assert.Equal(HttpStatusCode.NotFound, (await tech.GetAsync($"/api/v1/devices/{devB.DeviceId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PatchAsync($"/api/v1/devices/{devB.DeviceId}", new { tags = new[] { "pwned" } })).StatusCode);

        // Ids of the other organization in request bodies are refused too.
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/enrollment-tokens", new { siteId = b.SiteId, name = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await tech.PatchAsync($"/api/v1/devices/{devA.DeviceId}", new { siteId = b.SiteId })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await tech.PatchAsync($"/api/v1/devices/{devA.DeviceId}", new { groupId = b.GroupId })).StatusCode);
        var stillA = await fx.DbAsync(db => db.Devices.FirstAsync(d => d.Id == devA.DeviceId));
        Assert.Equal(a.SiteId, stillA.SiteId);
        Assert.Empty((await fx.DbAsync(db => db.Devices.FirstAsync(d => d.Id == devB.DeviceId))).Tags);
    }

    [Fact]
    public async Task Org_admin_cannot_create_children_in_another_organization()
    {
        var a = await fx.SeedOrgAsync("ChA " + Guid.NewGuid().ToString("N")[..6]);
        var b = await fx.SeedOrgAsync("ChB " + Guid.NewGuid().ToString("N")[..6]);
        var roleId = await fx.CreateRoleAsync("Org manager " + Guid.NewGuid().ToString("N")[..6], Permissions.TenantsRead, Permissions.TenantsManage, Permissions.EnrollmentManage);
        var roleName = await fx.DbAsync(db => db.Roles.Where(r => r.Id == roleId).Select(r => r.Name).FirstAsync());
        var mgr = await fx.CreateUserAsync($"mgr-{Guid.NewGuid():N}@t.test", roleName, ScopeType.Organization, a.OrgId);

        Assert.Equal(HttpStatusCode.Created, (await mgr.PostAsync("/api/v1/sites", new { organizationId = a.OrgId, name = "ok" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await mgr.PostAsync("/api/v1/sites", new { organizationId = b.OrgId, name = "intruder" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await mgr.PostAsync("/api/v1/groups", new { siteId = b.SiteId, name = "intruder" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await mgr.PatchAsync($"/api/v1/organizations/{b.OrgId}", new { name = "renamed" })).StatusCode);
        // Creating organizations needs partner scope.
        Assert.Equal(HttpStatusCode.Forbidden, (await mgr.PostAsync("/api/v1/organizations", new { name = "new org" })).StatusCode);
        Assert.Equal(1, await fx.DbAsync(db => db.Sites.CountAsync(s => s.OrganizationId == b.OrgId)));
        Assert.Equal(1, await fx.DbAsync(db => db.DeviceGroups.CountAsync(s => s.OrganizationId == b.OrgId)));
    }

    [Fact]
    public async Task Site_and_group_scopes_narrow_device_visibility()
    {
        var o = await fx.SeedOrgAsync("Scope " + Guid.NewGuid().ToString("N")[..6]);
        var admin = await fx.AdminAsync();
        var site2 = (await admin.PostJsonAsync("/api/v1/sites", new { organizationId = o.OrgId, name = "Branch" })).GetProperty("id").GetGuid();
        var token2 = (await admin.PostJsonAsync("/api/v1/enrollment-tokens", new { siteId = site2, name = "branch" })).GetProperty("token").GetString()!;
        var tokenNoGroup = (await admin.PostJsonAsync("/api/v1/enrollment-tokens", new { siteId = o.SiteId, name = "hq no group" })).GetProperty("token").GetString()!;
        await using var inGroup = await TestAgent.EnrollAsync(fx, o.Token, "hq-grouped", connect: false);
        await using var inSiteOnly = await TestAgent.EnrollAsync(fx, tokenNoGroup, "hq-ungrouped", connect: false);
        await using var inBranch = await TestAgent.EnrollAsync(fx, token2, "branch-1", connect: false);

        var siteUser = await fx.CreateUserAsync($"site-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Site, o.SiteId);
        Assert.Equal(new[] { inGroup.DeviceId, inSiteOnly.DeviceId }.Order(), Ids((await siteUser.GetJsonAsync("/api/v1/devices")).GetProperty("items")).Order());
        Assert.Equal(HttpStatusCode.NotFound, (await siteUser.GetAsync($"/api/v1/devices/{inBranch.DeviceId}")).StatusCode);
        Assert.Equal([o.SiteId], Ids(await siteUser.GetJsonAsync("/api/v1/sites")));
        Assert.Equal([o.OrgId], Ids(await siteUser.GetJsonAsync("/api/v1/organizations")));
        // Site scope does not allow moving a device to a site outside the scope.
        Assert.Equal(HttpStatusCode.BadRequest, (await siteUser.PatchAsync($"/api/v1/devices/{inGroup.DeviceId}", new { siteId = site2 })).StatusCode);

        var groupUser = await fx.CreateUserAsync($"group-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Group, o.GroupId);
        Assert.Equal([inGroup.DeviceId], Ids((await groupUser.GetJsonAsync("/api/v1/devices")).GetProperty("items")));
        Assert.Equal(HttpStatusCode.NotFound, (await groupUser.GetAsync($"/api/v1/devices/{inSiteOnly.DeviceId}")).StatusCode);
    }

    [Fact]
    public async Task Scope_is_per_permission_not_per_user()
    {
        var a = await fx.SeedOrgAsync("PermA " + Guid.NewGuid().ToString("N")[..6]);
        var b = await fx.SeedOrgAsync("PermB " + Guid.NewGuid().ToString("N")[..6]);
        await using var devA = await TestAgent.EnrollAsync(fx, a.Token, "perm-a", connect: false);
        await using var devB = await TestAgent.EnrollAsync(fx, b.Token, "perm-b", connect: false);
        // Technician in A, read-only viewer in B.
        var user = await fx.CreateUserAsync($"mixed-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, a.OrgId);
        var admin = await fx.AdminAsync();
        var viewerRole = (await admin.GetJsonAsync("/api/v1/roles")).EnumerateArray().First(r => r.GetProperty("name").GetString() == BuiltInRoles.OrganizationViewer).GetProperty("id").GetGuid();
        await admin.StepUpAsync();
        await admin.PostJsonAsync("/api/v1/role-assignments", new { userId = user.UserId, roleId = viewerRole, scopeType = "Organization", scopeId = b.OrgId });

        Assert.Equal(new[] { devA.DeviceId, devB.DeviceId }.Order(), Ids((await user.GetJsonAsync("/api/v1/devices")).GetProperty("items")).Order());
        Assert.Equal(HttpStatusCode.NoContent, (await user.PatchAsync($"/api/v1/devices/{devA.DeviceId}", new { tags = new[] { "ok" } })).StatusCode);
        // devices.manage is only held in A, so the B device does not exist for this request.
        Assert.Equal(HttpStatusCode.NotFound, (await user.PatchAsync($"/api/v1/devices/{devB.DeviceId}", new { tags = new[] { "no" } })).StatusCode);
    }

    [Fact]
    public async Task Partners_are_isolated_from_each_other()
    {
        var one = await fx.SeedOrgAsync("P1 " + Guid.NewGuid().ToString("N")[..6]);
        var email = $"p2admin-{Guid.NewGuid():N}@partner-two.test";
        var p2 = Guid.NewGuid();
        var p2Org = Guid.NewGuid();
        await fx.DbAsync(async db =>
        {
            db.Partners.Add(new Partner { Id = p2, Name = "Partner Two", CreatedAt = DateTimeOffset.UtcNow });
            var roles = await Dranzo.Api.Services.Bootstrap.EnsureRolesAsync(db, p2);
            var user = new User { Id = Guid.NewGuid(), PartnerId = p2, Email = email, DisplayName = "P2 Admin", PasswordHash = AuthService.HashPassword("Partner-Two-Pass-55"), CreatedAt = DateTimeOffset.UtcNow, PasswordChangedAt = DateTimeOffset.UtcNow };
            db.Users.Add(user);
            db.RoleAssignments.Add(new RoleAssignment { Id = Guid.NewGuid(), PartnerId = p2, UserId = user.Id, RoleId = roles[BuiltInRoles.PartnerAdmin].Id, ScopeType = ScopeType.Partner, CreatedAt = DateTimeOffset.UtcNow });
            db.Organizations.Add(new Organization { Id = p2Org, PartnerId = p2, Name = "P2 Client", CreatedAt = DateTimeOffset.UtcNow });
            await db.SaveChangesAsync();
        });
        var p2Admin = fx.NewClient();
        await p2Admin.LoginAsync(email, "Partner-Two-Pass-55");

        Assert.Equal([p2Org], Ids(await p2Admin.GetJsonAsync("/api/v1/organizations")));
        Assert.Equal(0, (await p2Admin.GetJsonAsync("/api/v1/devices")).GetProperty("total").GetInt32());
        Assert.All((await p2Admin.GetJsonAsync("/api/v1/users")).EnumerateArray(), u => Assert.EndsWith("partner-two.test", u.GetProperty("email").GetString()));
        Assert.Equal(HttpStatusCode.NotFound, (await p2Admin.PatchAsync($"/api/v1/organizations/{one.OrgId}", new { name = "stolen" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await p2Admin.PostAsync("/api/v1/sites", new { organizationId = one.OrgId, name = "x" })).StatusCode);
        // A partner admin cannot grant scope over another partner's organization.
        await p2Admin.StepUpAsync();
        var p2Roles = await p2Admin.GetJsonAsync("/api/v1/roles");
        var p2Users = await p2Admin.GetJsonAsync("/api/v1/users");
        var grant = await p2Admin.PostAsync("/api/v1/role-assignments", new { userId = p2Users[0].GetProperty("id").GetGuid(), roleId = p2Roles[0].GetProperty("id").GetGuid(), scopeType = "Organization", scopeId = one.OrgId });
        Assert.Equal(HttpStatusCode.BadRequest, grant.StatusCode);
        // Audit trails are separate.
        var audit = await p2Admin.GetJsonAsync("/api/v1/audit?pageSize=500");
        Assert.All(audit.GetProperty("items").EnumerateArray(), e => Assert.DoesNotContain("partner-one", e.GetProperty("actorName").GetString()));

        var p1Admin = await fx.AdminAsync();
        Assert.DoesNotContain(p2Org, Ids(await p1Admin.GetJsonAsync("/api/v1/organizations")));
        Assert.DoesNotContain(email, (await p1Admin.GetJsonAsync("/api/v1/users")).EnumerateArray().Select(u => u.GetProperty("email").GetString()));
    }

    [Fact]
    public async Task Org_scoped_auditor_sees_only_their_organizations_events()
    {
        var a = await fx.SeedOrgAsync("AudA " + Guid.NewGuid().ToString("N")[..6]);
        var b = await fx.SeedOrgAsync("AudB " + Guid.NewGuid().ToString("N")[..6]);
        var roleId = await fx.CreateRoleAsync("Auditor " + Guid.NewGuid().ToString("N")[..6], Permissions.AuditRead);
        var roleName = await fx.DbAsync(db => db.Roles.Where(r => r.Id == roleId).Select(r => r.Name).FirstAsync());
        var auditor = await fx.CreateUserAsync($"aud-{Guid.NewGuid():N}@t.test", roleName, ScopeType.Organization, a.OrgId);
        var events = (await auditor.GetJsonAsync("/api/v1/audit?pageSize=500")).GetProperty("items");
        Assert.NotEqual(0, events.GetArrayLength());
        Assert.All(events.EnumerateArray(), e => Assert.Equal(a.OrgId, e.GetProperty("organizationId").GetGuid()));
        Assert.Equal(HttpStatusCode.Forbidden, (await auditor.GetAsync("/api/v1/audit/verify")).StatusCode);
        var csv = await (await auditor.GetAsync("/api/v1/audit/export.csv")).Content.ReadAsStringAsync();
        Assert.DoesNotContain(b.OrgId.ToString(), csv);
    }

    [Fact]
    public async Task A_context_without_a_scope_returns_no_rows_for_any_entity()
    {
        await fx.SeedOrgAsync("Empty " + Guid.NewGuid().ToString("N")[..6]);
        await using var scope = fx.App.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<DranzoDbContext>(); // tenant context never set
        Assert.Equal(0, await db.Organizations.CountAsync());
        Assert.Equal(0, await db.Devices.CountAsync());
        Assert.Equal(0, await db.Users.CountAsync());
        Assert.Equal(0, await db.AuditEvents.CountAsync());
        Assert.Equal(0, await db.EnrollmentTokens.CountAsync());
        Assert.Equal(0, await db.Roles.CountAsync());
    }

    [Fact]
    public async Task Every_entity_is_tenant_filtered_or_explicitly_global()
    {
        await fx.DbAsync(db =>
        {
            foreach (var entity in db.Model.GetEntityTypes())
            {
                var filtered = entity.GetDeclaredQueryFilters().Count > 0;
                Assert.True(filtered || DranzoDbContext.GlobalEntities.Contains(entity.ClrType), $"{entity.ClrType.Name} has no tenant query filter");
            }
            return Task.CompletedTask;
        });
    }
}
