using System.Net;
using System.Text.RegularExpressions;
using Dranzo.Api.Auth;
using Dranzo.Domain;
using Dranzo.Tests.Infra;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Dranzo.Tests;

/// <summary>
/// Authorization coverage for <b>every</b> endpoint, generated from the route table so a new endpoint
/// cannot be added without being covered.
/// </summary>
[Collection("server")]
public partial class EndpointAccessTests(ServerFixture fx)
{
    private List<RouteEndpoint> AllEndpoints() =>
        [.. fx.App.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>()];

    private static string Method(RouteEndpoint e) => e.Metadata.GetMetadata<HttpMethodMetadata>()?.HttpMethods.FirstOrDefault() ?? "GET";

    [GeneratedRegex(@"\{[^}]+\}")]
    private static partial Regex RouteParam();

    private static string Fill(RouteEndpoint e, Func<string, string> value) => RouteParam().Replace(e.RoutePattern.RawText!, m => value(m.Value));

    [Fact]
    public void Every_endpoint_declares_exactly_one_access_rule()
    {
        var problems = new List<string>();
        foreach (var e in AllEndpoints())
        {
            var markers = new object?[]
            {
                e.Metadata.GetMetadata<PermissionMetadata>(), e.Metadata.GetMetadata<AuthenticatedOnlyMetadata>(),
                e.Metadata.GetMetadata<AnonymousMetadata>(), e.Metadata.GetMetadata<AgentListenerMetadata>(),
            }.Count(m => m is not null);
            if (markers != 1)
            {
                problems.Add($"{Method(e)} {e.RoutePattern.RawText}: {markers} access markers");
            }
            if (e.Metadata.GetMetadata<StepUpMetadata>() is not null && e.Metadata.GetMetadata<PermissionMetadata>() is null)
            {
                problems.Add($"{Method(e)} {e.RoutePattern.RawText}: step-up without a permission");
            }
        }
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public async Task Every_protected_endpoint_rejects_anonymous_and_role_less_callers()
    {
        var anonymous = fx.NewClient();
        var admin = await fx.AdminAsync();
        var email = $"norole-{Guid.NewGuid():N}@t.test";
        var created = await admin.PostAsync("/api/v1/users", new { email, displayName = "No Role", password = "Temp-Strong-Pass-5501" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var noRole = fx.NewClient();
        await noRole.LoginAsync(email, "Temp-Strong-Pass-5501");
        await noRole.PostAsync("/api/v1/auth/password", new { currentPassword = "Temp-Strong-Pass-5501", newPassword = "Another-Strong-Pass-77" });

        var problems = new List<string>();
        var checkedCount = 0;
        foreach (var e in AllEndpoints().Where(e => e.Metadata.GetMetadata<PermissionMetadata>() is not null))
        {
            var path = Fill(e, _ => Guid.NewGuid().ToString());
            var method = new HttpMethod(Method(e));
            var body = method == HttpMethod.Get ? null : new { };
            var a = await anonymous.SendAsync(method, path, body);
            if (a.StatusCode != HttpStatusCode.Unauthorized)
            {
                problems.Add($"anonymous {method} {path} → {(int)a.StatusCode}");
            }
            var n = await noRole.SendAsync(method, path, body);
            if (n.StatusCode != HttpStatusCode.Forbidden)
            {
                problems.Add($"no-role {method} {path} → {(int)n.StatusCode}");
            }
            checkedCount++;
        }
        Assert.True(checkedCount > 20);
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    [Fact]
    public async Task Org_scoped_admin_cannot_reach_another_organizations_resources_through_any_endpoint()
    {
        var a = await fx.SeedOrgAsync("XA " + Guid.NewGuid().ToString("N")[..6]);
        var b = await fx.SeedOrgAsync("XB-SECRET " + Guid.NewGuid().ToString("N")[..6]);
        await using var agentA = await TestAgent.EnrollAsync(fx, a.Token, "xa-host", connect: false);
        await using var agentB = await TestAgent.EnrollAsync(fx, b.Token, "xb-secret-host", connect: false);
        var ids = await CrossTenantIds.SeedAsync(fx, b, agentB.DeviceId);

        // Every permission that exists, but only inside organization A.
        var roleId = await fx.CreateRoleAsync("All in org " + Guid.NewGuid().ToString("N")[..6], [.. Permissions.All]);
        var roleName = await fx.DbAsync(db => db.Roles.Where(r => r.Id == roleId).Select(r => r.Name).FirstAsync());
        var userA = await fx.CreateUserAsync($"xa-{Guid.NewGuid():N}@t.test", roleName, ScopeType.Organization, a.OrgId);
        await userA.StepUpAsync();

        var problems = new List<string>();
        foreach (var e in AllEndpoints().Where(e => e.Metadata.GetMetadata<PermissionMetadata>() is not null))
        {
            var perm = e.Metadata.GetMetadata<PermissionMetadata>()!;
            var raw = e.RoutePattern.RawText!;
            var method = new HttpMethod(Method(e));
            var hasParams = raw.Contains('{');
            if (!hasParams && method != HttpMethod.Get && !perm.PartnerWide)
            {
                continue; // creation endpoints take ids in the body: covered one by one in TenantIsolationTests
            }
            string path;
            try
            {
                path = Fill(e, _ => ids.For(raw).ToString());
            }
            catch (KeyNotFoundException)
            {
                problems.Add($"{method} {raw}: add an organization-B resource for this route to CrossTenantIds");
                continue;
            }
            var r = await userA.SendAsync(method, path, method == HttpMethod.Get ? null : new { });
            var text = await r.Content.ReadAsStringAsync();
            if (perm.PartnerWide)
            {
                if (r.StatusCode != HttpStatusCode.Forbidden)
                {
                    problems.Add($"{method} {path} is partner-wide but returned {(int)r.StatusCode} to an org-scoped user");
                }
            }
            else if (hasParams)
            {
                if (r.StatusCode != HttpStatusCode.NotFound)
                {
                    problems.Add($"{method} {path} → {(int)r.StatusCode} (expected 404) {text[..Math.Min(120, text.Length)]}");
                }
            }
            else if (!r.IsSuccessStatusCode && r.StatusCode != HttpStatusCode.BadRequest)
            {
                problems.Add($"{method} {path} → {(int)r.StatusCode}");
            }
            foreach (var marker in ids.Markers.Where(m => text.Contains(m, StringComparison.OrdinalIgnoreCase)))
            {
                problems.Add($"{method} {path} leaked organization-B data ({marker})");
            }
        }
        Assert.True(problems.Count == 0, string.Join("\n", problems));

        // Nothing in organization B changed.
        Assert.True(await fx.DbAsync(db => db.Devices.AnyAsync(d => d.Id == agentB.DeviceId && d.Status == DeviceStatus.Active && d.CertThumbprint != null)));
        Assert.True(await fx.DbAsync(db => db.Organizations.AnyAsync(o => o.Id == b.OrgId && o.DeletedAt == null)));
        Assert.True(await fx.DbAsync(db => db.Sites.AnyAsync(s => s.Id == b.SiteId)));
        Assert.True(await fx.DbAsync(db => db.DeviceGroups.AnyAsync(s => s.Id == b.GroupId)));
    }
}
