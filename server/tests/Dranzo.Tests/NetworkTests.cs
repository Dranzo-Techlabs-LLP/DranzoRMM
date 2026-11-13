using System.Net;
using System.Text.Json;
using Dranzo.Api.Features;
using Dranzo.Domain;
using Dranzo.Tests.Infra;

namespace Dranzo.Tests;

/// <summary>Phase 10: network and firewall features.</summary>
[Collection("server")]
public class NetworkTests(ServerFixture fx)
{
    private static string U => Guid.NewGuid().ToString("N")[..6];

    // ----- 10a: Network Admin role and access review -----

    [Fact]
    public void Access_review_findings_follow_the_rules()
    {
        var now = DateTimeOffset.Parse("2026-11-13T00:00:00Z");
        var old = now.AddDays(-200);
        Assert.Empty(AccessReviewEndpoints.Findings("user", disabled: true, mfa: false, null, old, null, true, now));
        Assert.Equal(["MFA not set up", "Never used (90+ days)"], AccessReviewEndpoints.Findings("user", false, false, null, old, null, false, now));
        Assert.Equal(["Inactive 90+ days"], AccessReviewEndpoints.Findings("user", false, true, old, old, null, false, now));
        Assert.Empty(AccessReviewEndpoints.Findings("user", false, true, now.AddDays(-1), old, null, false, now));
        Assert.Equal(["API key never expires", "Full admin rights over every organization"],
            AccessReviewEndpoints.Findings("apikey", false, null, now, old, null, true, now));
    }

    [Fact]
    public void Network_admin_role_holds_network_rights_but_not_user_or_script_rights()
    {
        var perms = BuiltInRoles.Definitions[BuiltInRoles.NetworkAdmin];
        Assert.Contains(Permissions.NetworkConfigure, perms);
        Assert.Contains(Permissions.DevicesIsolate, perms);
        Assert.DoesNotContain(Permissions.UsersManage, perms);
        Assert.DoesNotContain(Permissions.ScriptsRun, perms);
        Assert.Contains(Permissions.NetworkConfigure, Permissions.InteractiveOnly);
        Assert.All(perms, p => Assert.Contains(p, Permissions.All));
        Assert.Equal(Permissions.All.Count, BuiltInRoles.Definitions[BuiltInRoles.PartnerAdmin].Length);
    }

    [Fact]
    public async Task Access_review_lists_users_with_effective_rights_and_is_partner_admin_only()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("AR " + U);
        var email = $"netadmin-{U}@example.test";
        var netAdmin = await fx.CreateUserAsync(email, BuiltInRoles.NetworkAdmin, ScopeType.Organization, org.OrgId);

        var review = await admin.GetJsonAsync("/api/v1/access-review");
        var me = review.GetProperty("principals").EnumerateArray().Single(p => p.GetProperty("email").GetString() == email);
        Assert.Equal("user", me.GetProperty("kind").GetString());
        var grant = me.GetProperty("grants").EnumerateArray().Single();
        Assert.Equal(BuiltInRoles.NetworkAdmin, grant.GetProperty("role").GetString());
        Assert.StartsWith("AR ", grant.GetProperty("scopeName").GetString(), StringComparison.Ordinal);
        Assert.Contains(me.GetProperty("permissions").EnumerateArray(), p => p.GetString() == Permissions.NetworkConfigure);
        Assert.DoesNotContain(me.GetProperty("findings").EnumerateArray(), f => f.GetString()!.Contains("Full admin", StringComparison.Ordinal));
        // The bootstrap admin holds every permission over every organization.
        var bootstrap = review.GetProperty("principals").EnumerateArray().Single(p => p.GetProperty("email").GetString() == ServerFixture.AdminEmail);
        Assert.Contains(bootstrap.GetProperty("findings").EnumerateArray(), f => f.GetString() == "Full admin rights over every organization");

        // An organization-scoped user may not see who else has access.
        Assert.Equal(HttpStatusCode.Forbidden, (await netAdmin.GetAsync("/api/v1/access-review")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await netAdmin.GetAsync("/api/v1/reports/access-review.csv")).StatusCode);

        var csv = await admin.GetAsync("/api/v1/reports/access-review.csv");
        Assert.Equal(HttpStatusCode.OK, csv.StatusCode);
        var text = await csv.Content.ReadAsStringAsync();
        Assert.Contains(email, text, StringComparison.Ordinal);
        Assert.Contains("Network Admin (AR ", text, StringComparison.Ordinal);
        var audit = await admin.GetJsonAsync("/api/v1/audit?action=report.generate");
        Assert.Contains(audit.GetProperty("items").EnumerateArray(), a => a.GetProperty("targetId").GetString() == "access-review");
    }
}
