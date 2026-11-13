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

    private static async Task<JsonElement> UntilAsync(Func<Task<JsonElement>> get, Func<JsonElement, bool> ok)
    {
        JsonElement v = default;
        for (var i = 0; i < 100; i++)
        {
            v = await get();
            if (ok(v))
            {
                return v;
            }
            await Task.Delay(50);
        }
        Assert.Fail("condition not reached: " + v);
        return v;
    }

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

    // ----- 10b: security score -----

    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-13T00:00:00Z");

    private static ScoreInputs Good => new(true, true, true, Now.AddDays(-1), 0, 0, 4, 4, true, 0, 0, false);

    [Fact]
    public void Score_is_100_for_a_healthy_device_and_drops_per_problem()
    {
        var r = SecurityScore.Compute(Good, Now);
        Assert.Equal(100, r.Score);
        Assert.Equal("A", r.Grade);

        // Antivirus off: 20 of 100 points lost.
        Assert.Equal(80, SecurityScore.Compute(Good with { Antivirus = false }, Now).Score);
        // A known exploited vulnerability zeroes the vulnerability part (15).
        var kev = SecurityScore.Compute(Good with { VulnKev = 1, VulnHigh = 3 }, Now);
        Assert.Equal(85, kev.Score);
        Assert.Equal("bad", kev.Components.Single(c => c.Key == "vulnerabilities").Status);
        // Three missing critical updates, one failed, stale scan: updates part is 0.
        var patches = SecurityScore.Compute(Good with { MissingCritical = 3, FailedPatches = 1, LastPatchScan = Now.AddDays(-30) }, Now);
        Assert.Equal(80, patches.Score);
        Assert.Contains("over 14 days", patches.Components.Single(c => c.Key == "patches").Reason, StringComparison.Ordinal);
        // Half the policies failing: 7.5 of 15.
        Assert.Equal(93, SecurityScore.Compute(Good with { PoliciesCompliant = 2 }, Now).Score);
        Assert.Equal("F", SecurityScore.Compute(new ScoreInputs(false, false, false, Now, 5, 2, 2, 0, true, 9, 2, false), Now).Grade);
    }

    [Fact]
    public void Unknown_parts_are_left_out_and_too_little_data_gives_no_score()
    {
        // No policies and no vulnerability feed: scored over the remaining 70 points.
        var r = SecurityScore.Compute(Good with { PoliciesTotal = 0, PoliciesCompliant = 0, VulnDataAvailable = false, Antivirus = false }, Now);
        Assert.Equal((int)Math.Round(100.0 * 50 / 70, MidpointRounding.AwayFromZero), r.Score);
        Assert.Equal(2, r.Components.Count(c => c.Status == "unknown"));
        // Only the firewall known (15 points): below the 40-point minimum.
        var none = SecurityScore.Compute(new ScoreInputs(null, true, null, null, 0, 0, 0, 0, false, 0, 0, false), Now);
        Assert.Null(none.Score);
        Assert.Equal("?", none.Grade);
    }

    [Fact]
    public async Task Score_endpoint_reflects_posture_and_is_tenant_scoped()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Score " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "score-host", os: "windows");
        await agent.SendAsync("posture", new
        {
            collectedAt = DateTimeOffset.UtcNow,
            antivirus = new[] { new { name = "Defender", enabled = false, upToDate = true, source = "defender" } },
            firewall = new { enabled = true, detail = "" },
            diskEncryption = new[] { new { volume = "C:", method = "bitlocker", status = "encrypted" } },
            localAdmins = new[] { "Administrator" },
            screenLock = new { enabled = true, timeoutSeconds = 300 },
            pendingReboot = false, listeningPorts = Array.Empty<object>(), unsupported = Array.Empty<string>(),
        });
        var score = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{agent.DeviceId}/security-score"),
            s => s.ValueKind == JsonValueKind.Object && s.GetProperty("components").EnumerateArray().First().GetProperty("status").GetString() != "unknown");
        var av = score.GetProperty("components").EnumerateArray().Single(c => c.GetProperty("key").GetString() == "antivirus");
        Assert.Equal("bad", av.GetProperty("status").GetString());
        Assert.Equal(0, av.GetProperty("earned").GetDouble());

        var fleet = await admin.GetJsonAsync($"/api/v1/security/posture?organizationId={org.OrgId}");
        Assert.Equal(score.GetProperty("score").ValueKind, fleet.GetProperty("items")[0].GetProperty("score").ValueKind);

        // Another organization's viewer gets 404, not the score.
        var other = await fx.SeedOrgAsync("Score other " + U);
        var viewer = await fx.CreateUserAsync($"scoreview-{U}@example.test", BuiltInRoles.OrganizationViewer, ScopeType.Organization, other.OrgId);
        Assert.Equal(HttpStatusCode.NotFound, (await viewer.GetAsync($"/api/v1/devices/{agent.DeviceId}/security-score")).StatusCode);
    }
}
