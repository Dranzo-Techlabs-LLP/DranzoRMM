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

    // ----- 10c: network discovery and approval list -----

    [Fact]
    public void Network_rules_accept_only_clean_unicast_private_input()
    {
        Assert.Equal("a4:83:e7:11:22:33", NetworkRules.NormalizeMac("A4-83-E7-11-22-33"));
        Assert.Null(NetworkRules.NormalizeMac("ff:ff:ff:ff:ff:ff"));
        Assert.Null(NetworkRules.NormalizeMac("01:00:5e:00:00:fb"));
        Assert.Null(NetworkRules.NormalizeMac("00:00:00:00:00:00"));
        Assert.Null(NetworkRules.NormalizeMac("a4:83:e7:11:22"));
        Assert.True(NetworkRules.Randomized("da:a1:19:22:33:44"));
        Assert.True(NetworkRules.IsPrivateIpv4("192.168.68.1"));
        Assert.True(NetworkRules.IsPrivateIpv4("100.64.1.1"));
        Assert.False(NetworkRules.IsPrivateIpv4("8.8.8.8"));
        Assert.False(NetworkRules.IsPrivateIpv4("192.168.1"));
        Assert.Equal("router.lan", NetworkRules.CleanHostname("router.lan."));
        Assert.Null(NetworkRules.CleanHostname("<script>"));
    }

    private static object Neighbor(string ip, string mac, string? hostname = null) => new { ip, mac, hostname };

    [Fact]
    public async Task Network_scan_records_devices_matches_managed_ones_alerts_and_supports_approval()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Net " + U);
        await using var scanner = await TestAgent.EnrollAsync(fx, org.Token, "net-scanner", os: "windows");
        await using var laptop = await TestAgent.EnrollAsync(fx, org.Token, "net-laptop", os: "macos");
        // The laptop reports its MAC in inventory, so the scan recognises it as managed.
        await laptop.SendAsync("inventory", new
        {
            collectedAt = DateTimeOffset.UtcNow, hostname = "net-laptop", os = new { family = "macos", name = "macOS", version = "15", build = "", kernel = "" },
            arch = "arm64", network = new[] { new { name = "en0", mac = "3C:22:FB:00:11:22", ipv4 = new[] { "192.168.68.50" }, ipv6 = Array.Empty<string>() } },
            defaultGateway = "192.168.68.1", wifi = new { @interface = "en0", ssid = "Dranzo-Office", bssid = "" },
        });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{laptop.DeviceId}"), d => d.GetProperty("osName").GetString() == "macOS");

        // A site scan goes to the most recently seen capable device: here the laptop, which just reported.
        var bySite = await admin.PostJsonAsync("/api/v1/network/scan", new { siteId = org.SiteId });
        Assert.Equal(laptop.DeviceId, bySite.GetProperty("deviceId").GetGuid());
        await laptop.CompleteAsync(await laptop.NextJobAsync("network.scan"), result: new { neighbors = Array.Empty<object>() });
        await admin.PostJsonAsync("/api/v1/network/scan", new { deviceId = scanner.DeviceId });
        var job = await scanner.NextJobAsync("network.scan");
        Assert.True(job.Payload.GetProperty("spec").GetProperty("resolveNames").GetBoolean());
        await scanner.CompleteAsync(job, result: new
        {
            scannedAt = DateTimeOffset.UtcNow, subnets = new[] { "192.168.68.0/24" }, gateway = "192.168.68.1", truncated = false,
            neighbors = new[]
            {
                Neighbor("192.168.68.1", "a4:83:e7:11:22:33", "router.lan"),
                Neighbor("192.168.68.50", "3c:22:fb:00:11:22"),
                Neighbor("192.168.68.77", "da:a1:19:22:33:44"),
                Neighbor("192.168.68.80", "00:11:22:33:44:55", "<b>evil</b>"),
                Neighbor("8.8.8.8", "00:11:22:33:44:66"),            // public: dropped
                Neighbor("192.168.68.255", "ff:ff:ff:ff:ff:ff"),     // broadcast: dropped
            },
        });
        var list = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/network/devices?organizationId={org.OrgId}"), l => l.GetProperty("total").GetInt32() == 4);
        var items = list.GetProperty("items").EnumerateArray().ToDictionary(i => i.GetProperty("mac").GetString()!);
        Assert.True(items["a4:83:e7:11:22:33"].GetProperty("isGateway").GetBoolean());
        Assert.Equal("router.lan", items["a4:83:e7:11:22:33"].GetProperty("hostname").GetString());
        Assert.Equal("net-laptop", items["3c:22:fb:00:11:22"].GetProperty("managedHostname").GetString());
        Assert.True(items["da:a1:19:22:33:44"].GetProperty("randomized").GetBoolean());
        Assert.Equal(JsonValueKind.Null, items["00:11:22:33:44:55"].GetProperty("hostname").ValueKind);
        Assert.Equal("net-scanner", items["00:11:22:33:44:55"].GetProperty("seenByHostname").GetString());
        Assert.Equal(4, list.GetProperty("counts").GetProperty("unknown").GetInt32());

        // First scan of a site: one summary alert, not one per device.
        var alerts = await admin.GetJsonAsync($"/api/v1/alerts?deviceId={scanner.DeviceId}");
        var networkAlerts = alerts.GetProperty("items").EnumerateArray().Where(a => a.GetProperty("type").GetString() == "network.unknown_device").ToList();
        Assert.Single(networkAlerts);
        Assert.Contains("First network scan: 2 unknown devices", networkAlerts[0].GetProperty("title").GetString(), StringComparison.Ordinal);

        // A later scan with a new device raises an alert for it.
        await admin.PostJsonAsync("/api/v1/network/scan", new { deviceId = scanner.DeviceId });
        var job2 = await scanner.NextJobAsync("network.scan");
        await scanner.CompleteAsync(job2, result: new
        {
            scannedAt = DateTimeOffset.UtcNow, subnets = new[] { "192.168.68.0/24" }, gateway = "192.168.68.1", truncated = false,
            neighbors = new[] { Neighbor("192.168.68.1", "a4:83:e7:11:22:33"), Neighbor("192.168.68.90", "00:aa:bb:cc:dd:ee", "printer.lan") },
        });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/network/devices?organizationId={org.OrgId}"), l => l.GetProperty("total").GetInt32() == 5);
        alerts = await admin.GetJsonAsync($"/api/v1/alerts?deviceId={scanner.DeviceId}");
        Assert.Contains(alerts.GetProperty("items").EnumerateArray(), a => a.GetProperty("title").GetString() == "New device on the network: printer.lan (192.168.68.90)");
        // The router kept its hostname although the second scan did not resolve it.
        list = await admin.GetJsonAsync($"/api/v1/network/devices?organizationId={org.OrgId}&search=router");
        Assert.Equal(1, list.GetProperty("total").GetInt32());

        // Approve and block, audited.
        var printer = (await admin.GetJsonAsync($"/api/v1/network/devices?organizationId={org.OrgId}&search=printer")).GetProperty("items")[0].GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/v1/network/devices/{printer}/status", new { status = "approved", note = "Office printer" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync($"/api/v1/network/devices/{printer}/status", new { status = "trusted" })).StatusCode);
        var all = (await admin.GetJsonAsync($"/api/v1/network/devices?organizationId={org.OrgId}&status=unknown")).GetProperty("items").EnumerateArray().Select(i => i.GetProperty("id").GetGuid()).ToArray();
        var bulk = await admin.PostJsonAsync("/api/v1/network/devices/status", new { ids = all, status = "blocked" });
        Assert.Equal(all.Length, bulk.GetProperty("updated").GetInt32());
        list = await admin.GetJsonAsync($"/api/v1/network/devices?organizationId={org.OrgId}");
        Assert.Equal(1, list.GetProperty("counts").GetProperty("approved").GetInt32());
        Assert.Equal(4, list.GetProperty("counts").GetProperty("blocked").GetInt32());
        var audit = await admin.GetJsonAsync($"/api/v1/audit?action=network_device.status&organizationId={org.OrgId}");
        Assert.True(audit.GetProperty("total").GetInt32() >= 2);

        // Another organization: cannot see, change or scan.
        var other = await fx.SeedOrgAsync("Net other " + U);
        var outsider = await fx.CreateUserAsync($"netout-{U}@example.test", BuiltInRoles.NetworkAdmin, ScopeType.Organization, other.OrgId);
        Assert.Equal(0, (await outsider.GetJsonAsync($"/api/v1/network/devices?organizationId={org.OrgId}")).GetProperty("total").GetInt32());
        Assert.Equal(HttpStatusCode.NotFound, (await outsider.PostAsync($"/api/v1/network/devices/{printer}/status", new { status = "blocked" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await outsider.PostAsync("/api/v1/network/devices/status", new { ids = new[] { printer }, status = "blocked" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await outsider.PostAsync("/api/v1/network/scan", new { siteId = org.SiteId })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await outsider.DeleteAsync($"/api/v1/network/devices/{printer}")).StatusCode);
        // A read-only organization viewer of the right organization cannot change anything.
        var viewer = await fx.CreateUserAsync($"netview-{U}@example.test", BuiltInRoles.ReadOnly, ScopeType.Organization, org.OrgId);
        Assert.Equal(1, (await viewer.GetJsonAsync($"/api/v1/network/devices?organizationId={org.OrgId}&status=approved")).GetProperty("total").GetInt32());
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsync($"/api/v1/network/devices/{printer}/status", new { status = "blocked" })).StatusCode);
    }

    [Fact]
    public async Task Scan_results_from_the_wrong_device_or_kind_are_ignored()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Net forge " + U);
        await using var scanner = await TestAgent.EnrollAsync(fx, org.Token, "forge-scanner");
        await using var forger = await TestAgent.EnrollAsync(fx, org.Token, "forge-other");
        await admin.PostJsonAsync("/api/v1/network/scan", new { deviceId = scanner.DeviceId });
        var job = await scanner.NextJobAsync("network.scan");
        // Another device answers the scanner's job run: refused by the result processor.
        await forger.CompleteAsync(job, result: new { neighbors = new[] { Neighbor("192.168.1.66", "00:66:66:66:66:66") } });
        await scanner.CompleteAsync(job, status: "failed", result: new { neighbors = new[] { Neighbor("192.168.1.67", "00:66:66:66:66:67") } });
        await Task.Delay(500);
        Assert.Equal(0, (await admin.GetJsonAsync($"/api/v1/network/devices?organizationId={org.OrgId}")).GetProperty("total").GetInt32());
    }

    // ----- 10d: firewall rule policies -----

    private static JsonElement Params(object o) => JsonSerializer.SerializeToElement(o);

    [Fact]
    public void Firewall_rule_params_are_validated_like_the_agent()
    {
        Assert.Null(FirewallRules.Validate(Params(new { rules = new[] { new { name = "Block SMB", direction = "in", action = "block", protocol = "tcp", ports = new[] { "445", "8000-8100" }, remoteAddresses = new[] { "10.0.0.0/8", "fd00::1" } } } })));
        Assert.Null(FirewallRules.Validate(Params(new { rules = new[] { new { name = "No torrent", direction = "out", action = "block", protocol = "any", program = @"C:\Apps\t.exe" } } })));
        string? Bad(object rule) => FirewallRules.Validate(Params(new { rules = new[] { rule } }));
        Assert.NotNull(FirewallRules.Validate(Params(new { rules = Array.Empty<object>() })));
        Assert.NotNull(FirewallRules.Validate(Params(new { })));
        Assert.Contains("name", Bad(new { name = "x\"; rm", direction = "in", action = "block", protocol = "tcp" }), StringComparison.Ordinal);
        Assert.Contains("direction", Bad(new { name = "a", direction = "both", action = "block", protocol = "tcp" }), StringComparison.Ordinal);
        Assert.Contains("ports need protocol", Bad(new { name = "a", direction = "in", action = "block", protocol = "any", ports = new[] { "80" } }), StringComparison.Ordinal);
        Assert.Contains("invalid port", Bad(new { name = "a", direction = "in", action = "block", protocol = "tcp", ports = new[] { "90-80" } }), StringComparison.Ordinal);
        Assert.Contains("invalid address", Bad(new { name = "a", direction = "in", action = "block", protocol = "tcp", remoteAddresses = new[] { "10.0.0.0/40" } }), StringComparison.Ordinal);
        Assert.Contains("program", Bad(new { name = "a", direction = "out", action = "block", protocol = "any", program = "t.exe" }), StringComparison.Ordinal);
        Assert.Contains("isolation", Bad(new { name = "a", direction = "out", action = "block", protocol = "any" }), StringComparison.Ordinal);
        Assert.NotNull(FirewallRules.Validate(Params(new { rules = Enumerable.Range(0, 101).Select(i => new { name = "r" + i, direction = "in", action = "allow", protocol = "tcp" }) })));
    }

    [Fact]
    public async Task Firewall_rules_policy_reaches_every_os_with_its_rules()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Fw " + U);
        await using var win = await TestAgent.EnrollAsync(fx, org.Token, "fw-win", os: "windows");
        var rules = new[] { new { name = "Block SMB", direction = "in", action = "block", protocol = "tcp", ports = new[] { "445" } } };
        var bad = await admin.PostAsync("/api/v1/policies", new { name = "Bad fw " + U, check = "firewall.rules", @params = new { rules = new[] { new { name = "a", direction = "out", action = "block", protocol = "any" } } }, organizationId = org.OrgId });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        var policy = (await admin.PostJsonAsync("/api/v1/policies", new { name = "Fw rules " + U, check = "firewall.rules", @params = new { rules }, remediate = true, organizationId = org.OrgId })).GetProperty("id").GetGuid();
        await admin.PostJsonAsync($"/api/v1/policies/{policy}/assignments", new { scopeType = "Organization", scopeId = org.OrgId });
        Assert.True((await admin.PostAsync("/api/v1/policies/evaluate", new { organizationId = org.OrgId })).IsSuccessStatusCode);
        var job = await win.NextJobAsync("policy.evaluate");
        var check = job.Payload.GetProperty("spec").GetProperty("checks").EnumerateArray().Single(c => c.GetProperty("check").GetString() == "firewall.rules");
        Assert.True(check.GetProperty("remediate").GetBoolean());
        Assert.Equal("445", check.GetProperty("params").GetProperty("rules")[0].GetProperty("ports")[0].GetString());
        await win.CompleteAsync(job, result: new { results = new[] { new { policyId = policy, check = "firewall.rules", compliant = true, remediated = true, detail = "2 of 2 rules missing; applied" } } });
        var compliance = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{win.DeviceId}/compliance"), c => c.GetArrayLength() == 1);
        Assert.True(compliance[0].GetProperty("compliant").GetBoolean());
    }
}
