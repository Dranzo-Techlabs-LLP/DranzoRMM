using System.Net;
using System.Text.Json;
using Dranzo.Api.Features;
using Dranzo.Domain;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;

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
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync($"/api/v1/network/devices/{printer}/status", new { status = "approved", note = "Office printer" })).StatusCode);
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

    // ----- 10e: device isolation -----

    [Fact]
    public async Task Isolation_needs_step_up_is_audited_tracked_and_released()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Iso " + U);
        await using var pc = await TestAgent.EnrollAsync(fx, org.Token, "iso-pc", os: "windows");

        Assert.Equal(HttpStatusCode.BadRequest, (await StepUpThen(admin, () => admin.PostAsync($"/api/v1/devices/{pc.DeviceId}/isolate", new { reason = "" }))).StatusCode);
        var isolate = await StepUpThen(admin, () => admin.PostAsync($"/api/v1/devices/{pc.DeviceId}/isolate", new { reason = "Ransomware alert INC-42", message = "Call IT on 1234." }));
        Assert.Equal(HttpStatusCode.Created, isolate.StatusCode);
        var job = await pc.NextJobAsync("network.isolate");
        var spec = job.Payload.GetProperty("spec");
        Assert.Equal("Call IT on 1234.", spec.GetProperty("message").GetString());
        await pc.CompleteAsync(job, result: new { allowed = new[] { "127.0.0.1" } });
        var detail = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{pc.DeviceId}"), d => d.GetProperty("isolatedAt").ValueKind == JsonValueKind.String);
        Assert.Equal("Ransomware alert INC-42", detail.GetProperty("isolationReason").GetString());
        Assert.False(string.IsNullOrEmpty(detail.GetProperty("isolatedBy").GetString()));
        Assert.True((await admin.GetJsonAsync($"/api/v1/devices/{pc.DeviceId}/security-score")).GetProperty("isolated").GetBoolean());
        var audit = await admin.GetJsonAsync($"/api/v1/audit?action=device.isolate&organizationId={org.OrgId}");
        Assert.Equal(1, audit.GetProperty("total").GetInt32());

        var release = await StepUpThen(admin, () => admin.PostAsync($"/api/v1/devices/{pc.DeviceId}/release", new { reason = "Cleaned" }));
        Assert.Equal(HttpStatusCode.Created, release.StatusCode);
        var rjob = await pc.NextJobAsync("network.release");
        await pc.CompleteAsync(rjob);
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{pc.DeviceId}"), d => d.GetProperty("isolatedAt").ValueKind == JsonValueKind.Null);
    }

    [Fact]
    public async Task Isolation_is_refused_without_rights_fresh_mfa_or_scope()
    {
        var org = await fx.SeedOrgAsync("Iso deny " + U);
        await using var pc = await TestAgent.EnrollAsync(fx, org.Token, "iso-deny");
        // A failed isolation on the device leaves the device not isolated.
        var admin = await fx.AdminAsync();
        await StepUpThen(admin, () => admin.PostAsync($"/api/v1/devices/{pc.DeviceId}/isolate", new { reason = "test" }));
        await pc.CompleteAsync(await pc.NextJobAsync("network.isolate"), status: "failed", message: "server unreachable, released");
        await Task.Delay(300);
        Assert.Equal(JsonValueKind.Null, (await admin.GetJsonAsync($"/api/v1/devices/{pc.DeviceId}")).GetProperty("isolatedAt").ValueKind);

        // Technicians do not hold devices.isolate.
        var tech = await fx.CreateUserAsync($"isotech-{U}@example.test", BuiltInRoles.Technician, ScopeType.Organization, org.OrgId);
        Assert.Equal(HttpStatusCode.Forbidden, (await StepUpThen(tech, () => tech.PostAsync($"/api/v1/devices/{pc.DeviceId}/isolate", new { reason = "x" }))).StatusCode);
        // A Network Admin of the organization needs a fresh authenticator code.
        var netAdmin = await fx.CreateUserAsync($"isonet-{U}@example.test", BuiltInRoles.NetworkAdmin, ScopeType.Organization, org.OrgId);
        var noStepUp = await netAdmin.PostAsync($"/api/v1/devices/{pc.DeviceId}/isolate", new { reason = "x" });
        Assert.Equal(HttpStatusCode.Unauthorized, noStepUp.StatusCode);
        Assert.Contains("step_up_required", await noStepUp.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Created, (await StepUpThen(netAdmin, () => netAdmin.PostAsync($"/api/v1/devices/{pc.DeviceId}/isolate", new { reason = "x" }))).StatusCode);
        // A Network Admin of another organization gets 404.
        var other = await fx.SeedOrgAsync("Iso other " + U);
        var outsider = await fx.CreateUserAsync($"isoout-{U}@example.test", BuiltInRoles.NetworkAdmin, ScopeType.Organization, other.OrgId);
        Assert.Equal(HttpStatusCode.NotFound, (await StepUpThen(outsider, () => outsider.PostAsync($"/api/v1/devices/{pc.DeviceId}/release", new { reason = "x" }))).StatusCode);
    }

    [Fact]
    public async Task Older_agent_without_network_features_is_refused_clearly_and_not_marked_non_compliant()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Old agent " + U);
        await using var old = await TestAgent.EnrollAsync(fx, org.Token, "old-agent", os: "windows", connect: false);
        // An agent from before network features: no network.* and no firewall.rules support.
        await old.ConnectAsync(capabilities: ["script", "inventory.refresh", "policy.evaluate", "posture.scan", "reboot"]);
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{old.DeviceId}"), d => d.GetProperty("capabilities").GetArrayLength() == 5);

        var isolate = await StepUpThen(admin, () => admin.PostAsync($"/api/v1/devices/{old.DeviceId}/isolate", new { reason = "test" }));
        Assert.Equal(HttpStatusCode.Conflict, isolate.StatusCode);
        Assert.Contains("does not support network isolation", await isolate.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync("/api/v1/network/scan", new { deviceId = old.DeviceId })).StatusCode);
        // The refused attempt is audited as a failure and no job was queued.
        var audit = await admin.GetJsonAsync($"/api/v1/audit?action=device.isolate&organizationId={org.OrgId}");
        Assert.Equal(1, audit.GetProperty("total").GetInt32());
        Assert.Equal("failure", audit.GetProperty("items")[0].GetProperty("result").GetString());
        Assert.Equal(0, await fx.DbAsync(db => db.Jobs.IgnoreQueryFilters().CountAsync(j => j.Kind == JobKinds.NetworkIsolate && j.OrganizationId == org.OrgId)));

        // The agent answers "unknown check" for a check it does not know: stored as unsupported, no drift alert.
        var policy = (await admin.PostJsonAsync("/api/v1/policies", new { name = "Fw on " + U, check = "firewall.enabled", @params = new { }, organizationId = org.OrgId })).GetProperty("id").GetGuid();
        await admin.PostJsonAsync($"/api/v1/policies/{policy}/assignments", new { scopeType = "Organization", scopeId = org.OrgId });
        Assert.True((await admin.PostAsync("/api/v1/policies/evaluate", new { organizationId = org.OrgId })).IsSuccessStatusCode);
        var job = await old.NextJobAsync("policy.evaluate");
        await old.CompleteAsync(job, result: new { results = new[] { new { policyId = policy, check = "firewall.enabled", compliant = false, remediated = false, detail = "unknown check" } } });
        var compliance = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{old.DeviceId}/compliance"), c => c.GetArrayLength() == 1);
        Assert.False(compliance[0].GetProperty("supported").GetBoolean());
        Assert.Contains("update the agent", compliance[0].GetProperty("detail").GetString(), StringComparison.Ordinal);
        // The org summary counts it as unsupported, not non-compliant, so the device stays compliant (no drift).
        var summary = await admin.GetJsonAsync($"/api/v1/compliance?organizationId={org.OrgId}");
        Assert.Equal((1, 1), (summary.GetProperty("devices").GetInt32(), summary.GetProperty("compliantDevices").GetInt32()));
        var fw = summary.GetProperty("policies").EnumerateArray().Single(p => p.GetProperty("policyId").GetGuid() == policy);
        Assert.Equal((0, 1), (fw.GetProperty("nonCompliant").GetInt32(), fw.GetProperty("unsupported").GetInt32()));
        Assert.Equal(0, summary.GetProperty("nonCompliant").GetArrayLength());
        var alerts = await admin.GetJsonAsync($"/api/v1/alerts?deviceId={old.DeviceId}");
        Assert.DoesNotContain(alerts.GetProperty("items").EnumerateArray(), a => a.GetProperty("type").GetString() == "compliance.drift");
    }

    private static async Task<HttpResponseMessage> StepUpThen(ApiClient client, Func<Task<HttpResponseMessage>> call)
    {
        await client.StepUpAsync();
        return await call();
    }

    // ----- 10f: UniFi controller, guest and office Wi-Fi -----

    [Fact]
    public void Controller_address_and_subnet_rules()
    {
        Assert.Equal("https://unifi.office.lan", UniFiRules.NormalizeBaseUrl("https://unifi.office.lan/"));
        Assert.Equal("https://192.168.1.1:8443", UniFiRules.NormalizeBaseUrl("https://192.168.1.1:8443"));
        Assert.Null(UniFiRules.NormalizeBaseUrl("http://192.168.1.1"));
        Assert.Null(UniFiRules.NormalizeBaseUrl("https://user:pw@192.168.1.1"));
        Assert.Null(UniFiRules.NormalizeBaseUrl("https://192.168.1.1/manage"));
        Assert.Null(UniFiRules.NormalizeBaseUrl("https://127.0.0.1"));
        Assert.Null(UniFiRules.NormalizeBaseUrl("https://169.254.169.254"));
        Assert.Null(UniFiRules.NormalizeBaseUrl("https://localhost"));
        Assert.False(UniFiRules.AllowedTarget(System.Net.IPAddress.Parse("::1")));
        Assert.True(UniFiRules.AllowedTarget(System.Net.IPAddress.Parse("10.0.0.1")));
        Assert.Equal(("192.168.20.1/24", "192.168.20.10", "192.168.20.254"), NetworkControllerEndpoints.ParseSubnet("192.168.20.1/24"));
        Assert.Null(NetworkControllerEndpoints.ParseSubnet("8.8.8.1/24"));
        Assert.Null(NetworkControllerEndpoints.ParseSubnet("192.168.20.0/24"));
        Assert.Null(NetworkControllerEndpoints.ParseSubnet("192.168.20.1/8"));
    }

    [Fact]
    public async Task Unifi_controller_setup_wifi_sync_guest_alert_and_blocking()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Uni " + U);
        var host = $"unifi-{U}.example.test";
        var unifi = fx.UniFi.Add(host);
        unifi.Devices.Add(new() { ["mac"] = "f0:9f:c2:00:00:01", ["name"] = "Lobby AP", ["model"] = "U6-Pro", ["type"] = "uap", ["ip"] = "192.168.1.20", ["state"] = 1, ["version"] = "6.6.77", ["num_sta"] = 3 });

        // Configuring a controller is partner-wide and needs a fresh code; the secret never comes back.
        var netAdmin = await fx.CreateUserAsync($"uniorg-{U}@example.test", BuiltInRoles.NetworkAdmin, ScopeType.Organization, org.OrgId);
        await netAdmin.StepUpAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await netAdmin.PostAsync("/api/v1/network-controllers", new { organizationId = org.OrgId, name = "x", baseUrl = $"https://{host}", secret = "k" })).StatusCode);
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/network-controllers", new { organizationId = org.OrgId, name = "x", baseUrl = "https://169.254.169.254", secret = "k" })).StatusCode);
        var created = await admin.PostAsync("/api/v1/network-controllers", new { organizationId = org.OrgId, siteId = org.SiteId, name = "Office UDM", baseUrl = $"https://{host}", authMode = "apikey", secret = FakeUniFi.ApiKey });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var createdText = await created.Content.ReadAsStringAsync();
        Assert.DoesNotContain(FakeUniFi.ApiKey, createdText, StringComparison.Ordinal);
        var controllerId = JsonDocument.Parse(createdText).RootElement.GetProperty("id").GetGuid();

        // The org's Network Admin can see it and its devices.
        var overview = await netAdmin.GetJsonAsync($"/api/v1/network-controllers/{controllerId}/overview");
        Assert.True(overview.GetProperty("reachable").GetBoolean());
        Assert.Equal("Lobby AP", overview.GetProperty("devices")[0].GetProperty("name").GetString());
        Assert.Equal("online", overview.GetProperty("devices")[0].GetProperty("state").GetString());

        // Separate office and guest Wi-Fi.
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync($"/api/v1/network-controllers/{controllerId}/wifi-setup",
            new { office = new { ssid = "Dranzo", passphrase = "short", vlan = 10, subnet = "192.168.10.1/24" } })).StatusCode);
        var setup = await admin.PostJsonAsync($"/api/v1/network-controllers/{controllerId}/wifi-setup", new
        {
            office = new { ssid = "Dranzo-Office", passphrase = "office-secret-123", vlan = 10, subnet = "192.168.10.1/24" },
            guest = new { ssid = "Dranzo-Guest", passphrase = "guest-pass-456", vlan = 20, subnet = "192.168.20.1/24", clientIsolation = true },
        });
        Assert.Equal(4, setup.GetProperty("steps").GetArrayLength());
        var guestNet = unifi.Networks.Single(n => n["vlan"]!.GetValue<int>() == 20);
        Assert.Equal("guest", guestNet["purpose"]!.GetValue<string>());
        Assert.Equal("192.168.20.10", guestNet["dhcpd_start"]!.GetValue<string>());
        var guestWlan = unifi.Wlans.Single(w => w["name"]!.GetValue<string>() == "Dranzo-Guest");
        Assert.True(guestWlan["is_guest"]!.GetValue<bool>());
        Assert.True(guestWlan["l2_isolation"]!.GetValue<bool>());
        Assert.Equal(guestNet["_id"]!.GetValue<string>(), guestWlan["networkconf_id"]!.GetValue<string>());
        Assert.Equal("apg-all", guestWlan["ap_group_ids"]![0]!.GetValue<string>());
        var officeWlan = unifi.Wlans.Single(w => w["name"]!.GetValue<string>() == "Dranzo-Office");
        Assert.False(officeWlan["is_guest"]!.GetValue<bool>());
        Assert.Equal("wpapsk", officeWlan["security"]!.GetValue<string>());
        // Running it again changes nothing.
        await admin.StepUpAsync();
        var again = await admin.PostJsonAsync($"/api/v1/network-controllers/{controllerId}/wifi-setup", new
        {
            office = new { ssid = "Dranzo-Office", passphrase = "office-secret-123", vlan = 10, subnet = "192.168.10.1/24" },
        });
        Assert.All(again.GetProperty("steps").EnumerateArray(), st => Assert.Contains("already exists", st.GetString(), StringComparison.Ordinal));
        Assert.Equal(2, unifi.Wlans.Count);
        // Passwords never reach the audit log.
        var audit = await admin.GetJsonAsync($"/api/v1/audit?organizationId={org.OrgId}&action=network_controller.wifi_setup");
        Assert.DoesNotContain("office-secret-123", audit.GetRawText(), StringComparison.Ordinal);
        var allAudit = await admin.GetJsonAsync($"/api/v1/audit?organizationId={org.OrgId}&pageSize=200");
        Assert.DoesNotContain(FakeUniFi.ApiKey, allAudit.GetRawText(), StringComparison.Ordinal);

        // Sync: a company laptop on the guest Wi-Fi raises an alert; clients become discovered devices.
        await using var laptop = await TestAgent.EnrollAsync(fx, org.Token, "uni-laptop", os: "windows");
        await laptop.SendAsync("inventory", new
        {
            collectedAt = DateTimeOffset.UtcNow, hostname = "uni-laptop", os = new { family = "windows", name = "Windows 11", version = "", build = "", kernel = "" },
            arch = "amd64", network = new[] { new { name = "Wi-Fi", mac = "04:d9:f5:0a:0b:0c", ipv4 = new[] { "192.168.20.33" }, ipv6 = Array.Empty<string>() } },
        });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{laptop.DeviceId}"), d => d.GetProperty("osName").GetString() == "Windows 11");
        unifi.Clients.Add(new() { ["mac"] = "04:d9:f5:0a:0b:0c", ["ip"] = "192.168.20.33", ["hostname"] = "uni-laptop", ["essid"] = "Dranzo-Guest", ["is_guest"] = true });
        unifi.Clients.Add(new() { ["mac"] = "aa:bb:cc:00:00:07", ["ip"] = "192.168.20.40", ["hostname"] = "visitor-phone", ["essid"] = "Dranzo-Guest", ["is_guest"] = true, ["oui"] = "Apple" });
        var synced = await admin.PostJsonAsync($"/api/v1/network-controllers/{controllerId}/sync", new { });
        Assert.Equal(JsonValueKind.Null, synced.GetProperty("lastError").ValueKind);
        var alerts = await admin.GetJsonAsync($"/api/v1/alerts?deviceId={laptop.DeviceId}");
        Assert.Contains(alerts.GetProperty("items").EnumerateArray(), a => a.GetProperty("type").GetString() == "network.device_on_guest");
        Assert.Equal("Dranzo-Guest", (await admin.GetJsonAsync($"/api/v1/devices/{laptop.DeviceId}")).GetProperty("wifiSsid").GetString());
        var phone = (await admin.GetJsonAsync($"/api/v1/network/devices?organizationId={org.OrgId}&search=visitor")).GetProperty("items")[0];
        Assert.Equal("Apple", phone.GetProperty("vendor").GetString());

        // Blocking a discovered device blocks it on the Wi-Fi.
        var block = await admin.PostJsonAsync($"/api/v1/network/devices/{phone.GetProperty("id").GetGuid()}/status", new { status = "blocked" });
        Assert.Contains("applied on the controller", block.GetProperty("controller").GetString(), StringComparison.Ordinal);
        Assert.Contains(unifi.Commands, cmd => cmd["cmd"]!.GetValue<string>() == "block-sta" && cmd["mac"]!.GetValue<string>() == "aa:bb:cc:00:00:07");

        // A wrong key is reported, not thrown.
        await admin.StepUpAsync();
        await admin.PatchAsync($"/api/v1/network-controllers/{controllerId}", new { secret = "wrong" });
        var failed = await admin.PostJsonAsync($"/api/v1/network-controllers/{controllerId}/sync", new { });
        Assert.Contains("refused the credentials", failed.GetProperty("lastError").GetString(), StringComparison.Ordinal);

        // Another organization's Network Admin sees nothing.
        var other = await fx.SeedOrgAsync("Uni other " + U);
        var outsider = await fx.CreateUserAsync($"uniout-{U}@example.test", BuiltInRoles.NetworkAdmin, ScopeType.Organization, other.OrgId);
        Assert.Equal(HttpStatusCode.NotFound, (await outsider.GetAsync($"/api/v1/network-controllers/{controllerId}/overview")).StatusCode);
        Assert.Empty((await outsider.GetJsonAsync("/api/v1/network-controllers")).EnumerateArray());
    }

    // ----- 10g: 802.1X / RADIUS -----

    [Fact]
    public void Network_ca_is_name_constrained_and_issues_wifi_certificates_and_crls()
    {
        var store = new Dranzo.Infrastructure.Security.FileKeyStore(Path.Combine(Path.GetTempPath(), "netca-" + Guid.NewGuid().ToString("N")));
        var ca = new Dranzo.Infrastructure.Security.NetworkCertificateAuthority(store);
        var org = Guid.NewGuid();
        using var root = ca.GetOrCreate(org);
        var nc = root.Extensions["2.5.29.30"];
        Assert.NotNull(nc);
        Assert.True(nc!.Critical);
        Assert.Contains("dranzo-radius.invalid", System.Text.Encoding.ASCII.GetString(nc.RawData), StringComparison.Ordinal);
        Assert.Equal(root.Thumbprint, ca.GetOrCreate(org).Thumbprint); // stable

        // The RADIUS server certificate chains to the CA.
        var (serverPem, _) = ca.IssueServer(org);
        using var server = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(serverPem);
        using var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
        chain.ChainPolicy.TrustMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
        Assert.True(chain.Build(server), string.Join(", ", chain.ChainStatus.Select(st => st.StatusInformation)));

        // A client certificate from a device CSR; the CSR's own subject is ignored.
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var csr = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=evil.example.com", key, System.Security.Cryptography.HashAlgorithmName.SHA256).CreateSigningRequestPem();
        var device = Guid.NewGuid();
        var (clientPem, serial, _, _) = ca.IssueClient(org, csr, device);
        using var client = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(clientPem);
        Assert.Equal($"CN={device:D}, O=DranzoRMM Wi-Fi", client.Subject);
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() => ca.IssueClient(org, csr.Replace("A", "B", StringComparison.Ordinal), device));

        // The CRL lists revoked serials and is signed by the CA.
        var crlPem = ca.CrlPem(org, [(serial, DateTimeOffset.UtcNow)], 7, DateTimeOffset.UtcNow);
        var crl = System.Security.Cryptography.X509Certificates.CertificateRevocationListBuilder.Load(
            Convert.FromBase64String(string.Concat(crlPem.Split('\n').Where(l => !l.StartsWith("-----", StringComparison.Ordinal)))), out var number);
        Assert.Equal(7, (int)number);
        Assert.True(crl.RemoveEntry(Convert.FromHexString(serial)));
    }

    [Fact]
    public async Task Radius_enrollment_issues_certificates_installs_profiles_and_revokes()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Rad " + U);
        await using var win = await TestAgent.EnrollAsync(fx, org.Token, "rad-win", os: "windows");

        // Only partner-wide network admins, with a fresh code.
        var netAdmin = await fx.CreateUserAsync($"radorg-{U}@example.test", BuiltInRoles.NetworkAdmin, ScopeType.Organization, org.OrgId);
        await netAdmin.StepUpAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await netAdmin.PostAsync("/api/v1/radius", new { organizationId = org.OrgId, clientsCidr = "192.168.1.0/24", officeSsid = "Office" })).StatusCode);
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/radius", new { organizationId = org.OrgId, clientsCidr = "0.0.0.0/0", officeSsid = "Office" })).StatusCode);
        var config = await admin.PostJsonAsync("/api/v1/radius", new { organizationId = org.OrgId, clientsCidr = "192.168.1.0/24", officeSsid = "Dranzo-Office" });
        var configId = config.GetProperty("id").GetGuid();

        // The bundle holds a working FreeRADIUS configuration; its download is audited.
        await admin.StepUpAsync();
        var bundle = await admin.GetAsync($"/api/v1/radius/{configId}/bundle.zip");
        Assert.Equal(HttpStatusCode.OK, bundle.StatusCode);
        using (var zip = new System.IO.Compression.ZipArchive(await bundle.Content.ReadAsStreamAsync()))
        {
            Assert.Equal(["Dockerfile", "README.txt", "certs/ca.pem", "certs/server.key", "certs/server.pem", "clients.conf", "docker-compose.yml", "eap", "update-crl.sh"], zip.Entries.Select(e => e.FullName).Order(StringComparer.Ordinal));
            using var reader = new StreamReader(zip.GetEntry("clients.conf")!.Open());
            Assert.Contains("ipaddr = 192.168.1.0/24", await reader.ReadToEndAsync(), StringComparison.Ordinal);
        }
        Assert.Equal(1, (await admin.GetJsonAsync($"/api/v1/audit?organizationId={org.OrgId}&action=radius.bundle_download")).GetProperty("total").GetInt32());

        // Enroll: the agent sends a CSR, gets the certificate and the Wi-Fi profile.
        await admin.StepUpAsync();
        var enroll = await admin.PostJsonAsync($"/api/v1/radius/{configId}/enroll", new { });
        Assert.Equal(1, enroll.GetProperty("deviceCount").GetInt32());
        var req = await win.NextJobAsync("network.cert.request");
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var csr = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=x", key, System.Security.Cryptography.HashAlgorithmName.SHA256).CreateSigningRequestPem();
        await win.CompleteAsync(req, result: new { csr });
        var install = await win.NextJobAsync("network.wifi.install");
        var spec = install.Payload.GetProperty("spec");
        Assert.Equal("Dranzo-Office", spec.GetProperty("ssid").GetString());
        Assert.Contains("BEGIN CERTIFICATE", spec.GetProperty("caPem").GetString(), StringComparison.Ordinal);
        using var cert = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(spec.GetProperty("certPem").GetString());
        Assert.Contains(win.DeviceId.ToString("D"), cert.Subject, StringComparison.Ordinal);
        await win.CompleteAsync(install, result: new { installed = true });
        var status = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/radius?organizationId={org.OrgId}"), r => r[0].GetProperty("installedCertificates").GetInt32() == 1);
        Assert.Equal(1, status[0].GetProperty("activeCertificates").GetInt32());

        // The CRL is public and lists the certificate once the device is revoked.
        var anonymous = fx.NewClient();
        var crl0 = await anonymous.GetAsync($"/api/v1/pki/network/{org.OrgId}/crl.pem");
        Assert.Equal(HttpStatusCode.OK, crl0.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await anonymous.GetAsync($"/api/v1/pki/network/{Guid.NewGuid()}/crl.pem")).StatusCode);
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/v1/devices/{win.DeviceId}/revoke")).StatusCode);
        var crlPem = await (await anonymous.GetAsync($"/api/v1/pki/network/{org.OrgId}/crl.pem")).Content.ReadAsStringAsync();
        var crl = System.Security.Cryptography.X509Certificates.CertificateRevocationListBuilder.Load(
            Convert.FromBase64String(string.Concat(crlPem.Split('\n').Where(l => !l.StartsWith("-----", StringComparison.Ordinal)))), out _);
        Assert.True(crl.RemoveEntry(cert.SerialNumberBytes.Span));

        // Another organization sees nothing.
        var other = await fx.SeedOrgAsync("Rad other " + U);
        var outsider = await fx.CreateUserAsync($"radout-{U}@example.test", BuiltInRoles.NetworkAdmin, ScopeType.Organization, other.OrgId);
        Assert.Empty((await outsider.GetJsonAsync($"/api/v1/radius?organizationId={org.OrgId}")).EnumerateArray());
    }

    /// <summary>Writes a RADIUS bundle to DRANZO_RADIUS_BUNDLE_OUT for a check with real FreeRADIUS (opt-in).</summary>
    [Fact]
    public void Write_radius_bundle_for_freeradius_check()
    {
        var outDir = Environment.GetEnvironmentVariable("DRANZO_RADIUS_BUNDLE_OUT");
        if (string.IsNullOrEmpty(outDir))
        {
            return;
        }
        var ca = new Dranzo.Infrastructure.Security.NetworkCertificateAuthority(new Dranzo.Infrastructure.Security.FileKeyStore(Path.Combine(outDir, "keys")));
        var org = Guid.NewGuid();
        var (cert, key) = ca.IssueServer(org);
        // Loopback here only so eapol_test inside the same container may ask; real bundles require a private range.
        var config = new RadiusConfig { Id = Guid.NewGuid(), OrganizationId = org, ClientsCidr = "127.0.0.0/8", OfficeSsid = "Office", SharedSecretProtected = "" };
        File.WriteAllBytes(Path.Combine(outDir, "bundle.zip"), RadiusEndpoints.Bundle(config, "test-shared-secret", ca.CaPem(org), cert, key, "http://127.0.0.1:9/crl.pem"));
        string revokedSerial = "";
        foreach (var name in new[] { "good", "revoked" })
        {
            using var k = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            var csr = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=x", k, System.Security.Cryptography.HashAlgorithmName.SHA256).CreateSigningRequestPem();
            var (pem, serial, _, _) = ca.IssueClient(org, csr, Guid.NewGuid());
            File.WriteAllText(Path.Combine(outDir, name + ".pem"), pem + "\n");
            File.WriteAllText(Path.Combine(outDir, name + ".key"), k.ExportPkcs8PrivateKeyPem() + "\n");
            revokedSerial = serial;
        }
        File.WriteAllText(Path.Combine(outDir, "crl.pem"), ca.CrlPem(org, [(revokedSerial, DateTimeOffset.UtcNow.AddMinutes(-1))], 1, DateTimeOffset.UtcNow) + "\n");
        File.WriteAllText(Path.Combine(outDir, "ca.pem"), ca.CaPem(org) + "\n");
    }
}
