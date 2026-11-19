using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dranzo.Api.Features;
using Dranzo.Api.Notifications;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Dranzo.Tests;

[Collection("server")]
public class SecurityAlertTests(ServerFixture fx)
{
    private static string U => Guid.NewGuid().ToString("N")[..6];

    private static object Posture(bool avOn = true, bool firewall = true, bool encrypted = true, params string[] admins) => new
    {
        collectedAt = DateTimeOffset.UtcNow,
        antivirus = new[] { new { name = "Defender", enabled = avOn, upToDate = true, source = "defender" } },
        firewall = new { enabled = firewall, detail = "" },
        diskEncryption = new[] { new { volume = "C:", method = "bitlocker", status = encrypted ? "encrypted" : "decrypted" } },
        localAdmins = admins.Length == 0 ? ["Administrator"] : admins,
        screenLock = new { enabled = true, timeoutSeconds = 300 },
        pendingReboot = false, listeningPorts = Array.Empty<object>(), unsupported = Array.Empty<string>(),
    };

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

    private async Task<int> DeliverAsync()
    {
        await using var scope = fx.App.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
        return await NotificationSender.ProcessAsync(scope.ServiceProvider, default);
    }

    private static Task<JsonElement> AlertsAsync(ApiClient c, Guid deviceId, string state = "open") => c.GetJsonAsync($"/api/v1/alerts?deviceId={deviceId}&state={state}");

    [Fact]
    public async Task Antivirus_off_raises_alert_notifies_signed_webhook_and_resolves_when_fixed()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Av " + U);
        using var receiver = new WebhookReceiver();
        var secret = "whsec-" + U;
        var channel = await admin.PostJsonAsync("/api/v1/notification-channels", new { name = "hook " + U, type = "webhook", url = receiver.Url(), secret, organizationId = org.OrgId });
        var channelId = channel.GetProperty("id").GetGuid();
        await admin.PostJsonAsync("/api/v1/alert-rules", new { name = "AV for org " + U, type = "antivirus.off", severity = "critical", organizationId = org.OrgId, channelIds = new[] { channelId } });
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "av-host", os: "windows");

        await agent.SendAsync("posture", Posture(avOn: true));
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{agent.DeviceId}/posture"), p => p.ValueKind == JsonValueKind.Object);
        Assert.Equal(0, (await AlertsAsync(admin, agent.DeviceId)).GetProperty("total").GetInt32());

        await agent.SendAsync("posture", Posture(avOn: false)); // someone turned the antivirus off
        var alerts = await UntilAsync(() => AlertsAsync(admin, agent.DeviceId), a => a.GetProperty("items").EnumerateArray().Any(x => x.GetProperty("type").GetString() == "antivirus.off" && x.GetProperty("severity").GetString() == "critical"));
        Assert.True(await DeliverAsync() >= 1);
        Assert.True(receiver.Received.TryDequeue(out var hook));
        using var doc = JsonDocument.Parse(hook!.Body);
        Assert.Equal("alert.opened", doc.RootElement.GetProperty("type").GetString());
        Assert.Equal(agent.DeviceId, doc.RootElement.GetProperty("deviceId").GetGuid());
        var mac = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(hook.Headers["X-Dranzo-Timestamp"] + "." + hook.Body));
        Assert.Equal("sha256=" + Convert.ToHexStringLower(mac), hook.Headers["X-Dranzo-Signature"]);

        // Reporting the same state again does not open a second alert.
        await agent.SendAsync("posture", Posture(avOn: false));
        await agent.SendAsync("heartbeat", new { seq = 1 });
        await agent.WaitForAsync("heartbeat.ack");
        Assert.Equal(alerts.GetProperty("items").EnumerateArray().Count(x => x.GetProperty("type").GetString() == "antivirus.off"),
            (await AlertsAsync(admin, agent.DeviceId)).GetProperty("items").EnumerateArray().Count(x => x.GetProperty("type").GetString() == "antivirus.off"));

        await agent.SendAsync("posture", Posture(avOn: true));
        await UntilAsync(() => AlertsAsync(admin, agent.DeviceId), a => a.GetProperty("items").EnumerateArray().All(x => x.GetProperty("type").GetString() != "antivirus.off"));
        var summary = await admin.GetJsonAsync($"/api/v1/security/posture?organizationId={org.OrgId}");
        Assert.Equal(0, summary.GetProperty("antivirusIssues").GetInt32());

        // The channel listing never exposes the URL path or the secret.
        var listed = await (await admin.GetAsync("/api/v1/notification-channels")).Content.ReadAsStringAsync();
        Assert.DoesNotContain(secret, listed);
        Assert.DoesNotContain("/hook", listed);
    }

    [Fact]
    public async Task Full_disk_offline_device_firewall_encryption_and_new_admin_raise_alerts()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Mon " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "mon-host", os: "windows");
        bool Has(JsonElement a, string type) => a.GetProperty("items").EnumerateArray().Any(x => x.GetProperty("type").GetString() == type);

        await agent.SendAsync("inventory", new { hostname = "mon-host", os = new { name = "Windows 11" }, disks = new[] { new { device = "C:", mountPoint = "C:", fsType = "NTFS", totalBytes = 100L << 30, freeBytes = 5L << 30 } } });
        var alerts = await UntilAsync(() => AlertsAsync(admin, agent.DeviceId), a => Has(a, "disk.usage"));
        Assert.Contains("95%", alerts.GetProperty("items").EnumerateArray().First(x => x.GetProperty("type").GetString() == "disk.usage").GetProperty("title").GetString());
        await agent.SendAsync("inventory", new { hostname = "mon-host", os = new { name = "Windows 11" }, disks = new[] { new { device = "C:", mountPoint = "C:", fsType = "NTFS", totalBytes = 100L << 30, freeBytes = 50L << 30 } } });
        await UntilAsync(() => AlertsAsync(admin, agent.DeviceId), a => !Has(a, "disk.usage"));

        await agent.SendAsync("posture", Posture(admins: ["Administrator"]));
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{agent.DeviceId}/posture"), p => p.ValueKind == JsonValueKind.Object);
        await agent.SendAsync("posture", Posture(firewall: false, encrypted: false, admins: ["Administrator", "eviladmin"]));
        alerts = await UntilAsync(() => AlertsAsync(admin, agent.DeviceId), a => Has(a, "firewall.off") && Has(a, "encryption.off") && Has(a, "localadmin.new"));
        Assert.Contains("eviladmin", alerts.GetProperty("items").EnumerateArray().First(x => x.GetProperty("type").GetString() == "localadmin.new").GetProperty("detail").GetString());

        // Offline for longer than the rule's 30 minutes.
        await agent.CloseAsync();
        await fx.DbAsync(db => db.Devices.Where(d => d.Id == agent.DeviceId).ExecuteUpdateAsync(s => s.SetProperty(d => d.IsOnline, false)));
        fx.Clock.Advance(TimeSpan.FromMinutes(31));
        await using (var scope = fx.App.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            await scope.ServiceProvider.GetRequiredService<AlertEngine>().EvaluateDeviceAsync(agent.DeviceId, default);
        }
        admin = await fx.AdminAsync();
        Assert.True(Has(await AlertsAsync(admin, agent.DeviceId), "device.offline"));
        await agent.ConnectAsync(); // back online
        await UntilAsync(() => AlertsAsync(admin, agent.DeviceId), a => !Has(a, "device.offline"));

        // Acknowledge and resolve by hand.
        admin = await fx.AdminAsync();
        var adminAlert = (await AlertsAsync(admin, agent.DeviceId)).GetProperty("items").EnumerateArray().First(x => x.GetProperty("type").GetString() == "localadmin.new").GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/v1/alerts/{adminAlert}/acknowledge")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/v1/alerts/{adminAlert}/resolve")).StatusCode);
        Assert.Contains((await AlertsAsync(admin, agent.DeviceId, "resolved")).GetProperty("items").EnumerateArray(), x => x.GetProperty("id").GetGuid() == adminAlert);
    }

    [Fact]
    public async Task Agent_refusing_a_command_for_signature_reasons_raises_a_tamper_alert()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Tamper " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "tamper-host");
        await agent.SendAsync("error", new { code = "bad_signature", message = "signature did not verify", refId = Guid.NewGuid() });
        var alerts = await UntilAsync(() => AlertsAsync(admin, agent.DeviceId), a => a.GetProperty("total").GetInt32() == 1);
        Assert.Equal("agent.tamper", alerts.GetProperty("items")[0].GetProperty("type").GetString());
        Assert.Equal("critical", alerts.GetProperty("items")[0].GetProperty("severity").GetString());
        Assert.Equal(1, (await admin.GetJsonAsync($"/api/v1/audit?deviceId={agent.DeviceId}&action=agent.command_refused")).GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Slack_and_teams_channels_get_their_own_payload_shape_and_failures_are_retried()
    {
        var admin = await fx.AdminAsync();
        using var receiver = new WebhookReceiver();
        var slack = (await admin.PostJsonAsync("/api/v1/notification-channels", new { name = "slack " + U, type = "slack", url = receiver.Url("/slack") })).GetProperty("id").GetGuid();
        var teams = (await admin.PostJsonAsync("/api/v1/notification-channels", new { name = "teams " + U, type = "teams", url = receiver.Url("/teams") })).GetProperty("id").GetGuid();
        receiver.StatusCode = 500;
        Assert.Equal(HttpStatusCode.Accepted, (await admin.PostAsync($"/api/v1/notification-channels/{slack}/test")).StatusCode);
        await DeliverAsync();
        var deliveries = await admin.GetJsonAsync($"/api/v1/notification-channels/{slack}/deliveries");
        Assert.Equal(1, deliveries[0].GetProperty("attempts").GetInt32());
        Assert.Contains("500", deliveries[0].GetProperty("lastError").GetString());
        receiver.Received.Clear();

        receiver.StatusCode = 200;
        await admin.PostAsync($"/api/v1/notification-channels/{teams}/test");
        fx.Clock.Advance(TimeSpan.FromMinutes(2)); // past the first retry delay
        await DeliverAsync();
        var got = receiver.Received.ToDictionary(r => r.Path, r => JsonDocument.Parse(r.Body).RootElement);
        Assert.Contains("test notification", got["/slack"].GetProperty("text").GetString());
        Assert.Equal("AdaptiveCard", got["/teams"].GetProperty("attachments")[0].GetProperty("content").GetProperty("type").GetString());
    }

    [Theory]
    [InlineData("http://example.com/hook", false)]
    [InlineData("https://127.0.0.1/hook", false)]
    [InlineData("https://10.1.2.3/hook", false)]
    [InlineData("https://169.254.169.254/latest/meta-data", false)]
    [InlineData("https://[::1]/hook", false)]
    [InlineData("https://192.168.1.10:8443/x", false)]
    [InlineData("https://user:pass@example.com/x", false)]
    [InlineData("ftp://example.com/x", false)]
    [InlineData("https://hooks.example.com/services/T000", true)]
    public void Webhook_urls_must_be_https_and_public(string url, bool ok) =>
        Assert.Equal(ok, SafeOutbound.ValidateUrl(url, allowPrivate: false) is null);

    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("172.20.1.1", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("8.8.8.8", true)]
    [InlineData("2606:4700:4700::1111", true)]
    public void Only_public_addresses_are_connectable(string ip, bool ok) => Assert.Equal(ok, SafeOutbound.IsPublic(IPAddress.Parse(ip)));

    [Fact]
    public async Task Hostname_that_resolves_to_a_private_address_is_blocked_at_connect_time()
    {
        using var http = SafeOutbound.CreateClient(allowPrivate: false);
        var ex = await Assert.ThrowsAsync<HttpRequestException>(() => http.GetAsync("https://localhost:9/"));
        Assert.Contains("non-public", ex.ToString());
    }

    [Fact]
    public async Task Vulnerabilities_are_matched_from_nvd_and_kev_data()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Vuln " + U);
        var product = "ziptool" + U;
        var (cveRange, cveOther) = ($"CVE-2099-{Random.Shared.Next(10000, 99999)}", $"CVE-2099-{Random.Shared.Next(10000, 99999)}");
        var nvd = JsonDocument.Parse("""
        {"totalResults":2,"vulnerabilities":[
          {"cve":{"id":"CVE_RANGE","published":"2026-01-01T00:00:00.000","descriptions":[{"lang":"en","value":"Heap overflow in PRODUCT"}],
            "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]},
            "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:zipinc:PRODUCT:*:*:*:*:*:*:*:*","versionStartIncluding":"2.0","versionEndExcluding":"2.5.3"}]}]}]}},
          {"cve":{"id":"CVE_OTHER","descriptions":[{"lang":"en","value":"Old bug"}],
            "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM"}}]},
            "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:zipinc:PRODUCT:*:*:*:*:*:*:*:*","versionEndExcluding":"1.0"}]}]}]}}
        ]}
        """.Replace("CVE_RANGE", cveRange).Replace("CVE_OTHER", cveOther).Replace("PRODUCT", product)).RootElement;
        await fx.DbAsync(async db =>
        {
            Assert.Equal(2, await VulnerabilityFeed.ImportNvdAsync(db, nvd, DateTimeOffset.UtcNow, default));
            var kev = JsonDocument.Parse("""{"vulnerabilities":[{"cveID":"CVE_RANGE"}]}""".Replace("CVE_RANGE", cveRange)).RootElement;
            Assert.Equal(1, await VulnerabilityFeed.ImportKevAsync(db, kev, DateTimeOffset.UtcNow, default));
        });

        await using var win = await TestAgent.EnrollAsync(fx, org.Token, "vuln-win", os: "windows");
        await using var linux = await TestAgent.EnrollAsync(fx, org.Token, "vuln-linux");
        await win.SendAsync("software.inventory", new { items = new object[] { new { name = $"{product} 2.4.1 (x64)", version = "2.4.1", publisher = "ZipInc", source = "registry" }, new { name = "Unrelated", version = "1.0", source = "registry" } } });
        // The same upstream version from a distribution package is deliberately not matched (backported fixes).
        await linux.SendAsync("software.inventory", new { items = new object[] { new { name = product, version = "2.4.1-1ubuntu3", source = "dpkg" } } });

        var vulns = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{win.DeviceId}/vulnerabilities"), v => v.GetArrayLength() == 1);
        Assert.Equal(cveRange, vulns[0].GetProperty("cveId").GetString());
        Assert.Equal("critical", vulns[0].GetProperty("severity").GetString());
        Assert.True(vulns[0].GetProperty("knownExploited").GetBoolean());
        await linux.SendAsync("heartbeat", new { seq = 1 });
        await linux.WaitForAsync("heartbeat.ack");
        Assert.Equal(0, (await admin.GetJsonAsync($"/api/v1/devices/{linux.DeviceId}/vulnerabilities")).GetArrayLength());
        var agg = await admin.GetJsonAsync($"/api/v1/vulnerabilities?organizationId={org.OrgId}&knownExploited=true");
        Assert.Equal(1, agg.GetProperty("total").GetInt32());
        // A known-exploited vulnerability raises an alert by default.
        await UntilAsync(() => AlertsAsync(admin, win.DeviceId), a => a.GetProperty("items").EnumerateArray().Any(x => x.GetProperty("type").GetString() == "vulnerability.known_exploited"));

        // After the software is updated the finding and the alert go away.
        await win.SendAsync("software.inventory", new { items = new object[] { new { name = $"{product} 2.5.3 (x64)", version = "2.5.3", publisher = "ZipInc", source = "registry" } } });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{win.DeviceId}/vulnerabilities"), v => v.GetArrayLength() == 0);
        await UntilAsync(() => AlertsAsync(admin, win.DeviceId), a => a.GetProperty("items").EnumerateArray().All(x => x.GetProperty("type").GetString() != "vulnerability.known_exploited"));
    }

    [Theory]
    [InlineData("1.2.10", "1.2.9", 1)]
    [InlineData("2.0", "2.0.0", 0)]
    [InlineData("120.0.6099.71", "120.0.6099.130", -1)]
    [InlineData("3.0.2-0ubuntu1", "3.0.2", 0)]
    public void Versions_compare_numerically(string a, string b, int expected) => Assert.Equal(expected, VersionCompare.Compare(a, b));

    [Fact]
    public void Mac_installer_receipts_do_not_duplicate_their_app()
    {
        static (InstalledSoftware, List<(string Product, bool Full)>) Item(string name, string version, string source, string? packageId)
        {
            var s = new InstalledSoftware { Name = name, Version = version, Source = source, PackageId = packageId };
            return (s, VulnerabilityMatcher.Candidates(name, packageId));
        }
        var items = new List<(InstalledSoftware Software, List<(string Product, bool Full)> Candidates)>
        {
            Item("Xcode", "26.6", "app", "com.apple.dt.Xcode"),
            Item("com.apple.pkg.Xcode", "26.6.0.0.1.1781584895", "pkgutil", "com.apple.pkg.Xcode"),
            // A receipt with no app entry (command-line tools) is still matched.
            Item("com.example.pkg.ToolChain", "3.1", "pkgutil", "com.example.pkg.ToolChain"),
            // Same product as an app but an older release: a separate installation, still matched.
            Item("Python", "3.13.1", "app", "org.python.IDLE"),
            Item("org.python.Python.PythonFramework-3.9", "3.9.6", "pkgutil", "org.python.python"),
        };
        var kept = VulnerabilityMatcher.WithoutReceiptDuplicates(items);
        Assert.Contains(kept, k => k.Software.Name == "Xcode");
        Assert.DoesNotContain(kept, k => k.Software.Name == "com.apple.pkg.Xcode" && k.Candidates.Any(c => c.Product == "xcode"));
        Assert.Contains(kept, k => k.Software.Name == "com.example.pkg.ToolChain" && k.Candidates.Any(c => c.Product == "toolchain"));
        Assert.Contains(kept, k => k.Software.Name == "org.python.Python.PythonFramework-3.9" && k.Candidates.Any(c => c.Product == "python"));
    }

    [Fact]
    public async Task Alerts_rules_and_channels_respect_tenant_scope()
    {
        var admin = await fx.AdminAsync();
        var a = await fx.SeedOrgAsync("AlA " + U);
        var b = await fx.SeedOrgAsync("AlB " + U);
        await using var devB = await TestAgent.EnrollAsync(fx, b.Token, "alb", os: "windows");
        await devB.SendAsync("posture", Posture(avOn: false));
        var alertB = (await UntilAsync(() => AlertsAsync(admin, devB.DeviceId), x => x.GetProperty("total").GetInt32() > 0)).GetProperty("items")[0].GetProperty("id").GetGuid();
        var channelB = (await admin.PostJsonAsync("/api/v1/notification-channels", new { name = "b chan " + U, type = "slack", url = "https://hooks.example.test/b", organizationId = b.OrgId })).GetProperty("id").GetGuid();
        var roleId = await fx.CreateRoleAsync("Alerting " + U, Permissions.AlertsRead, Permissions.AlertsManage, Permissions.NotificationsManage, Permissions.SecurityRead);
        var roleName = await fx.DbAsync(db => db.Roles.Where(r => r.Id == roleId).Select(r => r.Name).FirstAsync());
        var user = await fx.CreateUserAsync($"al-{Guid.NewGuid():N}@t.test", roleName, ScopeType.Organization, a.OrgId);

        Assert.Equal(0, (await user.GetJsonAsync($"/api/v1/alerts?deviceId={devB.DeviceId}")).GetProperty("total").GetInt32());
        Assert.Equal(HttpStatusCode.NotFound, (await user.PostAsync($"/api/v1/alerts/{alertB}/resolve")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync($"/api/v1/devices/{devB.DeviceId}/posture")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await user.GetAsync($"/api/v1/devices/{devB.DeviceId}/vulnerabilities")).StatusCode);
        Assert.All((await user.GetJsonAsync("/api/v1/security/posture")).GetProperty("items").EnumerateArray(), i => Assert.Equal(a.OrgId, i.GetProperty("organizationId").GetGuid()));
        // Cannot attach another organization's channel to a rule, nor create shared rules/channels.
        Assert.Equal(HttpStatusCode.BadRequest, (await user.PostAsync("/api/v1/alert-rules", new { name = "x", type = "firewall.off", organizationId = a.OrgId, channelIds = new[] { channelB } })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await user.PostAsync("/api/v1/alert-rules", new { name = "shared", type = "firewall.off" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await user.PostAsync("/api/v1/notification-channels", new { name = "x", type = "slack", url = "https://hooks.example.test/x", organizationId = b.OrgId })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await user.PostAsync($"/api/v1/notification-channels/{channelB}/test")).StatusCode);
        Assert.Equal(AlertState.Open, await fx.DbAsync(db => db.Alerts.Where(x => x.Id == alertB).Select(x => x.State).FirstAsync()));
    }
}
