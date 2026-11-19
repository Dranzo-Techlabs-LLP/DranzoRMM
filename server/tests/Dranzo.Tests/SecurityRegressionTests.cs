using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dranzo.Api.Features;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Tests.Infra;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Dranzo.Tests;

/// <summary>One test per finding of the independent security review (F1..F12). Each would have failed before the fix.</summary>
[Collection("server")]
public class SecurityRegressionTests(ServerFixture fx)
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

    [Fact]
    public async Task F1_org_technician_cannot_see_or_delete_assignments_protecting_another_organization()
    {
        var admin = await fx.AdminAsync();
        var a = await fx.SeedOrgAsync("F1A " + U);
        var b = await fx.SeedOrgAsync("F1B " + U);
        var policy = (await admin.PostJsonAsync("/api/v1/policies", new { name = "Shared FW " + U, check = "firewall.enabled", remediate = true })).GetProperty("id").GetGuid();
        var siteAssign = (await admin.PostJsonAsync($"/api/v1/policies/{policy}/assignments", new { scopeType = "Site", scopeId = b.SiteId })).GetProperty("id").GetGuid();
        var groupAssign = (await admin.PostJsonAsync($"/api/v1/policies/{policy}/assignments", new { scopeType = "Group", scopeId = b.GroupId })).GetProperty("id").GetGuid();
        var tech = await fx.CreateUserAsync($"f1-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, a.OrgId);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.DeleteAsync($"/api/v1/policies/{policy}/assignments/{siteAssign}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.DeleteAsync($"/api/v1/policies/{policy}/assignments/{groupAssign}")).StatusCode);
        Assert.Equal(2, await fx.DbAsync(db => db.PolicyAssignments.CountAsync(x => x.PolicyId == policy)));
        var listed = (await tech.GetJsonAsync("/api/v1/policies")).GetProperty("items").EnumerateArray().Single(p => p.GetProperty("id").GetGuid() == policy);
        Assert.Equal(0, listed.GetProperty("assignments").GetArrayLength());
    }

    [Fact]
    public async Task F2_users_manage_alone_cannot_take_over_a_partner_admin()
    {
        var roleId = await fx.CreateRoleAsync("Helpdesk " + U, Permissions.UsersRead, Permissions.UsersManage);
        var roleName = await fx.DbAsync(db => db.Roles.Where(r => r.Id == roleId).Select(r => r.Name).FirstAsync());
        var helpdesk = await fx.CreateUserAsync($"f2-{Guid.NewGuid():N}@t.test", roleName, ScopeType.Partner, null);
        var adminId = await fx.DbAsync(db => db.Users.IgnoreQueryFilters().Where(u => u.Email == ServerFixture.AdminEmail).Select(u => u.Id).FirstAsync());
        await helpdesk.StepUpAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await helpdesk.PostAsync($"/api/v1/users/{adminId}/reset-password", new { password = "Hijack-Strong-Pass-1234" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await helpdesk.PostAsync($"/api/v1/users/{adminId}/reset-mfa")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await helpdesk.PatchAsync($"/api/v1/users/{adminId}", new { disabled = true })).StatusCode);
        // ...but can still manage accounts that are not stronger than itself.
        var weakRole = await fx.CreateRoleAsync("Users reader " + U, Permissions.UsersRead);
        var weakRoleName = await fx.DbAsync(db => db.Roles.Where(r => r.Id == weakRole).Select(r => r.Name).FirstAsync());
        var weak = await fx.CreateUserAsync($"f2w-{Guid.NewGuid():N}@t.test", weakRoleName, ScopeType.Partner, null);
        var viewer = await fx.CreateUserAsync($"f2v-{Guid.NewGuid():N}@t.test", BuiltInRoles.OrganizationViewer, ScopeType.Partner, null);
        await helpdesk.StepUpAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await helpdesk.PostAsync($"/api/v1/users/{weak.UserId}/reset-password", new { password = "Reset-Strong-Pass-3300" })).StatusCode);
        // A read-only client user still has permissions (devices.read, ...) the helpdesk role lacks.
        Assert.Equal(HttpStatusCode.Forbidden, (await helpdesk.PostAsync($"/api/v1/users/{viewer.UserId}/reset-password", new { password = "Reset-Strong-Pass-3300" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await (await fx.AdminAsync()).GetAsync("/api/v1/auth/me")).StatusCode);
    }

    [Fact]
    public async Task F3_an_agent_in_one_organization_cannot_shape_another_organizations_patch_catalog()
    {
        var admin = await fx.AdminAsync();
        var a = await fx.SeedOrgAsync("F3A " + U);
        var b = await fx.SeedOrgAsync("F3B " + U);
        await admin.PostJsonAsync("/api/v1/patch-policies", new { name = "B critical " + U, organizationId = b.OrgId, autoApproveSeverities = new[] { "critical" } });
        await using var evil = await TestAgent.EnrollAsync(fx, a.Token, "f3-evil");
        await using var victim = await TestAgent.EnrollAsync(fx, b.Token, "f3-victim");
        var kb = "kb-f3-" + U;
        await evil.SendAsync("patch.state", new { pending = new[] { new { id = kb, title = "Totally harmless", source = "wua", severity = "low", category = "drivers" } } });
        await evil.SendAsync("heartbeat", new { seq = 1 });
        await evil.WaitForAsync("heartbeat.ack");
        await victim.SendAsync("patch.state", new { pending = new[] { new { id = kb, title = "Critical RCE fix", source = "wua", severity = "critical", category = "security" } } });
        var patches = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{victim.DeviceId}/patches"), v => v.GetProperty("items").GetArrayLength() == 1);
        var item = patches.GetProperty("items")[0];
        Assert.Equal("approved", item.GetProperty("status").GetString());
        Assert.Equal("Critical RCE fix", item.GetProperty("title").GetString());
        Assert.Equal(2, await fx.DbAsync(db => db.PatchCatalog.CountAsync(e => e.UpdateId == kb)));
    }

    [Fact]
    public async Task F4_the_previous_certificate_cannot_renew()
    {
        var org = await fx.SeedOrgAsync("F4 " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "f4-host", connect: false);
        var stolen = agent.Certificate;
        Assert.True(await agent.RenewAsync());
        var current = agent.Certificate;
        // The holder of the old key tries to renew with it.
        using var http = new HttpClient(new SocketsHttpHandler
        {
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions { RemoteCertificateValidationCallback = (_, c, _, e) => agent.ValidateServer(c, e), ClientCertificates = [stolen] },
        })
        { BaseAddress = new Uri(fx.AgentUrl) };
        var (_, csr) = TestAgent.NewCsr();
        Assert.Equal(HttpStatusCode.Forbidden, (await http.PostAsJsonAsync("/agent/v1/renew", new { csr })).StatusCode);
        // The real device is unaffected and an alert is raised.
        await agent.ConnectAsync(certOverride: current);
        var admin = await fx.AdminAsync();
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/alerts?deviceId={agent.DeviceId}&state=open"), x => x.GetProperty("items").EnumerateArray().Any(i => i.GetProperty("type").GetString() == "agent.tamper"));
    }

    [Fact]
    public async Task F5_and_F7_heavy_agent_reports_are_rate_limited_and_disk_alerts_collapse()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("F5 " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "f5-host");
        for (var i = 0; i < 8; i++)
        {
            var disks = Enumerable.Range(0, 64).Select(n => new { device = $"d{i}-{n}", mountPoint = $"/m{i}-{n}", fsType = "ext4", totalBytes = 100L << 30, freeBytes = 1L << 30 });
            await agent.SendAsync("inventory", new { hostname = "f5-host", os = new { name = "Linux" }, disks });
        }
        var limited = 0;
        while (true)
        {
            try
            {
                var e = await agent.WaitForAsync("error", m => m.Payload.GetProperty("code").GetString() == "rate_limited", 1500);
                limited++;
            }
            catch (TimeoutException)
            {
                break;
            }
        }
        Assert.Equal(3, limited); // burst of 5, then dropped
        var alerts = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/alerts?deviceId={agent.DeviceId}&state=open"), x => x.GetProperty("total").GetInt32() >= 1);
        Assert.Equal(1, alerts.GetProperty("items").EnumerateArray().Count(x => x.GetProperty("type").GetString() == "disk.usage"));
        Assert.Equal(1, (await admin.GetJsonAsync($"/api/v1/audit?deviceId={agent.DeviceId}&action=alert.open")).GetProperty("total").GetInt32());

        // Repeating an identical software list is not reprocessed.
        var items = Enumerable.Range(0, 2000).Select(n => new { name = $"app{n}", version = "1.0", source = "registry" }).ToArray();
        await agent.SendAsync("software.inventory", new { items });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{agent.DeviceId}/software"), v => v.GetArrayLength() == 2000);
        var firstSeen = await fx.DbAsync(db => db.InstalledSoftware.Where(s => s.DeviceId == agent.DeviceId).Select(s => s.Id).FirstAsync());
        await agent.SendAsync("software.inventory", new { items });
        await agent.SendAsync("heartbeat", new { seq = 1 });
        await agent.WaitForAsync("heartbeat.ack");
        Assert.True(await fx.DbAsync(db => db.InstalledSoftware.AnyAsync(s => s.Id == firstSeen)));
    }

    [Fact]
    public async Task F7_vulnerability_matching_is_fast_for_large_reports()
    {
        var product = "heavy" + U;
        await fx.DbAsync(async db =>
        {
            for (var i = 0; i < 2000; i++)
            {
                db.CveEntries.Add(new CveEntry
                {
                    Id = $"CVE-2098-{U}{i}", Severity = "high", UpdatedAt = DateTimeOffset.UtcNow, Products = [product],
                    MatchJson = JsonSerializer.Serialize(Enumerable.Range(0, 20).Select(k => new CpeRange("v", product, null, null, null, $"{k}.0", null)), JsonSerializerOptions.Web),
                });
            }
            await db.SaveChangesAsync();
        });
        var org = await fx.SeedOrgAsync("F7 " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "f7-host", connect: false);
        await fx.DbAsync(async db =>
        {
            var d = await db.Devices.FirstAsync(x => x.Id == agent.DeviceId);
            db.InstalledSoftware.AddRange(Enumerable.Range(0, 5000).Select(n => new InstalledSoftware
            {
                Id = Guid.NewGuid(), PartnerId = d.PartnerId, OrganizationId = d.OrganizationId, DeviceId = d.Id, Name = $"{product} {n}", Version = "1.0", Source = "registry", SeenAt = DateTimeOffset.UtcNow,
            }));
            await db.SaveChangesAsync();
        });
        var watch = System.Diagnostics.Stopwatch.StartNew();
        await using (var scope = fx.App.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            await scope.ServiceProvider.GetRequiredService<VulnerabilityMatcher>().MatchDeviceAsync(agent.DeviceId, default);
        }
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"matching took {watch.Elapsed}");
    }

    [Fact]
    public async Task F6_subscribing_to_a_job_does_not_stream_other_organizations_runs()
    {
        var admin = await fx.AdminAsync();
        var a = await fx.SeedOrgAsync("F6A " + U);
        var b = await fx.SeedOrgAsync("F6B " + U);
        await using var devA = await TestAgent.EnrollAsync(fx, a.Token, "f6-a");
        await using var devB = await TestAgent.EnrollAsync(fx, b.Token, "f6-b-secret");
        var script = (await admin.PostJsonAsync("/api/v1/scripts", new { name = "f6 " + U, language = "sh", body = "true" })).GetProperty("id").GetGuid();
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId = script, target = new { deviceIds = new[] { devA.DeviceId, devB.DeviceId } } });
        var reader = await fx.CreateUserAsync($"f6-{Guid.NewGuid():N}@t.test", BuiltInRoles.ReadOnly, ScopeType.Organization, a.OrgId);
        await using var hub = new HubConnectionBuilder().WithUrl(fx.DashboardUrl + "/hubs/live", o => { o.Cookies = reader.Cookies; o.Headers["X-CSRF-Token"] = reader.Csrf!; }).Build();
        var leaked = new List<string>();
        hub.On<JsonElement>("run", e => leaked.Add(e.ToString()));
        hub.On<JsonElement>("jobChanged", e => leaked.Add("changed"));
        await hub.StartAsync();
        Assert.True(await hub.InvokeAsync<bool>("SubscribeJob", job.GetProperty("jobId").GetGuid()));
        await devB.CompleteAsync(await devB.NextJobAsync());
        await devA.CompleteAsync(await devA.NextJobAsync());
        await Task.Delay(1000);
        Assert.Contains("changed", leaked);
        Assert.DoesNotContain(leaked, l => l.Contains(devB.DeviceId.ToString(), StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task F8_hub_follows_idle_timeout_and_rejects_foreign_origins()
    {
        var user = await fx.CreateUserAsync($"f8-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Partner, null);
        await using var hub = new HubConnectionBuilder().WithUrl(fx.DashboardUrl + "/hubs/live", o => { o.Cookies = user.Cookies; o.Headers["X-CSRF-Token"] = user.Csrf!; }).Build();
        await hub.StartAsync();
        await hub.InvokeAsync<bool>("SubscribeJob", Guid.NewGuid()); // hub works while the session is fresh
        fx.Clock.Advance(TimeSpan.FromMinutes(31));
        var org = await fx.SeedOrgAsync("F8 " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "f8-host", connect: false);
        var runs = await fx.DbAsync(db => db.JobRuns.Select(r => r.Id).FirstAsync());
        Assert.False(await hub.InvokeAsync<bool>("SubscribeRun", runs));

        using var raw = new System.Net.WebSockets.ClientWebSocket();
        raw.Options.SetRequestHeader("Origin", "https://evil.example");
        await Assert.ThrowsAnyAsync<System.Net.WebSockets.WebSocketException>(() => raw.ConnectAsync(new Uri(fx.DashboardUrl.Replace("http", "ws", StringComparison.Ordinal) + "/hubs/live"), default));
    }

    [Fact]
    public async Task F9_remote_desktop_link_needs_organization_wide_scope_and_mesh_install_needs_step_up()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("F9 " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "f9-host");
        await fx.DbAsync(db => db.Devices.Where(d => d.Id == agent.DeviceId).ExecuteUpdateAsync(s => s.SetProperty(d => d.MeshNodeId, "node//" + new string('b', 40))));
        await admin.StepUpAsync();
        await admin.PatchAsync($"/api/v1/organizations/{org.OrgId}/mesh", new { meshUser = "user//f9", meshGroupId = "mesh//f9" });
        var siteTech = await fx.CreateUserAsync($"f9-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Site, org.SiteId);
        await siteTech.StepUpAsync();
        var session = (await siteTech.PostJsonAsync($"/api/v1/devices/{agent.DeviceId}/sessions/desktop", new { })).GetProperty("sessionId").GetGuid();
        await agent.WaitForAsync("session.start");
        await agent.SendAsync("session.status", new { sessionId = session, state = "active" });
        await UntilAsync(() => siteTech.GetJsonAsync($"/api/v1/sessions/{session}"), s => s.GetProperty("state").GetString() == "active");
        Assert.Equal(HttpStatusCode.Forbidden, (await siteTech.GetAsync($"/api/v1/sessions/{session}/desktop-url")).StatusCode);

        fx.Clock.Advance(TimeSpan.FromMinutes(6));
        admin = await fx.AdminAsync();
        Assert.Contains("step_up_required", await (await admin.PostAsync($"/api/v1/devices/{agent.DeviceId}/mesh/install")).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task F10_weakening_consent_or_signed_powershell_needs_step_up()
    {
        var admin = await fx.AdminAsync();
        var org = (await admin.PostJsonAsync("/api/v1/organizations", new { name = "F10 " + U, consentMode = "require", requireSignedPowerShell = true })).GetProperty("id").GetGuid();
        fx.Clock.Advance(TimeSpan.FromMinutes(6));
        admin = await fx.AdminAsync();
        Assert.Contains("step_up_required", await (await admin.PatchAsync($"/api/v1/organizations/{org}", new { consentMode = "none" })).Content.ReadAsStringAsync());
        Assert.Contains("step_up_required", await (await admin.PatchAsync($"/api/v1/organizations/{org}", new { requireSignedPowerShell = false })).Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PatchAsync($"/api/v1/organizations/{org}", new { name = "F10 renamed " + U })).StatusCode);
        Assert.Equal(ConsentMode.Require, await fx.DbAsync(db => db.Organizations.Where(o => o.Id == org).Select(o => o.ConsentMode).FirstAsync()));
    }

    [Fact]
    public async Task F11_schedule_stops_when_its_creator_loses_the_permission()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("F11 " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "f11-host");
        var tech = await fx.CreateUserAsync($"f11-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, org.OrgId);
        var script = (await tech.PostJsonAsync("/api/v1/scripts", new { name = "f11 " + U, language = "sh", body = "true", organizationId = org.OrgId })).GetProperty("id").GetGuid();
        await tech.StepUpAsync();
        var job = (await tech.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId = script, target = new { deviceIds = new[] { agent.DeviceId } }, schedule = new { cron = "*/5 * * * *" } })).GetProperty("jobId").GetGuid();
        await admin.StepUpAsync();
        await admin.PatchAsync($"/api/v1/users/{tech.UserId}", new { disabled = true });
        fx.Clock.Advance(TimeSpan.FromMinutes(6));
        await using (var scope = fx.App.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            await Dranzo.Api.Jobs.Scheduler.RunDueAsync(scope.ServiceProvider, default);
        }
        Assert.True(await agent.NoneAsync("job.dispatch", 500));
        Assert.False(await fx.DbAsync(db => db.Jobs.Where(j => j.Id == job).Select(j => j.Enabled).FirstAsync()));
    }

    [Fact]
    public async Task F12_ending_someone_elses_session_is_attributed_to_whoever_ended_it()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("F12 " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "f12-host");
        var tech = await fx.CreateUserAsync($"f12-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, org.OrgId);
        await tech.StepUpAsync();
        var session = (await tech.PostJsonAsync($"/api/v1/devices/{agent.DeviceId}/sessions/terminal", new { })).GetProperty("sessionId").GetGuid();
        await agent.WaitForAsync("session.start");
        await admin.PostAsync($"/api/v1/sessions/{session}/end");
        var end = (await admin.GetJsonAsync($"/api/v1/audit?deviceId={agent.DeviceId}&action=session.end")).GetProperty("items")[0];
        Assert.Equal(ServerFixture.AdminEmail, end.GetProperty("actorName").GetString());
    }

    [Fact]
    public async Task Package_ids_that_are_urls_or_paths_are_rejected()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Pid " + U);
        await using var dev = await TestAgent.EnrollAsync(fx, org.Token, "pid", connect: false);
        foreach (var id in new[] { "https://evil.example/x.rpm", "/tmp/evil.deb", "foo/../../bar" })
        {
            var r = await admin.PostAsync("/api/v1/software/deploy", new { action = "install", packages = new Dictionary<string, string> { ["dnf"] = id }, target = new { deviceIds = new[] { dev.DeviceId } } });
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        }
    }
}
