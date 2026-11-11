using System.Net;
using System.Text.Json;
using Dranzo.Api.Features;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Dranzo.Tests;

[Collection("server")]
public class PolicyTests(ServerFixture fx)
{
    private static string U => Guid.NewGuid().ToString("N")[..6];

    private async Task<int> EvaluateAsync(params Guid[] devices)
    {
        await using var scope = fx.App.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
        return await PolicyEvaluator.RunAsync(scope.ServiceProvider, devices, false, default);
    }

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
    public async Task Non_compliant_device_is_detected_remediated_and_reported()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Pol " + U);
        await using var win = await TestAgent.EnrollAsync(fx, org.Token, "pol-win", os: "windows");
        await using var linux = await TestAgent.EnrollAsync(fx, org.Token, "pol-linux");
        var firewall = (await admin.PostJsonAsync("/api/v1/policies", new { name = "Firewall on " + U, check = "firewall.enabled", remediate = true, organizationId = org.OrgId, intervalMinutes = 60 })).GetProperty("id").GetGuid();
        var usb = (await admin.PostJsonAsync("/api/v1/policies", new { name = "USB blocked " + U, check = "usb.storage.blocked", organizationId = org.OrgId })).GetProperty("id").GetGuid();
        var admins = (await admin.PostJsonAsync("/api/v1/policies", new { name = "Admins " + U, check = "localadmins.allowed", @params = new { allowed = new[] { "Administrator", "it-admin" } }, organizationId = org.OrgId })).GetProperty("id").GetGuid();
        // Not assigned yet: nothing is evaluated.
        Assert.Equal(0, await EvaluateAsync(win.DeviceId, linux.DeviceId));
        foreach (var id in new[] { firewall, usb })
        {
            await admin.PostJsonAsync($"/api/v1/policies/{id}/assignments", new { scopeType = "Organization", scopeId = org.OrgId });
        }
        await admin.PostJsonAsync($"/api/v1/policies/{admins}/assignments", new { scopeType = "Group", scopeId = org.GroupId });

        Assert.Equal(2, await EvaluateAsync(win.DeviceId, linux.DeviceId));
        var winJob = await win.NextJobAsync("policy.evaluate");
        var linuxJob = await linux.NextJobAsync("policy.evaluate");
        var winChecks = winJob.Payload.GetProperty("spec").GetProperty("checks").EnumerateArray().ToDictionary(c => c.GetProperty("check").GetString()!);
        Assert.Equal(["firewall.enabled", "localadmins.allowed", "usb.storage.blocked"], winChecks.Keys.Order());
        Assert.True(winChecks["firewall.enabled"].GetProperty("remediate").GetBoolean());
        Assert.Equal("it-admin", winChecks["localadmins.allowed"].GetProperty("params").GetProperty("allowed")[1].GetString());
        // The Windows-only check is not sent to the Linux device.
        Assert.DoesNotContain("usb.storage.blocked", linuxJob.Payload.GetProperty("spec").GetProperty("checks").EnumerateArray().Select(c => c.GetProperty("check").GetString()));

        var foreignPolicy = Guid.NewGuid();
        await win.CompleteAsync(winJob, result: new
        {
            results = new object[]
            {
                new { policyId = firewall, check = "firewall.enabled", compliant = true, remediated = true, detail = "Firewall was off; enabled all profiles." },
                new { policyId = usb, check = "usb.storage.blocked", compliant = false, remediated = false, detail = "USBSTOR Start=3" },
                new { policyId = admins, check = "localadmins.allowed", compliant = false, remediated = false, detail = "Unexpected admins: bob" },
                new { policyId = foreignPolicy, check = "firewall.enabled", compliant = true, remediated = false, detail = "not asked for" },
            },
        });
        await linux.CompleteAsync(linuxJob, result: new
        {
            results = new object[]
            {
                new { policyId = firewall, check = "firewall.enabled", compliant = false, remediated = false, detail = "not supported on this OS: no supported firewall installed" },
                new { policyId = admins, check = "localadmins.allowed", compliant = true, remediated = false, detail = "ok" },
            },
        });

        var device = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{win.DeviceId}/compliance"), v => v.GetArrayLength() == 3);
        var byCheck = device.EnumerateArray().ToDictionary(r => r.GetProperty("check").GetString()!);
        Assert.True(byCheck["firewall.enabled"].GetProperty("compliant").GetBoolean());
        Assert.True(byCheck["firewall.enabled"].GetProperty("remediated").GetBoolean());
        Assert.False(byCheck["usb.storage.blocked"].GetProperty("compliant").GetBoolean());
        Assert.Equal(0, await fx.DbAsync(db => db.ComplianceResults.CountAsync(r => r.PolicyId == foreignPolicy)));

        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{linux.DeviceId}/compliance"), v => v.GetArrayLength() == 2);
        var summary = await admin.GetJsonAsync($"/api/v1/compliance?organizationId={org.OrgId}");
        Assert.Equal(2, summary.GetProperty("devices").GetInt32());
        Assert.Equal(1, summary.GetProperty("compliantDevices").GetInt32()); // Linux: its only failing check is "not supported", which is not drift
        var fw = summary.GetProperty("policies").EnumerateArray().Single(p => p.GetProperty("policyId").GetGuid() == firewall);
        Assert.Equal((1, 0, 1, 1), (fw.GetProperty("compliant").GetInt32(), fw.GetProperty("nonCompliant").GetInt32(), fw.GetProperty("unsupported").GetInt32(), fw.GetProperty("remediated").GetInt32()));
        Assert.Equal(2, summary.GetProperty("nonCompliant").GetArrayLength());

        // Drift raises an alert on the Windows device only, and clears once the device is compliant again.
        bool Drift(JsonElement a) => a.GetProperty("items").EnumerateArray().Any(x => x.GetProperty("type").GetString() == "compliance.drift");
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/alerts?deviceId={win.DeviceId}&state=open"), Drift);
        Assert.False(Drift(await admin.GetJsonAsync($"/api/v1/alerts?deviceId={linux.DeviceId}&state=open")));

        // Within the interval nothing is re-sent; a manual evaluation forces it.
        Assert.Equal(0, await EvaluateAsync(win.DeviceId));
        var manual = await admin.PostJsonAsync("/api/v1/policies/evaluate", new { deviceIds = new[] { win.DeviceId } });
        Assert.Equal(1, manual.GetProperty("deviceCount").GetInt32());
        var again = await win.NextJobAsync("policy.evaluate");
        await win.CompleteAsync(again, result: new
        {
            results = new object[]
            {
                new { policyId = firewall, check = "firewall.enabled", compliant = true, remediated = false, detail = "on" },
                new { policyId = usb, check = "usb.storage.blocked", compliant = true, remediated = false, detail = "blocked" },
                new { policyId = admins, check = "localadmins.allowed", compliant = true, remediated = false, detail = "ok" },
            },
        });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/alerts?deviceId={win.DeviceId}&state=open"), a => !Drift(a));
    }

    [Fact]
    public async Task Policy_parameters_are_validated_and_script_policies_need_step_up()
    {
        var admin = await fx.AdminAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/policies", new { name = "x", check = "does.not.exist" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/policies", new { name = "x", check = "screenlock.timeout", @params = new { maxSeconds = 5 } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/policies", new { name = "x", check = "screenlock.timeout" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/policies", new { name = "x", check = "usb.storage.blocked", osTargets = new[] { "linux" } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/policies", new { name = "x", check = "script", @params = new { language = "sh" } })).StatusCode);

        fx.Clock.Advance(TimeSpan.FromMinutes(6));
        admin = await fx.AdminAsync();
        var body = new { name = "Script " + U, check = "script", @params = new { language = "sh", checkScript = "test -f /etc/ok", remediationScript = "touch /etc/ok" }, remediate = true };
        var denied = await admin.PostAsync("/api/v1/policies", body);
        Assert.Contains("step_up_required", await denied.Content.ReadAsStringAsync());
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.Created, (await admin.PostAsync("/api/v1/policies", body)).StatusCode);
        var audit = (await admin.GetJsonAsync("/api/v1/audit?action=policy.create&pageSize=5")).GetProperty("items")[0];
        Assert.Equal(64, audit.GetProperty("contentSha256").GetString()!.Length);
    }

    [Fact]
    public async Task Policies_respect_tenant_scope()
    {
        var admin = await fx.AdminAsync();
        var a = await fx.SeedOrgAsync("PoA " + U);
        var b = await fx.SeedOrgAsync("PoB " + U);
        await using var devB = await TestAgent.EnrollAsync(fx, b.Token, "pob");
        var tech = await fx.CreateUserAsync($"po-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, a.OrgId);
        var shared = (await admin.PostJsonAsync("/api/v1/policies", new { name = "Shared fw " + U, check = "firewall.enabled" })).GetProperty("id").GetGuid();
        var own = (await tech.PostJsonAsync("/api/v1/policies", new { name = "A fw " + U, check = "firewall.enabled", organizationId = a.OrgId })).GetProperty("id").GetGuid();

        Assert.Equal(HttpStatusCode.Forbidden, (await tech.PostAsync("/api/v1/policies", new { name = "shared", check = "firewall.enabled" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/policies", new { name = "b", check = "firewall.enabled", organizationId = b.OrgId })).StatusCode);
        // A shared policy can be assigned by the technician to their own organization, but not to B or the whole partner; nor edited.
        Assert.Equal(HttpStatusCode.Created, (await tech.PostAsync($"/api/v1/policies/{shared}/assignments", new { scopeType = "Organization", scopeId = a.OrgId })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await tech.PostAsync($"/api/v1/policies/{shared}/assignments", new { scopeType = "Organization", scopeId = b.OrgId })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await tech.PostAsync($"/api/v1/policies/{shared}/assignments", new { scopeType = "Site", scopeId = b.SiteId })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await tech.PostAsync($"/api/v1/policies/{shared}/assignments", new { scopeType = "Group", scopeId = b.GroupId })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await tech.PostAsync($"/api/v1/policies/{shared}/assignments", new { scopeType = "Partner" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PatchAsync($"/api/v1/policies/{shared}", new { remediate = true })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.DeleteAsync($"/api/v1/policies/{shared}")).StatusCode);
        // An organization-A policy cannot be assigned into B even by a partner admin, and never reaches B's devices.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync($"/api/v1/policies/{own}/assignments", new { scopeType = "Organization", scopeId = b.OrgId })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/policies/evaluate", new { deviceIds = new[] { devB.DeviceId } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.GetAsync($"/api/v1/devices/{devB.DeviceId}/compliance")).StatusCode);
        Assert.Equal(0, await EvaluateAsync(devB.DeviceId));
        Assert.True(await devB.NoneAsync("job.dispatch", 300));
    }
}
