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
public class PatchTests(ServerFixture fx)
{
    private static string U => Guid.NewGuid().ToString("N")[..6];

    private static object Update(string id, string severity = "critical", string source = "apt", string category = "security") =>
        new { id, title = "Update " + id, source, severity, category, currentVersion = "1.0", newVersion = "1.1", requiresReboot = false };

    private static Task ReportAsync(TestAgent agent, params object[] pending) =>
        agent.SendAsync("patch.state", new { collectedAt = DateTimeOffset.UtcNow, pending, rebootRequired = false });

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

    private static Dictionary<string, string> Statuses(JsonElement devicePatches) =>
        devicePatches.GetProperty("items").EnumerateArray().ToDictionary(i => i.GetProperty("title").GetString()!, i => i.GetProperty("status").GetString()!);

    [Fact]
    public async Task Scan_approve_install_flow_updates_compliance()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Patch " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "patch-host");
        var (a, b, c) = ("kb-a-" + U, "kb-b-" + U, "kb-c-" + U);
        await ReportAsync(agent, Update(a), Update(b, "low"), Update(c, "moderate"));
        var patches = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{agent.DeviceId}/patches"), v => v.GetProperty("items").GetArrayLength() == 3);
        Assert.All(Statuses(patches).Values, s => Assert.Equal("pending", s));
        var compliance = await admin.GetJsonAsync($"/api/v1/patches/compliance?organizationId={org.OrgId}");
        Assert.Equal(1, compliance.GetProperty("unpatched").GetInt32());
        Assert.Equal(1, compliance.GetProperty("items")[0].GetProperty("missingCritical").GetInt32());

        var catalog = await admin.GetJsonAsync($"/api/v1/patches?organizationId={org.OrgId}");
        Guid Entry(string id) => catalog.EnumerateArray().Single(e => e.GetProperty("title").GetString() == "Update " + id).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/patches/install", new { target = new { deviceIds = new[] { agent.DeviceId } } })).StatusCode); // nothing approved yet
        await admin.PostJsonAsync("/api/v1/patches/approve", new { catalogEntryIds = new[] { Entry(a), Entry(b) }, status = "approved" });
        await admin.PostJsonAsync("/api/v1/patches/approve", new { catalogEntryIds = new[] { Entry(c) }, status = "rejected" });

        await admin.PostJsonAsync("/api/v1/patches/install", new { target = new { deviceIds = new[] { agent.DeviceId } }, reboot = new { mode = "if_required", deferrals = 2, deadlineMinutes = 60 } });
        var dispatch = await agent.NextJobAsync("patch.install");
        var spec = dispatch.Payload.GetProperty("spec");
        Assert.Equal(new[] { a, b }.Order(), spec.GetProperty("updateIds").EnumerateArray().Select(x => x.GetString()!).Order()); // only approved ones, never the rejected one
        Assert.Equal("if_required", spec.GetProperty("reboot").GetProperty("mode").GetString());
        Assert.Equal(2, spec.GetProperty("reboot").GetProperty("deferrals").GetInt32());

        await agent.CompleteAsync(dispatch, "succeeded", 0, [], new { installed = new object[] { new { id = a, ok = true }, new { id = b, ok = false, error = "E: dpkg lock" } }, rebootRequired = true });
        await agent.NextJobAsync("patch.scan"); // automatic rescan
        patches = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{agent.DeviceId}/patches"), v => Statuses(v)["Update " + a] == "installed");
        Assert.Equal("failed", Statuses(patches)["Update " + b]);
        Assert.Equal("rejected", Statuses(patches)["Update " + c]);
        Assert.True(patches.GetProperty("pendingReboot").GetBoolean());

        // Next scan no longer lists b: it is treated as installed. The rejected one stays rejected while still offered.
        await ReportAsync(agent, Update(c, "moderate"));
        patches = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{agent.DeviceId}/patches"), v => Statuses(v)["Update " + b] == "installed");
        Assert.Equal("rejected", Statuses(patches)["Update " + c]);
        compliance = await admin.GetJsonAsync($"/api/v1/patches/compliance?organizationId={org.OrgId}");
        Assert.Equal(1, compliance.GetProperty("patched").GetInt32());
    }

    [Fact]
    public async Task Policy_auto_approves_by_severity_and_installs_in_the_maintenance_window_after_deferral()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Win " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "window-host");
        var policy = await admin.PostJsonAsync("/api/v1/patch-policies", new
        {
            name = "Critical nightly", organizationId = org.OrgId, autoApproveSeverities = new[] { "critical" }, deferDays = 2, windowCron = "0 3 * * *", windowMinutes = 60, rebootMode = "force", rebootDeadlineMinutes = 30,
        });
        var (crit, low) = ("crit-" + U, "low-" + U);
        await ReportAsync(agent, Update(crit), Update(low, "low"));
        var patches = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{agent.DeviceId}/patches"), v => v.GetProperty("items").GetArrayLength() == 2);
        Assert.Equal("approved", Statuses(patches)["Update " + crit]);
        Assert.Equal("pending", Statuses(patches)["Update " + low]);

        async Task RunWindowAsync()
        {
            await using var scope = fx.App.Services.CreateAsyncScope();
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            await PatchWindowService.RunDueAsync(scope.ServiceProvider, default);
        }
        var policyId = policy.GetProperty("id").GetGuid();
        var next = await fx.DbAsync(db => db.PatchPolicies.Where(p => p.Id == policyId).Select(p => p.NextWindowAt).FirstAsync());
        // First window: the update is still inside its 2-day deferral, so nothing is installed.
        fx.Clock.Advance(next!.Value - fx.Clock.GetUtcNow() + TimeSpan.FromMinutes(1));
        await RunWindowAsync();
        Assert.True(await agent.NoneAsync("job.dispatch"));
        // Third window: deferral has passed.
        fx.Clock.Advance(TimeSpan.FromDays(2));
        await RunWindowAsync();
        var dispatch = await agent.NextJobAsync("patch.install");
        var spec = dispatch.Payload.GetProperty("spec");
        Assert.Equal([crit], spec.GetProperty("updateIds").EnumerateArray().Select(x => x.GetString()!));
        Assert.Equal("force", spec.GetProperty("reboot").GetProperty("mode").GetString());
        Assert.Equal(30, spec.GetProperty("reboot").GetProperty("deadlineMinutes").GetInt32());
        // The run only stays valid for the length of the window.
        var run = await fx.DbAsync(db => db.JobRuns.FirstAsync(r => r.Id == dispatch.RunId()));
        Assert.True(run.ExpiresAt - run.CreatedAt <= TimeSpan.FromMinutes(61));
    }

    [Fact]
    public async Task Patch_actions_respect_tenant_scope()
    {
        var admin = await fx.AdminAsync();
        var a = await fx.SeedOrgAsync("PtA " + U);
        var b = await fx.SeedOrgAsync("PtB " + U);
        await using var devA = await TestAgent.EnrollAsync(fx, a.Token, "pta");
        await using var devB = await TestAgent.EnrollAsync(fx, b.Token, "ptb");
        var shared = "shared-kb-" + U;
        await ReportAsync(devA, Update(shared));
        await ReportAsync(devB, Update(shared));
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{devB.DeviceId}/patches"), v => v.GetProperty("items").GetArrayLength() == 1);
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{devA.DeviceId}/patches"), v => v.GetProperty("items").GetArrayLength() == 1);
        var tech = await fx.CreateUserAsync($"pt-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, a.OrgId);

        var catalog = await tech.GetJsonAsync("/api/v1/patches");
        var entry = catalog.EnumerateArray().Single(e => e.GetProperty("title").GetString() == "Update " + shared);
        Assert.Equal(1, entry.GetProperty("devices").GetInt32()); // the same update on B's device is not counted
        // Approving touches only the technician's own organization, even when B is named explicitly.
        var approved = await tech.PostJsonAsync("/api/v1/patches/approve", new { catalogEntryIds = new[] { entry.GetProperty("id").GetGuid() }, status = "approved" });
        Assert.Equal(1, approved.GetProperty("updated").GetInt32());
        var none = await tech.PostJsonAsync("/api/v1/patches/approve", new { catalogEntryIds = new[] { entry.GetProperty("id").GetGuid() }, status = "approved", deviceIds = new[] { devB.DeviceId } });
        Assert.Equal(0, none.GetProperty("updated").GetInt32());
        Assert.Equal(PatchStatus.Pending, await fx.DbAsync(db => db.DevicePatchStates.Where(s => s.DeviceId == devB.DeviceId).Select(s => s.Status).FirstAsync()));

        Assert.Equal(HttpStatusCode.NotFound, (await tech.GetAsync($"/api/v1/devices/{devB.DeviceId}/patches")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/patches/install", new { target = new { deviceIds = new[] { devB.DeviceId } } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/patches/scan", new { deviceIds = new[] { devB.DeviceId } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync($"/api/v1/devices/{devB.DeviceId}/reboot", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await tech.PostAsync("/api/v1/patch-policies", new { name = "shared policy" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/patch-policies", new { name = "b policy", organizationId = b.OrgId })).StatusCode);
        Assert.All((await tech.GetJsonAsync("/api/v1/patches/compliance")).GetProperty("items").EnumerateArray(), i => Assert.Equal(a.OrgId, i.GetProperty("organizationId").GetGuid()));
        Assert.True(await devB.NoneAsync("job.dispatch"));
    }

    [Fact]
    public async Task Reboot_is_a_signed_audited_job()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Rb " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "reboot-host");
        await admin.PostJsonAsync($"/api/v1/devices/{agent.DeviceId}/reboot", new { delaySeconds = 120, message = "Restarting for maintenance" });
        var dispatch = await agent.NextJobAsync("reboot");
        Assert.Equal(120, dispatch.Payload.GetProperty("spec").GetProperty("delaySeconds").GetInt32());
        Assert.True(dispatch.Payload.GetProperty("spec").GetProperty("notifyUser").GetBoolean());
        var audit = await admin.GetJsonAsync($"/api/v1/audit?deviceId={agent.DeviceId}&action=device.reboot");
        Assert.Equal(1, audit.GetProperty("total").GetInt32());
    }
}
