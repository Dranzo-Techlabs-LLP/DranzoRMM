using System.Net;
using System.Text.Json;
using Dranzo.Api.Jobs;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Dranzo.Tests;

[Collection("server")]
public class ScriptJobTests(ServerFixture fx)
{
    private static string U => Guid.NewGuid().ToString("N")[..6];

    private async Task<Guid> ScriptAsync(ApiClient c, string language = "sh", string body = "echo hello", Guid? organizationId = null, object[]? parameters = null)
    {
        var s = await c.PostJsonAsync("/api/v1/scripts", new { name = "script " + U, language, body, organizationId, parameters });
        return s.GetProperty("id").GetGuid();
    }

    private static async Task<JsonElement> WaitRunAsync(ApiClient c, Guid runId, Func<JsonElement, bool> until)
    {
        JsonElement run = default;
        for (var i = 0; i < 100; i++)
        {
            run = await c.GetJsonAsync($"/api/v1/runs/{runId}");
            if (until(run))
            {
                return run;
            }
            await Task.Delay(50);
        }
        Assert.Fail("run did not reach the expected state: " + run);
        return run;
    }

    [Fact]
    public async Task Script_runs_end_to_end_with_live_output_exit_code_and_audit_trail()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Run " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "run-host");
        var scriptId = await ScriptAsync(admin, body: "echo $GREETING", parameters: [new { name = "GREETING", type = "string", required = true }]);
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId, target = new { deviceIds = new[] { agent.DeviceId } }, parameters = new Dictionary<string, object> { ["GREETING"] = "hi there" }, runAs = "user", timeoutSeconds = 120 });
        var runId = job.GetProperty("runs")[0].GetProperty("id").GetGuid();

        var dispatch = await agent.NextJobAsync("script");
        Assert.Equal(runId, dispatch.RunId());
        var spec = dispatch.Payload.GetProperty("spec");
        Assert.Equal("sh", spec.GetProperty("language").GetString());
        Assert.Equal("echo $GREETING", spec.GetProperty("body").GetString());
        Assert.Equal("hi there", spec.GetProperty("env").GetProperty("GREETING").GetString());
        Assert.Equal("user", spec.GetProperty("runAs").GetString());
        Assert.False(spec.GetProperty("requireSignedPowerShell").GetBoolean());
        Assert.Equal(120, dispatch.Payload.GetProperty("timeoutSeconds").GetInt32());

        await agent.CompleteAsync(dispatch, "failed", 3, ["hi ", "there\n"]);
        var run = await WaitRunAsync(admin, runId, r => r.GetProperty("status").GetString() == "failed");
        Assert.Equal(3, run.GetProperty("exitCode").GetInt32());
        Assert.Equal("hi there\n", string.Concat(run.GetProperty("output").EnumerateArray().Select(o => o.GetProperty("data").GetString())));
        Assert.Equal(Dranzo.Infrastructure.Security.Hashing.Sha256Hex("hi there\n"), run.GetProperty("outputSha256").GetString());

        var audit = (await admin.GetJsonAsync($"/api/v1/audit?deviceId={agent.DeviceId}&pageSize=50")).GetProperty("items").EnumerateArray().ToList();
        var dispatched = audit.Single(e => e.GetProperty("action").GetString() == "job.dispatch");
        var scriptSha = Dranzo.Infrastructure.Security.Hashing.Sha256Hex("echo $GREETING");
        Assert.Equal(scriptSha, dispatched.GetProperty("contentSha256").GetString());
        Assert.Equal(ServerFixture.AdminEmail, dispatched.GetProperty("actorName").GetString());
        var result = audit.Single(e => e.GetProperty("action").GetString() == "job.result");
        Assert.Equal(run.GetProperty("outputSha256").GetString(), result.GetProperty("contentSha256").GetString());
        Assert.Equal("failure", result.GetProperty("result").GetString());
        // history per device
        var history = await admin.GetJsonAsync($"/api/v1/runs?deviceId={agent.DeviceId}");
        Assert.Equal(1, history.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Saving_a_script_creates_versions_and_old_versions_stay_runnable()
    {
        var admin = await fx.AdminAsync();
        var id = await ScriptAsync(admin, body: "echo v1");
        var put = await admin.PutAsync($"/api/v1/scripts/{id}", new { body = "echo v2", changeNote = "second" });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        var current = await admin.GetJsonAsync($"/api/v1/scripts/{id}");
        Assert.Equal(2, current.GetProperty("currentVersion").GetInt32());
        Assert.Equal("echo v2", current.GetProperty("body").GetString());
        Assert.Equal(2, current.GetProperty("versions").GetArrayLength());
        Assert.Equal("echo v1", (await admin.GetJsonAsync($"/api/v1/scripts/{id}?version=1")).GetProperty("body").GetString());

        var org = await fx.SeedOrgAsync("Ver " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "ver-host");
        await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId = id, version = 1, target = new { deviceIds = new[] { agent.DeviceId } } });
        Assert.Equal("echo v1", (await agent.NextJobAsync()).Payload.GetProperty("spec").GetProperty("body").GetString());
    }

    [Fact]
    public async Task Offline_device_gets_the_job_on_reconnect_signed_at_send_time()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Off " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "offline-host", connect: false);
        var scriptId = await ScriptAsync(admin);
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId, target = new { deviceIds = new[] { agent.DeviceId } } });
        var runId = job.GetProperty("runs")[0].GetProperty("id").GetGuid();
        Assert.Equal("pending", (await admin.GetJsonAsync($"/api/v1/runs/{runId}")).GetProperty("status").GetString());

        fx.Clock.Advance(TimeSpan.FromHours(2)); // the device stays off for two hours
        await agent.ConnectAsync();
        var dispatch = await agent.NextJobAsync();
        var issued = dispatch.Payload.GetProperty("issuedAt").GetDateTimeOffset();
        Assert.True((fx.Clock.GetUtcNow() - issued).Duration() < TimeSpan.FromMinutes(1), "command must be signed when it is sent, not when the job was created");
    }

    [Fact]
    public async Task Wide_runs_need_step_up()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Wide " + U);
        var ids = new List<Guid>();
        for (var i = 0; i < 11; i++)
        {
            var (r, a) = await TestAgent.TryEnrollAsync(fx, org.Token, "wide-" + i);
            Assert.True(r.IsSuccessStatusCode);
            ids.Add(a.DeviceId);
        }
        var scriptId = await ScriptAsync(admin);
        fx.Clock.Advance(TimeSpan.FromMinutes(6)); // no fresh step-up
        admin = await fx.AdminAsync();

        Assert.Equal(HttpStatusCode.Created, (await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId, target = new { deviceIds = ids.Take(10) } })).StatusCode);
        var eleven = await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId, target = new { deviceIds = ids } });
        Assert.Equal(HttpStatusCode.Unauthorized, eleven.StatusCode);
        Assert.Contains("step_up_required", await eleven.Content.ReadAsStringAsync());
        // "all devices of an organization" needs step-up even if it is a small organization
        var small = await fx.SeedOrgAsync("Small " + U);
        await using var one = await TestAgent.EnrollAsync(fx, small.Token, "small-1", connect: false);
        fx.Clock.Advance(TimeSpan.FromMinutes(6));
        admin = await fx.AdminAsync();
        var wholeOrg = await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId, target = new { organizationId = small.OrgId } });
        Assert.Equal(HttpStatusCode.Unauthorized, wholeOrg.StatusCode);
        var preview = await admin.PostJsonAsync("/api/v1/jobs/preview-target", new { organizationId = small.OrgId });
        Assert.True(preview.GetProperty("stepUpRequired").GetBoolean());

        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.Created, (await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId, target = new { deviceIds = ids } })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId, target = new { organizationId = small.OrgId } })).StatusCode);
        var denied = (await admin.GetJsonAsync("/api/v1/audit?action=script.run&pageSize=100")).GetProperty("items").EnumerateArray().Count(e => e.GetProperty("result").GetString() == "denied");
        Assert.True(denied >= 2);
    }

    [Fact]
    public async Task An_agent_cannot_report_on_another_devices_run_and_results_count_once()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Foreign " + U);
        await using var victim = await TestAgent.EnrollAsync(fx, org.Token, "victim");
        await using var attacker = await TestAgent.EnrollAsync(fx, org.Token, "attacker");
        var scriptId = await ScriptAsync(admin);
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId, target = new { deviceIds = new[] { victim.DeviceId } } });
        var runId = job.GetProperty("runs")[0].GetProperty("id").GetGuid();
        var dispatch = await victim.NextJobAsync();

        // The attacker's agent tries to fake the victim's result and output.
        await attacker.SendAsync("job.ack", new { jobRunId = runId, accepted = true });
        await attacker.SendAsync("job.output", new { jobRunId = runId, seq = 1, stream = "stdout", data = "forged" });
        await attacker.SendAsync("job.result", new { jobRunId = runId, status = "succeeded", exitCode = 0, truncated = false });
        await attacker.SendAsync("heartbeat", new { seq = 1 });
        await attacker.WaitForAsync("heartbeat.ack"); // everything above has been processed
        var run = await admin.GetJsonAsync($"/api/v1/runs/{runId}");
        Assert.Equal("dispatched", run.GetProperty("status").GetString());
        Assert.Equal(0, run.GetProperty("output").GetArrayLength());

        await victim.CompleteAsync(dispatch, "succeeded", 0, ["real\n"]);
        await WaitRunAsync(admin, runId, r => r.GetProperty("status").GetString() == "succeeded");
        // A second result for the same run is ignored.
        await victim.SendAsync("job.result", new { jobRunId = runId, status = "failed", exitCode = 9, truncated = false });
        await victim.SendAsync("heartbeat", new { seq = 2 });
        await victim.WaitForAsync("heartbeat.ack");
        Assert.Equal("succeeded", (await admin.GetJsonAsync($"/api/v1/runs/{runId}")).GetProperty("status").GetString());
    }

    [Fact]
    public async Task Server_enforces_the_output_cap()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Cap " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "cap-host");
        var scriptId = await ScriptAsync(admin);
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId, target = new { deviceIds = new[] { agent.DeviceId } }, maxOutputBytes = 2048 });
        var runId = job.GetProperty("runs")[0].GetProperty("id").GetGuid();
        var dispatch = await agent.NextJobAsync();
        Assert.Equal(2048, dispatch.Payload.GetProperty("maxOutputBytes").GetInt32());
        await agent.SendAsync("job.ack", new { jobRunId = runId, accepted = true });
        for (var i = 1; i <= 5; i++)
        {
            await agent.SendAsync("job.output", new { jobRunId = runId, seq = i, stream = "stdout", data = new string('x', 1000) }); // a misbehaving agent ignoring the cap
        }
        await agent.SendAsync("job.result", new { jobRunId = runId, status = "succeeded", exitCode = 0, truncated = false });
        var run = await WaitRunAsync(admin, runId, r => r.GetProperty("status").GetString() == "succeeded");
        Assert.True(run.GetProperty("truncated").GetBoolean());
        Assert.Equal(2000, run.GetProperty("outputBytes").GetInt64());
    }

    [Fact]
    public async Task Cancel_pending_and_running_runs()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Cancel " + U);
        await using var offline = await TestAgent.EnrollAsync(fx, org.Token, "cancel-offline", connect: false);
        await using var online = await TestAgent.EnrollAsync(fx, org.Token, "cancel-online");
        var scriptId = await ScriptAsync(admin);
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId, target = new { deviceIds = new[] { offline.DeviceId, online.DeviceId } } });
        var runs = job.GetProperty("runs").EnumerateArray().ToDictionary(r => r.GetProperty("deviceId").GetGuid(), r => r.GetProperty("id").GetGuid());
        var dispatch = await online.NextJobAsync();
        await online.SendAsync("job.ack", new { jobRunId = dispatch.RunId(), accepted = true });
        await WaitRunAsync(admin, runs[online.DeviceId], r => r.GetProperty("status").GetString() == "running");

        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync($"/api/v1/jobs/{job.GetProperty("jobId").GetGuid()}/cancel")).StatusCode);
        Assert.Equal("cancelled", (await admin.GetJsonAsync($"/api/v1/runs/{runs[offline.DeviceId]}")).GetProperty("status").GetString());
        var cancel = await online.WaitForAsync("job.cancel");
        Assert.True(cancel.Signed && cancel.SignatureValid);
        Assert.Equal(runs[online.DeviceId].ToString("D"), cancel.Payload.GetProperty("jobRunId").GetString());
        await online.SendAsync("job.result", new { jobRunId = dispatch.RunId(), status = "cancelled", truncated = false });
        await WaitRunAsync(admin, runs[online.DeviceId], r => r.GetProperty("status").GetString() == "cancelled");
        // the cancelled pending run is never sent
        await offline.ConnectAsync();
        Assert.True(await offline.NoneAsync("job.dispatch"));
    }

    [Fact]
    public async Task Agent_refusal_is_recorded_and_audited()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Refuse " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "refuse-host");
        var scriptId = await ScriptAsync(admin);
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId, target = new { deviceIds = new[] { agent.DeviceId } } });
        var runId = job.GetProperty("runs")[0].GetProperty("id").GetGuid();
        await agent.NextJobAsync();
        await agent.SendAsync("job.ack", new { jobRunId = runId, accepted = false, reason = "expired" });
        var run = await WaitRunAsync(admin, runId, r => r.GetProperty("status").GetString() == "rejected");
        Assert.Contains("expired", run.GetProperty("message").GetString());
        var audit = await admin.GetJsonAsync($"/api/v1/audit?deviceId={agent.DeviceId}&action=job.refused_by_agent");
        Assert.Equal(1, audit.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Os_targeting_and_signed_powershell_policy_are_applied_per_device()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Os " + U);
        await admin.PatchAsync($"/api/v1/organizations/{org.OrgId}", new { requireSignedPowerShell = true });
        await using var linux = await TestAgent.EnrollAsync(fx, org.Token, "os-linux", os: "linux");
        await using var windows = await TestAgent.EnrollAsync(fx, org.Token, "os-windows", os: "windows");
        var ps = await ScriptAsync(admin, "powershell", "Write-Output 1");
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId = ps, target = new { deviceIds = new[] { linux.DeviceId, windows.DeviceId } } });
        var runs = job.GetProperty("runs").EnumerateArray().ToDictionary(r => r.GetProperty("deviceId").GetGuid(), r => r.GetProperty("id").GetGuid());
        var dispatch = await windows.NextJobAsync();
        Assert.True(dispatch.Payload.GetProperty("spec").GetProperty("requireSignedPowerShell").GetBoolean());
        var skipped = await WaitRunAsync(admin, runs[linux.DeviceId], r => r.GetProperty("status").GetString() == "unsupported");
        Assert.Contains("linux", skipped.GetProperty("message").GetString());
        Assert.True(await linux.NoneAsync("job.dispatch"));
        // language/OS mismatch is refused when the script is saved
        var bad = await admin.PostAsync("/api/v1/scripts", new { name = "bad", language = "powershell", osTargets = new[] { "linux" }, body = "x" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
    }

    [Fact]
    public async Task At_most_four_jobs_run_on_a_device_at_once()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Conc " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "conc-host");
        var scriptId = await ScriptAsync(admin);
        for (var i = 0; i < 6; i++)
        {
            await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId, target = new { deviceIds = new[] { agent.DeviceId } } });
        }
        var first = new List<AgentMessage>();
        for (var i = 0; i < 4; i++)
        {
            first.Add(await agent.NextJobAsync());
        }
        Assert.True(await agent.NoneAsync("job.dispatch", 1200));
        await agent.CompleteAsync(first[0]);
        await agent.NextJobAsync(); // a slot opened
    }

    [Fact]
    public async Task Scheduled_script_fires_in_the_organizations_time_zone()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Sched " + U);
        await admin.PatchAsync($"/api/v1/organizations/{org.OrgId}", new { timeZone = "Asia/Dubai" });
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "sched-host");
        var scriptId = await ScriptAsync(admin);
        await admin.StepUpAsync();
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId, target = new { groupId = org.GroupId }, schedule = new { cron = "30 2 * * *" } });
        Assert.Equal(0, job.GetProperty("runs").GetArrayLength());
        var next = job.GetProperty("nextRunAt").GetDateTimeOffset();
        Assert.Equal(new TimeSpan(22, 30, 0), next.UtcDateTime.TimeOfDay); // 02:30 in Dubai (UTC+4)
        var schedules = await admin.GetJsonAsync("/api/v1/schedules");
        Assert.Contains(schedules.EnumerateArray(), s => s.GetProperty("id").GetGuid() == job.GetProperty("jobId").GetGuid() && s.GetProperty("timeZone").GetString() == "Asia/Dubai");

        fx.Clock.Advance(next - fx.Clock.GetUtcNow() + TimeSpan.FromMinutes(1));
        await using (var scope = fx.App.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            await Scheduler.RunDueAsync(scope.ServiceProvider, default);
        }
        await agent.NextJobAsync();
        var after = await fx.DbAsync(db => db.Jobs.Where(j => j.Id == job.GetProperty("jobId").GetGuid()).Select(j => j.NextRunAt).FirstAsync());
        Assert.Equal(next.AddDays(1), after);
        Assert.Equal(HttpStatusCode.BadRequest, (await (await fx.AdminAsync()).PostAsync("/api/v1/jobs/run-script", new { scriptId, target = new { groupId = org.GroupId }, schedule = new { cron = "not a cron" } })).StatusCode);
    }

    [Fact]
    public async Task Scripts_and_runs_respect_tenant_scope()
    {
        var admin = await fx.AdminAsync();
        var a = await fx.SeedOrgAsync("SA " + U);
        var b = await fx.SeedOrgAsync("SB " + U);
        await using var devA = await TestAgent.EnrollAsync(fx, a.Token, "sa-host", connect: false);
        await using var devB = await TestAgent.EnrollAsync(fx, b.Token, "sb-host", connect: false);
        var tech = await fx.CreateUserAsync($"st-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, a.OrgId);

        // A shared script would run anywhere, so an org-scoped technician cannot create one.
        Assert.Equal(HttpStatusCode.Forbidden, (await tech.PostAsync("/api/v1/scripts", new { name = "shared", language = "sh", body = "id" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/scripts", new { name = "for b", language = "sh", body = "id", organizationId = b.OrgId })).StatusCode);
        var own = await ScriptAsync(tech, organizationId: a.OrgId);
        var shared = await ScriptAsync(admin);
        // ...but may use shared scripts on their own devices, and cannot edit them.
        Assert.Equal(HttpStatusCode.Created, (await tech.PostAsync("/api/v1/jobs/run-script", new { scriptId = shared, target = new { deviceIds = new[] { devA.DeviceId } } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PutAsync($"/api/v1/scripts/{shared}", new { body = "rm -rf /" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.DeleteAsync($"/api/v1/scripts/{shared}")).StatusCode);

        // Devices of organization B do not exist for this technician, alone or mixed into a list.
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/jobs/run-script", new { scriptId = own, target = new { deviceIds = new[] { devB.DeviceId } } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/jobs/run-script", new { scriptId = own, target = new { deviceIds = new[] { devA.DeviceId, devB.DeviceId } } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/jobs/run-script", new { scriptId = own, target = new { organizationId = b.OrgId } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/jobs/run-script", new { scriptId = own, target = new { groupId = b.GroupId } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/jobs/run-script", new { scriptId = own, target = new { siteId = b.SiteId } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/jobs/run-script", new { scriptId = own, target = new { filter = new { organizationId = b.OrgId } } })).StatusCode);
        // A filter without an organization only ever matches devices in scope.
        var preview = await tech.PostJsonAsync("/api/v1/jobs/preview-target", new { filter = new { os = "linux" } });
        Assert.Equal(1, preview.GetProperty("deviceCount").GetInt32());
        Assert.Equal(0, await fx.DbAsync(db => db.JobRuns.CountAsync(r => r.DeviceId == devB.DeviceId)));

        // An organization-A script cannot be pointed at organization B even by a partner admin.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId = own, target = new { deviceIds = new[] { devB.DeviceId } } })).StatusCode);

        // Runs of organization B are invisible to the technician.
        var jobB = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId = shared, target = new { deviceIds = new[] { devB.DeviceId } } });
        var runB = jobB.GetProperty("runs")[0].GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NotFound, (await tech.GetAsync($"/api/v1/runs/{runB}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync($"/api/v1/runs/{runB}/cancel")).StatusCode);
        Assert.All((await tech.GetJsonAsync("/api/v1/runs?pageSize=200")).GetProperty("items").EnumerateArray(), r => Assert.Equal(devA.DeviceId, r.GetProperty("deviceId").GetGuid()));
    }

    [Fact]
    public async Task Parameters_are_validated_against_the_script_definition()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Param " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "param-host", connect: false);
        var id = await ScriptAsync(admin, parameters: [new { name = "COUNT", type = "int", required = true }, new { name = "FORCE", type = "bool", required = false, @default = "false" }]);
        object Target() => new { deviceIds = new[] { agent.DeviceId } };
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId = id, target = Target() })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId = id, target = Target(), parameters = new Dictionary<string, object> { ["COUNT"] = "abc" } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId = id, target = Target(), parameters = new Dictionary<string, object> { ["COUNT"] = 1, ["EXTRA"] = "x" } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId = id, target = Target(), parameters = new Dictionary<string, object> { ["COUNT"] = 1 }, runAs = "root" })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await admin.PostAsync("/api/v1/jobs/run-script", new { scriptId = id, target = Target(), parameters = new Dictionary<string, object> { ["COUNT"] = 5 } })).StatusCode);
        await agent.ConnectAsync();
        var env = (await agent.NextJobAsync()).Payload.GetProperty("spec").GetProperty("env");
        Assert.Equal("5", env.GetProperty("COUNT").GetString());
        Assert.Equal("false", env.GetProperty("FORCE").GetString());
    }
}
