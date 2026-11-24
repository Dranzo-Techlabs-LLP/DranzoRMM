using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dranzo.Api.Features;
using Dranzo.Domain;
using Dranzo.Tests.Infra;
using Microsoft.AspNetCore.SignalR.Client;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Tests;

[Collection("server")]
public class RemoteSessionTests(ServerFixture fx)
{
    private static string U => Guid.NewGuid().ToString("N")[..6];

    private async Task<HubConnection> HubAsync(ApiClient c)
    {
        var hub = new HubConnectionBuilder().WithUrl(fx.DashboardUrl + "/hubs/live", o =>
        {
            o.Cookies = c.Cookies;
            o.Headers["X-CSRF-Token"] = c.Csrf!;
        }).Build();
        await hub.StartAsync();
        return hub;
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

    private async Task<(ServerFixture.OrgSeed Org, TestAgent Agent)> SetupAsync(string consent, string host)
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Rs " + U);
        await admin.PatchAsync($"/api/v1/organizations/{org.OrgId}", new { consentMode = consent });
        return (org, await TestAgent.EnrollAsync(fx, org.Token, host));
    }

    private static async Task<Guid> StartAsync(ApiClient c, TestAgent agent, string kind, object? body = null)
    {
        await c.StepUpAsync();
        var r = await c.PostJsonAsync($"/api/v1/devices/{agent.DeviceId}/sessions/{kind}", body ?? new { });
        return r.GetProperty("sessionId").GetGuid();
    }

    [Fact]
    public async Task Terminal_session_with_consent_signed_input_live_output_and_audit()
    {
        var (org, agent) = await SetupAsync("require", "term-host");
        await using var _ = agent;
        var admin = await fx.AdminAsync();
        fx.Clock.Advance(TimeSpan.FromMinutes(6));
        admin = await fx.AdminAsync();
        // Opening a session needs fresh step-up.
        var denied = await admin.PostAsync($"/api/v1/devices/{agent.DeviceId}/sessions/terminal", new { });
        Assert.Contains("step_up_required", await denied.Content.ReadAsStringAsync());

        var sessionId = await StartAsync(admin, agent, "terminal", new { cols = 100, rows = 40, runAs = "system" });
        var start = await agent.WaitForAsync("session.start");
        Assert.True(start.Signed && start.SignatureValid);
        Assert.Equal(agent.DeviceId.ToString("D"), start.Payload.GetProperty("deviceId").GetString());
        Assert.Equal("require", start.Payload.GetProperty("consent").GetString());
        Assert.Equal("terminal", start.Payload.GetProperty("kind").GetString());
        Assert.Contains("Administrator (Partner One)", start.Payload.GetProperty("requestedBy").GetString());
        Assert.Equal(100, start.Payload.GetProperty("terminal").GetProperty("cols").GetInt32());

        await using var hub = await HubAsync(admin);
        var output = new List<string>();
        var states = new List<string>();
        hub.On<JsonElement>("terminalOutput", e => output.Add(Encoding.UTF8.GetString(Convert.FromBase64String(e.GetProperty("data").GetString()!))));
        hub.On<JsonElement>("sessionState", e => states.Add(e.GetProperty("state").GetString()!));
        Assert.True(await hub.InvokeAsync<bool>("JoinSession", sessionId));
        // No keystrokes reach the device before the user at the device has accepted.
        await agent.SendAsync("session.status", new { sessionId, state = "pending_consent" });
        Assert.False(await hub.InvokeAsync<bool>("TerminalInput", sessionId, Convert.ToBase64String("id\n"u8)));
        Assert.True(await agent.NoneAsync("session.input", 300));

        await agent.SendAsync("session.status", new { sessionId, state = "active" });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/sessions/{sessionId}"), s => s.GetProperty("state").GetString() == "active");
        Assert.True(await hub.InvokeAsync<bool>("TerminalInput", sessionId, Convert.ToBase64String("whoami\n"u8)));
        Assert.True(await hub.InvokeAsync<bool>("TerminalResize", sessionId, 132, 50));
        var in1 = await agent.WaitForAsync("session.input");
        var in2 = await agent.WaitForAsync("session.input");
        Assert.True(in1.Signed && in1.SignatureValid && in2.SignatureValid);
        Assert.Equal(1, in1.Payload.GetProperty("seq").GetInt64());
        Assert.Equal(2, in2.Payload.GetProperty("seq").GetInt64());
        Assert.Equal("whoami\n", Encoding.UTF8.GetString(Convert.FromBase64String(in1.Payload.GetProperty("data").GetString()!)));
        Assert.Equal("resize", in2.Payload.GetProperty("kind").GetString());
        Assert.Equal(132, in2.Payload.GetProperty("cols").GetInt32());
        Assert.Equal(sessionId.ToString("D"), in1.Payload.GetProperty("sessionId").GetString());

        await agent.SendAsync("session.output", new { sessionId, seq = 1, data = Convert.ToBase64String("root\n"u8) });
        for (var i = 0; i < 100 && output.Count == 0; i++)
        {
            await Task.Delay(30);
        }
        Assert.Equal(["root\n"], output);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/v1/sessions/{sessionId}/end")).StatusCode);
        var end = await agent.WaitForAsync("session.end");
        Assert.True(end.Signed && end.SignatureValid);
        Assert.False(await hub.InvokeAsync<bool>("TerminalInput", sessionId, Convert.ToBase64String("x"u8)));

        var session = await admin.GetJsonAsync($"/api/v1/sessions/{sessionId}");
        Assert.Equal("ended", session.GetProperty("state").GetString());
        Assert.Equal("accepted", session.GetProperty("consentResult").GetString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData("whoami\n"u8)), session.GetProperty("inputSha256").GetString());
        var actions = (await admin.GetJsonAsync($"/api/v1/audit?deviceId={agent.DeviceId}&action=session.&pageSize=20")).GetProperty("items").EnumerateArray().Select(e => e.GetProperty("action").GetString()).ToList();
        Assert.Contains("session.request", actions);
        Assert.Contains("session.start", actions);
        Assert.Contains("session.end", actions);
        Assert.Contains("active", states);
    }

    [Fact]
    public async Task Denied_consent_and_disconnect_end_the_session()
    {
        var (org, agent) = await SetupAsync("require", "deny-host");
        await using var _ = agent;
        var admin = await fx.AdminAsync();
        var denied = await StartAsync(admin, agent, "terminal");
        await agent.WaitForAsync("session.start");
        await agent.SendAsync("session.status", new { sessionId = denied, state = "denied", reason = "user_denied" });
        var s = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/sessions/{denied}"), x => x.GetProperty("state").GetString() == "denied");
        Assert.Equal("denied", s.GetProperty("consentResult").GetString());
        Assert.Equal(1, (await admin.GetJsonAsync($"/api/v1/audit?deviceId={agent.DeviceId}&action=session.denied")).GetProperty("total").GetInt32());

        // A session that was active ends when the control connection drops (fail closed).
        var second = await StartAsync(admin, agent, "terminal");
        await agent.WaitForAsync("session.start", m => m.Payload.GetProperty("sessionId").GetString() == second.ToString("D"));
        await agent.SendAsync("session.status", new { sessionId = second, state = "active" });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/sessions/{second}"), x => x.GetProperty("state").GetString() == "active");
        await agent.CloseAsync();
        s = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/sessions/{second}"), x => x.GetProperty("state").GetString() == "ended");
        Assert.Equal("connection lost", s.GetProperty("endReason").GetString());
        // Offline device: no session can be requested.
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync($"/api/v1/devices/{agent.DeviceId}/sessions/terminal", new { })).StatusCode);
    }

    [Fact]
    public async Task Only_the_owner_and_the_sessions_own_device_can_drive_a_session()
    {
        var (org, agent) = await SetupAsync("none", "own-host");
        await using var _ = agent;
        await using var otherAgent = await TestAgent.EnrollAsync(fx, org.Token, "other-host");
        var admin = await fx.AdminAsync();
        var sessionId = await StartAsync(admin, agent, "terminal");
        await agent.WaitForAsync("session.start");

        // Another device's agent cannot activate or feed the session.
        await otherAgent.SendAsync("session.status", new { sessionId, state = "active" });
        await otherAgent.SendAsync("session.output", new { sessionId, seq = 1, data = Convert.ToBase64String("forged"u8) });
        await otherAgent.SendAsync("heartbeat", new { seq = 1 });
        await otherAgent.WaitForAsync("heartbeat.ack");
        Assert.Equal("requested", (await admin.GetJsonAsync($"/api/v1/sessions/{sessionId}")).GetProperty("state").GetString());
        await agent.SendAsync("session.status", new { sessionId, state = "active" });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/sessions/{sessionId}"), x => x.GetProperty("state").GetString() == "active");

        // Another technician with full rights on the same organization cannot join or type into it.
        var other = await fx.CreateUserAsync($"rs-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, org.OrgId);
        await using var otherHub = await HubAsync(other);
        Assert.False(await otherHub.InvokeAsync<bool>("JoinSession", sessionId));
        Assert.False(await otherHub.InvokeAsync<bool>("TerminalInput", sessionId, Convert.ToBase64String("rm -rf /\n"u8)));
        Assert.True(await agent.NoneAsync("session.input", 300));
        // ...but can see it in the session list and end it.
        Assert.Contains((await other.GetJsonAsync($"/api/v1/sessions?deviceId={agent.DeviceId}")).GetProperty("items").EnumerateArray(), x => x.GetProperty("id").GetGuid() == sessionId);
        Assert.Equal(HttpStatusCode.NoContent, (await other.PostAsync($"/api/v1/sessions/{sessionId}/end")).StatusCode);
        await agent.WaitForAsync("session.end");

        // A technician of another organization cannot open or see sessions here.
        var elsewhere = await fx.SeedOrgAsync("RsX " + U);
        var outsider = await fx.CreateUserAsync($"rsx-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, elsewhere.OrgId);
        await outsider.StepUpAsync();
        Assert.Equal(HttpStatusCode.NotFound, (await outsider.PostAsync($"/api/v1/devices/{agent.DeviceId}/sessions/terminal", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await outsider.GetAsync($"/api/v1/sessions/{sessionId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await outsider.PostAsync($"/api/v1/sessions/{sessionId}/end")).StatusCode);
    }

    [Fact]
    public async Task File_browser_lists_downloads_and_uploads_inside_an_active_session_only()
    {
        var (org, agent) = await SetupAsync("notify", "files-host");
        await using var _ = agent;
        var admin = await fx.AdminAsync();
        var sessionId = await StartAsync(admin, agent, "files");
        var start = await agent.WaitForAsync("session.start");
        Assert.Equal("notify", start.Payload.GetProperty("consent").GetString());
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync($"/api/v1/sessions/{sessionId}/files/list", new { path = "/etc" })).StatusCode); // not active yet
        await agent.SendAsync("session.status", new { sessionId, state = "active" });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/sessions/{sessionId}"), x => x.GetProperty("state").GetString() == "active");

        // list
        var listTask = admin.PostAsync($"/api/v1/sessions/{sessionId}/files/list", new { path = "/etc" });
        var list = await agent.NextJobAsync("file.list");
        Assert.Equal(sessionId.ToString("D"), list.Payload.GetProperty("sessionId").GetString());
        Assert.Equal("/etc", list.Payload.GetProperty("spec").GetProperty("path").GetString());
        await agent.CompleteAsync(list, result: new { path = "/etc", entries = new[] { new { name = "hosts", isDir = false, sizeBytes = 120, modifiedAt = DateTimeOffset.UtcNow, mode = "0644" } }, truncated = false });
        var listed = await (await listTask).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("hosts", listed.GetProperty("entries")[0].GetProperty("name").GetString());

        // download: the agent uploads the file over mTLS with a one-time ticket
        var content = RandomNumberGenerator.GetBytes(50_000);
        var downloadTask = admin.PostAsync($"/api/v1/sessions/{sessionId}/files/download", new { path = "/etc/hosts" });
        var read = await agent.NextJobAsync("file.read");
        var uploadId = read.Payload.GetProperty("spec").GetProperty("uploadId").GetGuid();
        using var agentHttp = agent.NewHttp();
        var put = await agentHttp.PutAsync($"/agent/v1/uploads/{uploadId}", new ByteArrayContent(content));
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await agentHttp.PutAsync($"/agent/v1/uploads/{uploadId}", new ByteArrayContent(content))).StatusCode); // single use
        var sha = Convert.ToHexStringLower(SHA256.HashData(content));
        await agent.CompleteAsync(read, result: new { sizeBytes = content.Length, sha256 = sha });
        var download = await (await downloadTask).Content.ReadFromJsonAsync<JsonElement>();
        var file = await admin.GetAsync($"/api/v1/sessions/{sessionId}/files/content/{download.GetProperty("ticketId").GetGuid()}?fileName=hosts");
        Assert.Equal(content, await file.Content.ReadAsByteArrayAsync());
        Assert.Equal("attachment", file.Content.Headers.ContentDisposition!.DispositionType);
        Assert.Equal("application/octet-stream", file.Content.Headers.ContentType!.MediaType);
        // another technician cannot fetch that content
        var other = await fx.CreateUserAsync($"rf-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, org.OrgId);
        Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync($"/api/v1/sessions/{sessionId}/files/content/{download.GetProperty("ticketId").GetGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await other.PostAsync($"/api/v1/sessions/{sessionId}/files/list", new { path = "/" })).StatusCode);

        // upload: the agent gets a blob id + hash and downloads it over mTLS
        var payload = RandomNumberGenerator.GetBytes(20_000);
        var uploadTask = admin.SendAsync(HttpMethod.Put, $"/api/v1/sessions/{sessionId}/files/upload?path=%2Ftmp%2Fnew.bin&overwrite=true", new ByteArrayContent(payload));
        var write = await agent.NextJobAsync("file.write");
        var spec = write.Payload.GetProperty("spec");
        Assert.Equal("/tmp/new.bin", spec.GetProperty("path").GetString());
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(payload)), spec.GetProperty("sha256").GetString());
        Assert.Equal(payload, await agentHttp.GetByteArrayAsync($"/agent/v1/blobs/{spec.GetProperty("blobId").GetGuid()}"));
        await agent.CompleteAsync(write, result: new { sizeBytes = payload.Length });
        Assert.Equal(HttpStatusCode.OK, (await uploadTask).StatusCode);

        // a device-side failure is reported, not hidden
        var failTask = admin.PostAsync($"/api/v1/sessions/{sessionId}/files/list", new { path = "/root/secret" });
        await agent.CompleteAsync(await agent.NextJobAsync("file.list"), "failed", 1, message: "permission denied");
        var fail = await failTask;
        Assert.Equal((HttpStatusCode)422, fail.StatusCode);
        Assert.Contains("permission denied", await fail.Content.ReadAsStringAsync());

        var audit = (await admin.GetJsonAsync($"/api/v1/audit?deviceId={agent.DeviceId}&action=file.&pageSize=20")).GetProperty("items").EnumerateArray().ToList();
        Assert.Contains(audit, e => e.GetProperty("action").GetString() == "file.download" && e.GetProperty("contentSha256").GetString() == sha);
        Assert.Contains(audit, e => e.GetProperty("action").GetString() == "file.upload");
        Assert.Contains(audit, e => e.GetProperty("action").GetString() == "file.list" && e.GetProperty("result").GetString() == "failure");

        await admin.PostAsync($"/api/v1/sessions/{sessionId}/end");
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync($"/api/v1/sessions/{sessionId}/files/list", new { path = "/etc" })).StatusCode);

        // The session record counts the transferred bytes: device -> technician (download) as out, upload as in.
        var ended = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/sessions/{sessionId}"), x => x.GetProperty("state").GetString() == "ended");
        Assert.Equal(((long)content.Length, (long)payload.Length), (ended.GetProperty("bytesOut").GetInt64(), ended.GetProperty("bytesIn").GetInt64()));
    }

    [Fact]
    public async Task Remote_desktop_link_is_short_lived_per_organization_and_refuses_a_shared_account()
    {
        var (org, agent) = await SetupAsync("none", "desk-host");
        await using var _ = agent;
        var admin = await fx.AdminAsync();
        var sessionId = await StartAsync(admin, agent, "desktop");
        var start = await agent.WaitForAsync("session.start");
        Assert.Equal("desktop", start.Payload.GetProperty("kind").GetString());
        await agent.SendAsync("session.status", new { sessionId, state = "active" });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/sessions/{sessionId}"), x => x.GetProperty("state").GetString() == "active");

        // The MeshAgent is not installed yet.
        Assert.Equal(HttpStatusCode.Conflict, (await admin.GetAsync($"/api/v1/sessions/{sessionId}/desktop-url")).StatusCode);
        var nodeId = "node//" + new string('a', 64);
        await fx.DbAsync(db => db.Devices.Where(d => d.Id == agent.DeviceId).ExecuteUpdateAsync(s => s.SetProperty(d => d.MeshNodeId, nodeId)));
        // Installed, but the organization has no dedicated MeshCentral account: refused rather than using a shared login.
        var refused = await admin.GetAsync($"/api/v1/sessions/{sessionId}/desktop-url");
        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        Assert.Contains("shared account", await refused.Content.ReadAsStringAsync());

        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PatchAsync($"/api/v1/organizations/{org.OrgId}/mesh", new { meshUser = "user//org-" + org.OrgId.ToString("N")[..6], meshGroupId = "mesh//abc" })).StatusCode);
        var url = new Uri((await admin.GetJsonAsync($"/api/v1/sessions/{sessionId}/desktop-url")).GetProperty("url").GetString()!);
        Assert.Equal("mesh.example.test", url.Host);
        var query = System.Web.HttpUtility.ParseQueryString(url.Query);
        // MeshCentral's web app prefixes "node/<domain>/" itself; the full id opened no device (field test 2026-11-24).
        Assert.Equal(new string('a', 64), query["gotonode"]);
        var token = JsonDocument.Parse(MeshCentral.DecodeToken(query["login"]!, ServerFixture.MeshTestKey)!).RootElement;
        Assert.Equal("user//org-" + org.OrgId.ToString("N")[..6], token.GetProperty("u").GetString());
        Assert.True(token.GetProperty("expire").GetInt32() <= 5);
        // The link is never written to the audit log.
        var audit = await (await admin.GetAsync($"/api/v1/audit?deviceId={agent.DeviceId}&pageSize=50")).Content.ReadAsStringAsync();
        Assert.Contains("session.desktop_url", audit);
        Assert.DoesNotContain("login=", audit);
        await admin.PostAsync($"/api/v1/sessions/{sessionId}/end");
        Assert.Equal(HttpStatusCode.Conflict, (await admin.GetAsync($"/api/v1/sessions/{sessionId}/desktop-url")).StatusCode);
    }
}
