using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dranzo.Api.Features;
using Dranzo.Api.Notifications;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Dranzo.Tests;

[Collection("server")]
public class Phase8Tests(ServerFixture fx)
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

    private async Task<int> RolloutAsync(params Guid[] devices)
    {
        await using var scope = fx.App.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
        return await scope.ServiceProvider.GetRequiredService<UpdateRollout>().RunAsync(devices, default);
    }

    [Fact]
    public async Task Release_rolls_out_ring_by_ring_with_signed_offers_and_handles_rollback()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Rel " + U);
        var testGroup = (await admin.PostJsonAsync("/api/v1/groups", new { siteId = org.SiteId, name = "Test ring", updateRing = "test" })).GetProperty("id").GetGuid();
        var pilotGroup = (await admin.PostJsonAsync("/api/v1/groups", new { siteId = org.SiteId, name = "Pilot ring", updateRing = "pilot" })).GetProperty("id").GetGuid();
        async Task<TestAgent> InGroupAsync(Guid? group, string host)
        {
            var token = (await admin.PostJsonAsync("/api/v1/enrollment-tokens", new { siteId = org.SiteId, groupId = group, name = host })).GetProperty("token").GetString()!;
            return await TestAgent.EnrollAsync(fx, token, host);
        }
        await using var test = await InGroupAsync(testGroup, "rel-test");
        await using var pilot = await InGroupAsync(pilotGroup, "rel-pilot");
        await using var everyone = await InGroupAsync(org.GroupId, "rel-all"); // default ring "all"
        await using var ungrouped = await InGroupAsync(null, "rel-ungrouped");

        var binary = RandomNumberGenerator.GetBytes(1_200_000);
        var sha = Convert.ToHexStringLower(SHA256.HashData(binary));
        await admin.StepUpAsync();
        var upload = await (await admin.SendAsync(HttpMethod.Put, "/api/v1/releases/upload?fileName=dranzo-agent", new ByteArrayContent(binary))).Content.ReadFromJsonAsync<JsonElement>();
        var blobId = upload.GetProperty("blobId").GetGuid();
        var version = $"9.{Random.Shared.Next(1, 9999)}.0";
        var release = (await admin.PostJsonAsync("/api/v1/releases", new { version, notes = "test", binaries = new[] { new { os = "linux", arch = "amd64", blobId } } })).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsync("/api/v1/releases", new { version, binaries = new[] { new { os = "linux", arch = "amd64", blobId } } })).StatusCode);
        // The stored release signature verifies with the command-signing public key.
        var stored = await fx.DbAsync(db => db.AgentReleaseBinaries.FirstAsync(b => b.ReleaseId == release));
        var signer = fx.Service<ICommandSigner>();
        var verifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        verifier.Init(false, new Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters(signer.PublicKey, 0));
        var input = Encoding.UTF8.GetBytes(ReleaseEndpoints.SignatureInput(version, "linux", "amd64", sha));
        verifier.BlockUpdate(input, 0, input.Length);
        Assert.True(verifier.VerifySignature(Convert.FromBase64String(stored.Signature)));

        var all = new[] { test.DeviceId, pilot.DeviceId, everyone.DeviceId, ungrouped.DeviceId };
        Assert.Equal(0, await RolloutAsync(all)); // ring "none": nobody is offered anything

        await admin.PostJsonAsync($"/api/v1/releases/{release}/rollout", new { ring = "test" });
        Assert.Equal(1, await RolloutAsync(all));
        var offer = await test.WaitForAsync("update.available");
        Assert.True(offer.Signed && offer.SignatureValid);
        Assert.Equal(test.DeviceId.ToString("D"), offer.Payload.GetProperty("deviceId").GetString());
        Assert.Equal(version, offer.Payload.GetProperty("version").GetString());
        Assert.Equal(sha, offer.Payload.GetProperty("sha256").GetString());
        Assert.Equal(binary.Length, offer.Payload.GetProperty("sizeBytes").GetInt64());
        Assert.True(await pilot.NoneAsync("update.available", 300));
        // Only the offered device may download the binary.
        using var testHttp = test.NewHttp();
        Assert.Equal(sha, Convert.ToHexStringLower(SHA256.HashData(await testHttp.GetByteArrayAsync($"/agent/v1/blobs/{blobId}"))));
        using var pilotHttp = pilot.NewHttp();
        Assert.Equal(HttpStatusCode.NotFound, (await pilotHttp.GetAsync($"/agent/v1/blobs/{blobId}")).StatusCode);
        Assert.Equal(0, await RolloutAsync(all)); // not re-offered right away

        await test.SendAsync("update.status", new { version, state = "installed" });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/releases/{release}/devices"), d => d.EnumerateArray().Any(x => x.GetProperty("state").GetString() == "installed"));

        await admin.PostJsonAsync($"/api/v1/releases/{release}/rollout", new { ring = "pilot" });
        await fx.DbAsync(db => db.Devices.Where(d => d.Id == test.DeviceId).ExecuteUpdateAsync(s => s.SetProperty(d => d.AgentVersion, version))); // the updated agent reports the new version in hello
        Assert.Equal(1, await RolloutAsync(all));
        await pilot.WaitForAsync("update.available");
        // The pilot device fails to come up on the new version and rolls back: never offered this version again, and an alert is raised.
        await pilot.SendAsync("update.status", new { version, state = "rolled_back", error = "no hello.ack within 5 minutes" });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/alerts?deviceId={pilot.DeviceId}&state=open"), a => a.GetProperty("total").GetInt32() == 1);
        fx.Clock.Advance(TimeSpan.FromMinutes(31));
        Assert.Equal(0, await RolloutAsync(test.DeviceId, pilot.DeviceId));

        // Pausing stops the rollout; "all" reaches grouped and ungrouped devices.
        admin = await fx.AdminAsync();
        await admin.StepUpAsync();
        await admin.PostJsonAsync($"/api/v1/releases/{release}/rollout", new { ring = "all", paused = true });
        Assert.Equal(0, await RolloutAsync(all));
        await admin.PostJsonAsync($"/api/v1/releases/{release}/rollout", new { paused = false });
        Assert.Equal(2, await RolloutAsync(all));
        await everyone.WaitForAsync("update.available");
        await ungrouped.WaitForAsync("update.available");
        var audit = (await admin.GetJsonAsync("/api/v1/audit?action=agent_&pageSize=100")).GetProperty("items").EnumerateArray().Select(e => e.GetProperty("action").GetString()).ToList();
        Assert.Contains("agent_release.create", audit);
        Assert.Contains("agent_update.offer", audit);
        Assert.Contains("agent_update.rolled_back", audit);
    }

    [Fact]
    public async Task Api_keys_are_scoped_rate_limited_and_cannot_do_interactive_actions()
    {
        var admin = await fx.AdminAsync();
        var a = await fx.SeedOrgAsync("KeyA " + U);
        var b = await fx.SeedOrgAsync("KeyB " + U);
        await using var devA = await TestAgent.EnrollAsync(fx, a.Token, "key-a", connect: false);
        await using var devB = await TestAgent.EnrollAsync(fx, b.Token, "key-b", connect: false);
        await admin.StepUpAsync();
        var created = await admin.PostJsonAsync("/api/v1/api-keys", new { name = "ci " + U, expiresInDays = 30 });
        var key = created.GetProperty("key").GetString()!;
        var keyId = created.GetProperty("id").GetGuid();
        using var http = new HttpClient { BaseAddress = new Uri(fx.DashboardUrl) };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);

        // No role yet: authenticated but allowed nothing.
        Assert.Equal(HttpStatusCode.Forbidden, (await http.GetAsync("/api/v1/devices")).StatusCode);
        var roles = await admin.GetJsonAsync("/api/v1/roles");
        Guid Role(string name) => roles.EnumerateArray().First(r => r.GetProperty("name").GetString() == name).GetProperty("id").GetGuid();
        // Roles containing interactive-only permissions cannot be given to a key.
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/role-assignments", new { apiKeyId = keyId, roleId = Role(BuiltInRoles.Technician), scopeType = "Organization", scopeId = a.OrgId })).StatusCode);
        var automationRole = await fx.CreateRoleAsync("Automation " + U, Permissions.DevicesRead, Permissions.DevicesManage, Permissions.ScriptsRead, Permissions.ScriptsRun, Permissions.JobsRead);
        await admin.StepUpAsync();
        await admin.PostJsonAsync("/api/v1/role-assignments", new { apiKeyId = keyId, roleId = automationRole, scopeType = "Organization", scopeId = a.OrgId });

        var devices = await http.GetFromJsonAsync<JsonElement>("/api/v1/devices");
        Assert.Equal([devA.DeviceId], devices.GetProperty("items").EnumerateArray().Select(d => d.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync($"/api/v1/devices/{devB.DeviceId}")).StatusCode);
        // Writes work without a CSRF token (no cookies involved) and are audited as the key.
        Assert.Equal(HttpStatusCode.NoContent, (await http.PatchAsJsonAsync($"/api/v1/devices/{devA.DeviceId}", new { tags = new[] { "from-api" } })).StatusCode);
        var entry = (await admin.GetJsonAsync($"/api/v1/audit?deviceId={devA.DeviceId}&action=device.update")).GetProperty("items")[0];
        Assert.Equal("apikey", entry.GetProperty("actorType").GetString());
        // Step-up protected and interactive endpoints are closed to keys, as are wide runs that would need step-up.
        Assert.Equal(HttpStatusCode.Forbidden, (await http.PostAsJsonAsync($"/api/v1/devices/{devA.DeviceId}/sessions/terminal", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await http.PostAsJsonAsync($"/api/v1/devices/{devA.DeviceId}/revoke", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await http.GetAsync("/api/v1/auth/me")).StatusCode);
        var script = (await admin.PostJsonAsync("/api/v1/scripts", new { name = "k " + U, language = "sh", body = "true", organizationId = a.OrgId })).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.Created, (await http.PostAsJsonAsync("/api/v1/jobs/run-script", new { scriptId = script, target = new { deviceIds = new[] { devA.DeviceId } } })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.PostAsJsonAsync("/api/v1/jobs/run-script", new { scriptId = script, target = new { organizationId = a.OrgId } })).StatusCode);

        // A key with a wrong secret is rejected.
        using var bad = new HttpClient { BaseAddress = new Uri(fx.DashboardUrl) };
        bad.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key[..^4] + "AAAA");
        Assert.Equal(HttpStatusCode.Unauthorized, (await bad.GetAsync("/api/v1/devices")).StatusCode);

        // Rate limit: 120 requests per minute per key by default.
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 130; i++)
        {
            statuses.Add((await http.GetAsync("/api/v1/devices?pageSize=1")).StatusCode);
        }
        Assert.Contains(HttpStatusCode.TooManyRequests, statuses);

        // The secret is stored hashed.
        Assert.DoesNotContain(await fx.DbAsync(db => db.ApiKeys.IgnoreQueryFilters().Select(k => k.SecretHash).ToListAsync()), h => key.Contains(h));
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/v1/api-keys/{keyId}")).StatusCode);
        using var revoked = new HttpClient { BaseAddress = new Uri(fx.DashboardUrl) };
        revoked.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);
        Assert.Contains((await revoked.GetAsync("/api/v1/devices")).StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.TooManyRequests });
    }

    [Fact]
    public async Task Reports_render_as_csv_and_pdf_and_follow_the_callers_scope()
    {
        var admin = await fx.AdminAsync();
        var a = await fx.SeedOrgAsync("RepA " + U);
        var b = await fx.SeedOrgAsync("RepB " + U);
        await using var devA = await TestAgent.EnrollAsync(fx, a.Token, "=HYPERLINK(\"http://evil\")"); // a hostile hostname must not become a spreadsheet formula
        await using var devB = await TestAgent.EnrollAsync(fx, b.Token, "repb-host-" + U);
        await devA.SendAsync("software.inventory", new { items = new object[] { new { name = "ReportApp", version = "1.0", source = "dpkg" } } });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{devA.DeviceId}/software"), v => v.GetArrayLength() == 1);

        foreach (var name in new[] { "device-inventory", "patch-compliance", "security-posture", "software", "audit-log" })
        {
            var csv = await admin.GetAsync($"/api/v1/reports/{name}.csv");
            Assert.True(csv.IsSuccessStatusCode, $"{name}: {(int)csv.StatusCode} {await csv.Content.ReadAsStringAsync()}");
            Assert.Equal("text/csv", csv.Content.Headers.ContentType!.MediaType);
            Assert.True((await csv.Content.ReadAsStringAsync()).Split('\n').Length > 2, name);
            var pdf = await admin.GetAsync($"/api/v1/reports/{name}.pdf?organizationId={a.OrgId}");
            var pdfError = pdf.IsSuccessStatusCode ? "" : await pdf.Content.ReadAsStringAsync();
            Assert.True(pdf.IsSuccessStatusCode, $"{name}: {(int)pdf.StatusCode} {pdfError[..Math.Min(900, pdfError.Length)]}");
            var bytes = await pdf.Content.ReadAsByteArrayAsync();
            Assert.Equal("%PDF-", Encoding.ASCII.GetString(bytes, 0, 5));
            Assert.True(bytes.Length > 1500, name);
        }
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync("/api/v1/reports/device-inventory.exe")).StatusCode);
        var inventory = await (await admin.GetAsync("/api/v1/reports/device-inventory.csv")).Content.ReadAsStringAsync();
        Assert.Contains("\"'=HYPERLINK", inventory);
        Assert.DoesNotContain(",\"=HYPERLINK", inventory);

        // Client portal: an Organization Viewer reads their own organization and nothing else, and cannot change anything.
        var viewer = await fx.CreateUserAsync($"client-{Guid.NewGuid():N}@client.test", BuiltInRoles.OrganizationViewer, ScopeType.Organization, a.OrgId);
        var viewerCsv = await (await viewer.GetAsync("/api/v1/reports/device-inventory.csv")).Content.ReadAsStringAsync();
        Assert.Contains("RepA", viewerCsv);
        Assert.DoesNotContain(devB.Hostname, viewerCsv);
        Assert.DoesNotContain("RepB", viewerCsv);
        var overview = await viewer.GetJsonAsync("/api/v1/overview");
        Assert.Equal(1, overview.GetProperty("devices").GetProperty("total").GetInt32());
        Assert.Equal([a.OrgId], overview.GetProperty("organizations").EnumerateArray().Select(o => o.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/v1/reports/audit-log.csv")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PatchAsync($"/api/v1/devices/{devA.DeviceId}", new { tags = new[] { "x" } })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsync("/api/v1/jobs/run-script", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/v1/users")).StatusCode);
        Assert.Equal(1, (await admin.GetJsonAsync("/api/v1/audit?action=report.generate&pageSize=1")).GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task Uninstall_code_is_sent_as_a_slow_hash_and_agent_uninstall_revokes_the_device()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Un " + U);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "uninstall-host");
        const string code = "Remove-Me-2026";
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync($"/api/v1/devices/{agent.DeviceId}/uninstall-code", new { code = "short" })).StatusCode);
        await admin.PostJsonAsync($"/api/v1/devices/{agent.DeviceId}/uninstall-code", new { code });
        var configure = await agent.NextJobAsync("agent.configure");
        var u = configure.Payload.GetProperty("spec").GetProperty("uninstallCode");
        var salt = Convert.FromBase64String(u.GetProperty("salt").GetString()!);
        var iterations = u.GetProperty("iterations").GetInt32();
        Assert.InRange(salt.Length, 16, 64);
        Assert.InRange(iterations, 100_000, 10_000_000);
        Assert.Equal(Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(code), salt, iterations, HashAlgorithmName.SHA256, 32)), u.GetProperty("hash").GetString());
        Assert.DoesNotContain(code, configure.Raw);
        await agent.CompleteAsync(configure);
        Assert.DoesNotContain(code, await (await admin.GetAsync($"/api/v1/audit?deviceId={agent.DeviceId}&pageSize=50")).Content.ReadAsStringAsync());
        Assert.DoesNotContain(code, await fx.DbAsync(async db => string.Join("|", await db.Jobs.IgnoreQueryFilters().Select(j => j.SpecJson).ToListAsync())));

        await admin.PostJsonAsync($"/api/v1/devices/{agent.DeviceId}/uninstall-agent", new { });
        var uninstall = await agent.NextJobAsync("agent.uninstall");
        await agent.CompleteAsync(uninstall);
        var device = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{agent.DeviceId}"), d => d.GetProperty("status").GetString() == "revoked");
        Assert.False(device.GetProperty("isOnline").GetBoolean());
        Assert.True(await agent.WaitClosedAsync());
    }

    [Fact]
    public async Task Subscribed_webhooks_receive_events()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Hook " + U);
        using var receiver = new WebhookReceiver();
        await admin.PostJsonAsync("/api/v1/notification-channels", new { name = "events " + U, type = "webhook", url = receiver.Url("/events"), organizationId = org.OrgId, eventTypes = new[] { "device.enrolled", "job.finished" } });
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "hook-host");
        var script = (await admin.PostJsonAsync("/api/v1/scripts", new { name = "h " + U, language = "sh", body = "true", organizationId = org.OrgId })).GetProperty("id").GetGuid();
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId = script, target = new { deviceIds = new[] { agent.DeviceId } } });
        await agent.CompleteAsync(await agent.NextJobAsync("script"));
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/runs/{job.GetProperty("runs")[0].GetProperty("id").GetGuid()}"), r => r.GetProperty("status").GetString() == "succeeded");
        await using (var scope = fx.App.Services.CreateAsyncScope())
        {
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            await NotificationSender.ProcessAsync(scope.ServiceProvider, default);
        }
        var events = receiver.Received.Select(r => JsonDocument.Parse(r.Body).RootElement).ToList();
        Assert.Contains(events, e => e.GetProperty("type").GetString() == "device.enrolled" && e.GetProperty("data").GetProperty("deviceId").GetGuid() == agent.DeviceId);
        Assert.Contains(events, e => e.GetProperty("type").GetString() == "job.finished" && e.GetProperty("data").GetProperty("status").GetString() == "succeeded");
    }
}
