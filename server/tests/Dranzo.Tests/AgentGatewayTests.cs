using System.Net;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Dranzo.Api.Agents;
using Dranzo.Domain;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Tests;

[Collection("server")]
public class AgentGatewayTests(ServerFixture fx)
{
    [Fact]
    public async Task Enroll_connect_heartbeat_inventory_shows_device_online()
    {
        var org = await fx.SeedOrgAsync("Gateway " + Guid.NewGuid().ToString("N")[..6]);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "gw-host-1");
        await agent.SendAsync("heartbeat", new { seq = 1, uptimeSeconds = 100, cpuPercent = 1.5, memUsedPercent = 40.0, consoleUser = "alice", pendingReboot = false, agentRssBytes = 20_000_000 });
        await agent.WaitForAsync("heartbeat.ack");
        await agent.SendAsync("inventory", new
        {
            collectedAt = DateTimeOffset.UtcNow, hostname = "gw-host-1", machineId = "m-1",
            os = new { family = "linux", name = "Ubuntu", version = "24.04", build = "", kernel = "6.8" }, arch = "amd64",
            cpu = new { model = "Test CPU", cores = 4, logicalCores = 8 }, memoryBytes = 8L << 30,
            disks = new[] { new { device = "/dev/sda1", mountPoint = "/", fsType = "ext4", totalBytes = 100L << 30, freeBytes = 60L << 30 } },
            network = new[] { new { name = "eth0", mac = "aa:bb:cc:dd:ee:ff", ipv4 = new[] { "10.0.0.5" }, ipv6 = Array.Empty<string>() } },
            serial = "SER123", manufacturer = "ACME", model = "Box 1", consoleUser = "alice", loggedInUsers = new[] { "alice" },
            uptimeSeconds = 100, pendingReboot = false, timezone = "UTC", unsupported = Array.Empty<string>(),
        });
        var admin = await fx.AdminAsync();
        JsonElement detail = default;
        for (var i = 0; i < 50; i++)
        {
            detail = await admin.GetJsonAsync($"/api/v1/devices/{agent.DeviceId}");
            if (detail.GetProperty("serial").GetString() == "SER123")
            {
                break;
            }
            await Task.Delay(50);
        }
        Assert.True(detail.GetProperty("isOnline").GetBoolean());
        Assert.Equal("SER123", detail.GetProperty("serial").GetString());
        Assert.Equal("Ubuntu", detail.GetProperty("osName").GetString());
        Assert.Equal("alice", detail.GetProperty("consoleUser").GetString());
        Assert.Equal("Test CPU", detail.GetProperty("inventory").GetProperty("cpu").GetProperty("model").GetString());
        var list = await admin.GetJsonAsync($"/api/v1/devices?organizationId={org.OrgId}&online=true&search=gw-host");
        Assert.Equal(1, list.GetProperty("total").GetInt32());
    }

    [Fact]
    public async Task Issued_certificate_ignores_csr_subject_and_is_client_auth_only()
    {
        var org = await fx.SeedOrgAsync("Cert " + Guid.NewGuid().ToString("N")[..6]);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "cert-host", connect: false);
        Assert.Contains(agent.DeviceId.ToString("D"), agent.Certificate.Subject);
        var eku = agent.Certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
        Assert.Equal(["1.3.6.1.5.5.7.3.2"], eku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value));
        Assert.False(agent.Certificate.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority);
    }

    [Theory]
    [InlineData("revoked")]
    [InlineData("expired")]
    [InlineData("used_up")]
    [InlineData("garbage")]
    public async Task Bad_enrollment_tokens_are_rejected(string kind)
    {
        var org = await fx.SeedOrgAsync("Tok " + Guid.NewGuid().ToString("N")[..6]);
        var admin = await fx.AdminAsync();
        var token = org.Token;
        switch (kind)
        {
            case "revoked":
                var list = await admin.GetJsonAsync($"/api/v1/enrollment-tokens?organizationId={org.OrgId}");
                await admin.DeleteAsync($"/api/v1/enrollment-tokens/{list[0].GetProperty("id").GetGuid()}");
                break;
            case "expired":
                await fx.DbAsync(db => db.EnrollmentTokens.Where(t => t.OrganizationId == org.OrgId).ExecuteUpdateAsync(s => s.SetProperty(t => t.ExpiresAt, DateTimeOffset.UtcNow.AddYears(-1))));
                break;
            case "used_up":
                var one = await admin.PostJsonAsync("/api/v1/enrollment-tokens", new { siteId = org.SiteId, name = "single", maxUses = 1 });
                token = one.GetProperty("token").GetString()!;
                var (first, a) = await TestAgent.TryEnrollAsync(fx, token, "one");
                Assert.Equal(HttpStatusCode.OK, first.StatusCode);
                await a.DisposeAsync();
                break;
            default:
                token = "dz_enroll_not-a-real-token";
                break;
        }
        var (response, _) = await TestAgent.TryEnrollAsync(fx, token, "should-fail");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Concurrent_enrollments_cannot_exceed_max_uses()
    {
        var org = await fx.SeedOrgAsync("Race " + Guid.NewGuid().ToString("N")[..6]);
        var admin = await fx.AdminAsync();
        var t = await admin.PostJsonAsync("/api/v1/enrollment-tokens", new { siteId = org.SiteId, name = "three", maxUses = 3 });
        var token = t.GetProperty("token").GetString()!;
        var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(i => TestAgent.TryEnrollAsync(fx, token, "race-" + i)));
        Assert.Equal(3, results.Count(r => r.Response.StatusCode == HttpStatusCode.OK));
        Assert.Equal(3, await fx.DbAsync(db => db.Devices.CountAsync(d => d.OrganizationId == org.OrgId)));
    }

    [Fact]
    public async Task Non_p256_and_garbage_csrs_are_rejected_without_consuming_the_token()
    {
        var org = await fx.SeedOrgAsync("Csr " + Guid.NewGuid().ToString("N")[..6]);
        using var rsa = RSA.Create(2048);
        var rsaCsr = new CertificateRequest("CN=x", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSigningRequestPem();
        Assert.Equal(HttpStatusCode.BadRequest, (await TestAgent.TryEnrollAsync(fx, org.Token, "rsa", csrOverride: rsaCsr)).Response.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await TestAgent.TryEnrollAsync(fx, org.Token, "junk", csrOverride: "not a csr")).Response.StatusCode);
        Assert.Equal(0, await fx.DbAsync(db => db.EnrollmentTokens.Where(t => t.OrganizationId == org.OrgId).SumAsync(t => t.Uses)));
    }

    [Fact]
    public async Task Revoked_device_is_disconnected_and_cannot_reconnect()
    {
        var org = await fx.SeedOrgAsync("Rev " + Guid.NewGuid().ToString("N")[..6]);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "revoke-me");
        var admin = await fx.AdminAsync();
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/v1/devices/{agent.DeviceId}/revoke")).StatusCode);
        Assert.True(await agent.WaitClosedAsync());
        var ex = await Assert.ThrowsAsync<WebSocketException>(() => agent.ConnectAsync());
        Assert.Contains("403", ex.Message);
        Assert.False(await agent.RenewAsync());
    }

    [Fact]
    public async Task Certificate_from_another_ca_fails_the_tls_handshake()
    {
        var org = await fx.SeedOrgAsync("Rogue " + Guid.NewGuid().ToString("N")[..6]);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "rogue", connect: false);
        using var rogueKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={agent.DeviceId:D}", rogueKey, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.2")], true));
        using var selfSigned = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
        var rogue = X509CertificateLoader.LoadPkcs12(selfSigned.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
        await Assert.ThrowsAnyAsync<Exception>(() => agent.ConnectAsync(certOverride: rogue));
        Assert.False(fx.Service<AgentRegistry>().IsConnected(agent.DeviceId));
    }

    [Fact]
    public async Task Renewal_rotates_the_certificate_and_retires_the_old_one()
    {
        var org = await fx.SeedOrgAsync("Renew " + Guid.NewGuid().ToString("N")[..6]);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "renew-host", connect: false);
        var old = agent.Certificate;
        Assert.True(await agent.RenewAsync());
        Assert.NotEqual(old.Thumbprint, agent.Certificate.Thumbprint);
        // The old certificate still works until the new one is first used...
        await agent.ConnectAsync(certOverride: old);
        // ...then connecting with the new one retires it.
        await agent.ConnectAsync();
        await Task.Delay(100);
        var ex = await Assert.ThrowsAsync<WebSocketException>(() => agent.ConnectAsync(certOverride: old));
        Assert.Contains("403", ex.Message);
    }

    [Fact]
    public async Task Listeners_are_separated()
    {
        var org = await fx.SeedOrgAsync("Sep " + Guid.NewGuid().ToString("N")[..6]);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "sep-host", connect: false);
        using var agentHttp = agent.NewHttp();
        // Dashboard API is not served on the agent listener, even with a valid device certificate.
        Assert.Equal(HttpStatusCode.NotFound, (await agentHttp.GetAsync("/api/v1/devices")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await agentHttp.PostAsJsonAsync("/api/v1/auth/login", new { email = "a", password = "b" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await agentHttp.GetAsync("/healthz")).StatusCode);
        // Agent endpoints are not served on the dashboard listener.
        var dash = fx.NewClient();
        Assert.Equal(HttpStatusCode.NotFound, (await dash.Http.PostAsJsonAsync("/agent/v1/enroll", new { token = org.Token })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await dash.Http.GetAsync("/agent/v1/ws")).StatusCode);
    }

    [Fact]
    public async Task Messages_before_hello_close_the_connection_and_unknown_types_get_an_error()
    {
        var org = await fx.SeedOrgAsync("Proto " + Guid.NewGuid().ToString("N")[..6]);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "proto-host", connect: false);
        await agent.ConnectAsync(sendHello: false);
        await agent.SendAsync("heartbeat", new { seq = 1 });
        Assert.True(await agent.WaitClosedAsync());

        await agent.ConnectAsync();
        await agent.SendAsync("does.not.exist", new { });
        var err = await agent.WaitForAsync("error");
        Assert.Equal("unknown_type", err.Payload.GetProperty("code").GetString());
        await agent.SendRawAsync("{not json");
        Assert.Equal("malformed", (await agent.WaitForAsync("error")).Payload.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Flooding_agent_is_disconnected()
    {
        var org = await fx.SeedOrgAsync("Flood " + Guid.NewGuid().ToString("N")[..6]);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "flood-host");
        try
        {
            for (var i = 0; i < 600; i++)
            {
                await agent.SendAsync("heartbeat", new { seq = i });
            }
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException or ObjectDisposedException)
        {
        }
        Assert.True(await agent.WaitClosedAsync());
    }

    [Fact]
    public async Task Second_enrollment_of_same_machine_creates_a_new_identity_and_flags_duplicate()
    {
        var org = await fx.SeedOrgAsync("Dup " + Guid.NewGuid().ToString("N")[..6]);
        var (r1, a1) = await TestAgent.TryEnrollAsync(fx, org.Token, "dup-host", machineId: "machine-xyz");
        var (r2, a2) = await TestAgent.TryEnrollAsync(fx, org.Token, "dup-host", machineId: "machine-xyz");
        Assert.True(r1.IsSuccessStatusCode && r2.IsSuccessStatusCode);
        Assert.NotEqual(a1.DeviceId, a2.DeviceId);
        var second = await fx.DbAsync(db => db.Devices.FirstAsync(d => d.Id == a2.DeviceId));
        Assert.Equal(a1.DeviceId, second.PossibleDuplicateOfDeviceId);
        // The first identity is untouched and still valid.
        await a1.ConnectAsync();
        Assert.Equal(WebSocketState.Open, a1.State);
        await a1.DisposeAsync();
        await a2.DisposeAsync();
    }

    [Fact]
    public async Task Oversized_message_closes_the_connection()
    {
        var org = await fx.SeedOrgAsync("Big " + Guid.NewGuid().ToString("N")[..6]);
        await using var agent = await TestAgent.EnrollAsync(fx, org.Token, "big-host");
        try
        {
            await agent.SendAsync("inventory", new { blob = new string('x', 3 * 1024 * 1024) });
        }
        catch (Exception ex) when (ex is WebSocketException or OperationCanceledException)
        {
        }
        Assert.True(await agent.WaitClosedAsync());
    }
}
