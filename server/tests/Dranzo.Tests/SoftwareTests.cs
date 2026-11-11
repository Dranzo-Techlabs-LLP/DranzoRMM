using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Dranzo.Domain;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Tests;

[Collection("server")]
public class SoftwareTests(ServerFixture fx)
{
    private static string U => Guid.NewGuid().ToString("N")[..6];

    private static async Task SetOsNameAsync(TestAgent agent, string name) =>
        await agent.SendAsync("inventory", new { hostname = agent.Hostname, os = new { family = agent.Os, name, version = "1" }, arch = "amd64" });

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
    public async Task Reported_software_is_listed_per_device_and_aggregated()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Sw " + U);
        await using var a = await TestAgent.EnrollAsync(fx, org.Token, "sw-a");
        await using var b = await TestAgent.EnrollAsync(fx, org.Token, "sw-b");
        var marker = "ZipTool" + U;
        await a.SendAsync("software.inventory", new { collectedAt = DateTimeOffset.UtcNow, items = new object[] { new { name = marker, version = "1.0", publisher = "Zip Inc", source = "dpkg", id = "ziptool" }, new { name = "curl", version = "8.5", source = "dpkg" } }, truncated = false });
        await b.SendAsync("software.inventory", new { collectedAt = DateTimeOffset.UtcNow, items = new object[] { new { name = marker, version = "2.0", publisher = "Zip Inc", source = "rpm" } }, truncated = false });
        var list = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{a.DeviceId}/software"), v => v.GetArrayLength() == 2);
        Assert.Contains(list.EnumerateArray(), s => s.GetProperty("name").GetString() == marker && s.GetProperty("version").GetString() == "1.0");
        var agg = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/software?organizationId={org.OrgId}&search={marker}"), v => v.GetProperty("total").GetInt32() == 1 && v.GetProperty("items")[0].GetProperty("devices").GetInt32() == 2);
        Assert.Equal(2, agg.GetProperty("items")[0].GetProperty("versions").GetInt32());
        // A new report replaces the old list.
        await a.SendAsync("software.inventory", new { items = new object[] { new { name = "curl", version = "8.6", source = "dpkg" } } });
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{a.DeviceId}/software"), v => v.GetArrayLength() == 1);
    }

    [Fact]
    public async Task Package_manager_deploy_picks_the_right_manager_per_device()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Pm " + U);
        await using var win = await TestAgent.EnrollAsync(fx, org.Token, "pm-win", os: "windows");
        await using var mac = await TestAgent.EnrollAsync(fx, org.Token, "pm-mac", os: "macos");
        await using var ubuntu = await TestAgent.EnrollAsync(fx, org.Token, "pm-ubuntu");
        await using var rocky = await TestAgent.EnrollAsync(fx, org.Token, "pm-rocky");
        await using var odd = await TestAgent.EnrollAsync(fx, org.Token, "pm-odd");
        await SetOsNameAsync(ubuntu, "Ubuntu");
        await SetOsNameAsync(rocky, "Rocky Linux");
        await SetOsNameAsync(odd, "Mystery OS");
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/devices/{odd.DeviceId}"), d => d.GetProperty("osName").GetString() == "Mystery OS");

        var deploy = await admin.PostJsonAsync("/api/v1/software/deploy", new
        {
            action = "install",
            packages = new Dictionary<string, string> { ["winget"] = "7zip.7zip", ["brew"] = "sevenzip", ["apt"] = "7zip", ["dnf"] = "p7zip" },
            target = new { deviceIds = new[] { win.DeviceId, mac.DeviceId, ubuntu.DeviceId, rocky.DeviceId, odd.DeviceId } },
        });
        async Task<(string, string)> Got(TestAgent a)
        {
            var spec = (await a.NextJobAsync("software.install")).Payload.GetProperty("spec");
            return (spec.GetProperty("manager").GetString()!, spec.GetProperty("packageId").GetString()!);
        }
        Assert.Equal(("winget", "7zip.7zip"), await Got(win));
        Assert.Equal(("brew", "sevenzip"), await Got(mac));
        Assert.Equal(("apt", "7zip"), await Got(ubuntu));
        Assert.Equal(("dnf", "p7zip"), await Got(rocky));
        var job = await UntilAsync(() => admin.GetJsonAsync($"/api/v1/jobs/{deploy.GetProperty("jobId").GetGuid()}"),
            j => j.GetProperty("runs").EnumerateArray().Any(r => r.GetProperty("status").GetString() == "unsupported"));
        Assert.Equal(odd.DeviceId, job.GetProperty("runs").EnumerateArray().Single(r => r.GetProperty("status").GetString() == "unsupported").GetProperty("deviceId").GetGuid());
    }

    [Theory]
    [InlineData("7zip; rm -rf /")]
    [InlineData("$(curl evil)")]
    [InlineData("-o ProxyCommand=x")]
    [InlineData("")]
    public async Task Package_ids_that_are_not_plain_identifiers_are_rejected(string id)
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Inj " + U);
        await using var dev = await TestAgent.EnrollAsync(fx, org.Token, "inj", connect: false);
        var r = await admin.PostAsync("/api/v1/software/deploy", new { action = "install", packages = new Dictionary<string, string> { ["apt"] = id }, target = new { deviceIds = new[] { dev.DeviceId } } });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task Custom_package_is_hashed_delivered_only_to_the_target_device_and_retried_on_failure()
    {
        var admin = await fx.AdminAsync();
        var org = await fx.SeedOrgAsync("Pkg " + U);
        await using var target = await TestAgent.EnrollAsync(fx, org.Token, "pkg-target");
        await using var other = await TestAgent.EnrollAsync(fx, org.Token, "pkg-other");
        var bytes = RandomNumberGenerator.GetBytes(300_000);
        var expectedSha = Convert.ToHexStringLower(SHA256.HashData(bytes));

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.SendAsync(HttpMethod.Put, "/api/v1/packages/upload?fileName=evil.sh", new ByteArrayContent(bytes))).StatusCode);
        try
        {
            // Over the limit: the server answers 413 and may drop the connection before the body is fully sent.
            Assert.Equal((HttpStatusCode)413, (await admin.SendAsync(HttpMethod.Put, "/api/v1/packages/upload?fileName=big.deb", new ByteArrayContent(new byte[6 * 1024 * 1024]))).StatusCode);
        }
        catch (HttpRequestException)
        {
        }
        Assert.Equal(0, await fx.DbAsync(db => db.Blobs.CountAsync(b => b.SizeBytes > 5 * 1024 * 1024)));
        var upload = await (await admin.SendAsync(HttpMethod.Put, "/api/v1/packages/upload?fileName=..%2F..%2Ftool_1.0.deb", new ByteArrayContent(bytes))).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(expectedSha, upload.GetProperty("sha256").GetString());
        var blobId = upload.GetProperty("blobId").GetGuid();
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync("/api/v1/packages", new { name = "Tool", type = "msi", blobId })).StatusCode); // extension mismatch
        var pkg = await admin.PostJsonAsync("/api/v1/packages", new { name = "Tool", version = "1.0", type = "deb", blobId, installArgs = Array.Empty<string>(), uninstallCommand = new[] { "apt-get", "remove", "-y", "tool" }, detection = new { type = "dpkg", key = "tool" } });
        var listed = (await admin.GetJsonAsync("/api/v1/packages")).EnumerateArray().Single(p => p.GetProperty("id").GetGuid() == pkg.GetProperty("id").GetGuid());
        Assert.Equal("tool_1.0.deb", listed.GetProperty("fileName").GetString());

        var deploy = await admin.PostJsonAsync($"/api/v1/packages/{pkg.GetProperty("id").GetGuid()}/deploy", new { action = "install", target = new { deviceIds = new[] { target.DeviceId } }, maxAttempts = 2 });
        var dispatch = await target.NextJobAsync("package.install");
        var spec = dispatch.Payload.GetProperty("spec");
        Assert.Equal(expectedSha, spec.GetProperty("sha256").GetString());
        Assert.Equal(bytes.Length, spec.GetProperty("sizeBytes").GetInt64());
        Assert.Equal("deb", spec.GetProperty("type").GetString());
        Assert.Equal("dpkg", spec.GetProperty("detection").GetProperty("type").GetString());
        Assert.False(spec.TryGetProperty("os", out _));

        // The target downloads over mTLS and gets exactly the uploaded bytes...
        using var targetHttp = target.NewHttp();
        var downloaded = await targetHttp.GetByteArrayAsync($"/agent/v1/blobs/{blobId}");
        Assert.Equal(expectedSha, Convert.ToHexStringLower(SHA256.HashData(downloaded)));
        // ...a device that was not sent the job cannot, nor can a caller without a certificate.
        using var otherHttp = other.NewHttp();
        Assert.Equal(HttpStatusCode.NotFound, (await otherHttp.GetAsync($"/agent/v1/blobs/{blobId}")).StatusCode);
        using var anonymous = other.NewHttp(withClientCert: false);
        Assert.Equal(HttpStatusCode.Forbidden, (await anonymous.GetAsync($"/agent/v1/blobs/{blobId}")).StatusCode);
        // ...and it is not reachable from the dashboard listener at all.
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/agent/v1/blobs/{blobId}")).StatusCode);

        // First attempt fails → a second attempt is queued; second succeeds → software inventory is refreshed.
        await target.CompleteAsync(dispatch, "failed", 1, ["dpkg: error\n"]);
        var jobId = deploy.GetProperty("jobId").GetGuid();
        await UntilAsync(() => admin.GetJsonAsync($"/api/v1/jobs/{jobId}"), j => j.GetProperty("runs").GetArrayLength() == 2);
        fx.Clock.Advance(TimeSpan.FromSeconds(61));
        fx.Service<Dranzo.Api.Jobs.JobDispatcher>().Kick(target.DeviceId);
        var retry = await target.NextJobAsync("package.install");
        Assert.NotEqual(dispatch.RunId(), retry.RunId());
        await target.CompleteAsync(retry, "succeeded", 0, [], new { installed = true, version = "1.0" });
        await target.NextJobAsync("software.scan");
        var audit = (await admin.GetJsonAsync("/api/v1/audit?action=package.&pageSize=50")).GetProperty("items").EnumerateArray().ToList();
        Assert.Contains(audit, e => e.GetProperty("action").GetString() == "package.install" && e.GetProperty("contentSha256").GetString() == expectedSha);
    }

    [Fact]
    public async Task Packages_respect_tenant_scope()
    {
        var admin = await fx.AdminAsync();
        var a = await fx.SeedOrgAsync("PkA " + U);
        var b = await fx.SeedOrgAsync("PkB " + U);
        await using var devA = await TestAgent.EnrollAsync(fx, a.Token, "pka", connect: false);
        await using var devB = await TestAgent.EnrollAsync(fx, b.Token, "pkb", connect: false);
        var tech = await fx.CreateUserAsync($"pk-{Guid.NewGuid():N}@t.test", BuiltInRoles.Technician, ScopeType.Organization, a.OrgId);
        async Task<Guid> Upload(ApiClient c) => (await (await c.SendAsync(HttpMethod.Put, "/api/v1/packages/upload?fileName=t.rpm", new ByteArrayContent([9, 9, 9]))).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("blobId").GetGuid();

        var pkgB = (await admin.PostJsonAsync("/api/v1/packages", new { name = "B only " + U, type = "rpm", blobId = await Upload(admin), organizationId = b.OrgId })).GetProperty("id").GetGuid();
        Assert.DoesNotContain(pkgB, (await tech.GetJsonAsync("/api/v1/packages")).EnumerateArray().Select(p => p.GetProperty("id").GetGuid()));
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync($"/api/v1/packages/{pkgB}/deploy", new { action = "install", target = new { deviceIds = new[] { devA.DeviceId } } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.DeleteAsync($"/api/v1/packages/{pkgB}")).StatusCode);
        // A technician scoped to A cannot create shared packages or packages for B, nor deploy to B's devices.
        var blob = await Upload(tech);
        Assert.Equal(HttpStatusCode.Forbidden, (await tech.PostAsync("/api/v1/packages", new { name = "shared", type = "rpm", blobId = blob })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/packages", new { name = "for b", type = "rpm", blobId = blob, organizationId = b.OrgId })).StatusCode);
        var pkgA = (await tech.PostJsonAsync("/api/v1/packages", new { name = "A pkg " + U, type = "rpm", blobId = blob, organizationId = a.OrgId })).GetProperty("id").GetGuid();
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync($"/api/v1/packages/{pkgA}/deploy", new { action = "install", target = new { deviceIds = new[] { devB.DeviceId } } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsync($"/api/v1/packages/{pkgA}/deploy", new { action = "install", target = new { deviceIds = new[] { devB.DeviceId } } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.PostAsync("/api/v1/software/deploy", new { action = "install", packages = new Dictionary<string, string> { ["apt"] = "x" }, target = new { deviceIds = new[] { devB.DeviceId } } })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await tech.GetAsync($"/api/v1/devices/{devB.DeviceId}/software")).StatusCode);
        Assert.Equal(0, await fx.DbAsync(db => db.JobRuns.CountAsync(r => r.DeviceId == devB.DeviceId)));
    }
}
