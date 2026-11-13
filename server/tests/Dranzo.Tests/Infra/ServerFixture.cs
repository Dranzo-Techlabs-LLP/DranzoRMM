using Dranzo.Api.Features;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dranzo.Api;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using OtpNet;

namespace Dranzo.Tests.Infra;

/// <summary>Controllable clock so tests can step TOTP windows and timeouts without sleeping.</summary>
public sealed class TestClock : TimeProvider
{
    private TimeSpan _offset = TimeSpan.Zero;

    public override DateTimeOffset GetUtcNow() => DateTimeOffset.UtcNow + _offset;

    /// <summary>Time only moves forward: rewinding would make TOTP steps and timestamps go backwards.</summary>
    public void Advance(TimeSpan by)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(by, TimeSpan.Zero);
        _offset += by;
    }
}

/// <summary>
/// Starts the real server (real Kestrel, both listeners on random ports, real TLS on the agent listener)
/// against a throwaway PostgreSQL database. Set DRANZO_TEST_PG to point at the PostgreSQL server
/// (default: Host=localhost, current OS user).
/// </summary>
public class ServerFixture : IAsyncLifetime
{
    public const string AdminEmail = "admin@partner-one.test";
    public const string AdminPassword = "Correct-Horse-Battery-9";
    public static readonly string MeshTestKey = string.Concat(Enumerable.Range(0, 80).Select(i => (i * 7 % 256).ToString("x2")));

    private readonly string _dbName = "dranzo_test_" + Guid.NewGuid().ToString("N");
    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "dranzo-test-" + Guid.NewGuid().ToString("N"));
    private string _adminConn = "";

    public WebApplication App { get; private set; } = null!;
    public TestClock Clock { get; } = new();
    public FakeUniFi UniFi { get; } = new();
    public string DashboardUrl { get; private set; } = "";
    public string AgentUrl { get; private set; } = "";
    public string TempDir => _tempDir;

    protected virtual Dictionary<string, string?> ExtraConfig => [];

    public virtual async Task InitializeAsync()
    {
        var baseConn = Environment.GetEnvironmentVariable("DRANZO_TEST_PG") ?? "Host=localhost";
        _adminConn = new NpgsqlConnectionStringBuilder(baseConn) { Database = "postgres", Pooling = false }.ConnectionString;
        await using (var conn = new NpgsqlConnection(_adminConn))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand($"CREATE DATABASE \"{_dbName}\"", conn);
            await cmd.ExecuteNonQueryAsync();
        }
        Directory.CreateDirectory(_tempDir);
        var config = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Default"] = new NpgsqlConnectionStringBuilder(baseConn) { Database = _dbName, MaxPoolSize = 20 }.ConnectionString,
            ["Dranzo:DashboardPort"] = "0",
            ["Dranzo:AgentPort"] = "0",
            ["Dranzo:KeyStore:Directory"] = Path.Combine(_tempDir, "keys"),
            ["Dranzo:Storage:Directory"] = Path.Combine(_tempDir, "storage"),
            ["Dranzo:Bootstrap:PartnerName"] = "Partner One",
            ["Dranzo:Bootstrap:AdminEmail"] = AdminEmail,
            ["Dranzo:Bootstrap:AdminPassword"] = AdminPassword,
            ["Dranzo:RateLimits:AuthPerMinute"] = "100000",
            ["Dranzo:RateLimits:EnrollPerMinute"] = "100000",
            ["Dranzo:RateLimits:ApiPerMinute"] = "1000000",
            ["Dranzo:RunBackgroundServices"] = "false",
            ["Dranzo:Mesh:Url"] = "https://mesh.example.test",
            ["Dranzo:Mesh:LoginTokenKey"] = MeshTestKey, // fixed test value, not a real MeshCentral key
            ["Dranzo:Notifications:AllowPrivateTargets"] = "true", // webhook receivers in tests listen on 127.0.0.1
            ["Dranzo:Storage:MaxPackageBytes"] = (5 * 1024 * 1024).ToString(),
            ["Logging:LogLevel:Default"] = "Warning",
            ["Logging:LogLevel:Microsoft.AspNetCore.Server.Kestrel"] = "Error",
        };
        foreach (var kv in ExtraConfig)
        {
            config[kv.Key] = kv.Value;
        }
        App = DranzoApp.Build([], b =>
        {
            b.Configuration.Sources.Clear();
            b.Configuration.AddInMemoryCollection(config);
            b.Services.AddSingleton<TimeProvider>(Clock);
            b.Services.AddSingleton<IUniFiTransport>(UniFi);
            b.Logging.SetMinimumLevel(LogLevel.Warning);
        }, Environments.Development);
        await DranzoApp.InitializeAsync(App);
        await App.StartAsync();
        var addresses = App.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses;
        DashboardUrl = "http://localhost:" + new Uri(addresses.Single(a => a.StartsWith("http://", StringComparison.Ordinal))).Port;
        AgentUrl = "https://localhost:" + new Uri(addresses.Single(a => a.StartsWith("https://", StringComparison.Ordinal))).Port;
    }

    public virtual async Task DisposeAsync()
    {
        await App.StopAsync();
        await App.DisposeAsync();
        NpgsqlConnection.ClearAllPools();
        await using (var conn = new NpgsqlConnection(_adminConn))
        {
            await conn.OpenAsync();
            await using var cmd = new NpgsqlCommand($"DROP DATABASE IF EXISTS \"{_dbName}\" WITH (FORCE)", conn);
            await cmd.ExecuteNonQueryAsync();
        }
        try
        {
            Directory.Delete(_tempDir, true);
        }
        catch (IOException)
        {
        }
    }

    /// <summary>Runs <paramref name="work"/> with a system-scoped DbContext (bypasses tenant filters; test setup/asserts only).</summary>
    public async Task<T> DbAsync<T>(Func<DranzoDbContext, Task<T>> work)
    {
        await using var scope = App.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
        return await work(scope.ServiceProvider.GetRequiredService<DranzoDbContext>());
    }

    public Task DbAsync(Func<DranzoDbContext, Task> work) => DbAsync(async db =>
    {
        await work(db);
        return 0;
    });

    public T Service<T>() where T : notnull => App.Services.GetRequiredService<T>();

    public ApiClient NewClient() => new(this);

    private ApiClient? _admin;

    /// <summary>The bootstrap Partner Admin, signed in (MFA enrolled on first use).</summary>
    public async Task<ApiClient> AdminAsync()
    {
        if (_admin is null)
        {
            var c = NewClient();
            await c.LoginAsync(AdminEmail, AdminPassword);
            _admin = c;
        }
        else if (!(await _admin.GetAsync("/api/v1/auth/me")).IsSuccessStatusCode)
        {
            // Another test moved the clock past the idle timeout; sign in again with the same authenticator.
            await _admin.LoginAsync(AdminEmail, AdminPassword);
        }
        return _admin;
    }

    /// <summary>Creates a user with one role assignment and returns a signed-in client for them.</summary>
    public async Task<ApiClient> CreateUserAsync(string email, string roleName, ScopeType scopeType, Guid? scopeId)
    {
        var admin = await AdminAsync();
        const string password = "Another-Strong-Pass-77";
        const string temporary = "Temp-Strong-Pass-5501";
        var created = await admin.PostAsync("/api/v1/users", new { email, displayName = email.Split('@')[0], password = temporary });
        Assert.True(created.StatusCode == HttpStatusCode.Created, $"create user → {(int)created.StatusCode} {await created.Content.ReadAsStringAsync()}");
        var userId = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
        var roles = await admin.GetJsonAsync("/api/v1/roles");
        var roleId = roles.EnumerateArray().First(r => r.GetProperty("name").GetString() == roleName).GetProperty("id").GetGuid();
        await admin.StepUpAsync();
        var assigned = await admin.PostAsync("/api/v1/role-assignments", new { userId, roleId, scopeType = scopeType.ToString(), scopeId });
        Assert.Equal(HttpStatusCode.Created, assigned.StatusCode);
        // New users start with a temporary password and can do nothing until they change it.
        var client = NewClient();
        await client.LoginAsync(email, temporary);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/api/v1/auth/password", new { currentPassword = temporary, newPassword = password })).StatusCode);
        client.UserId = userId;
        return client;
    }

    public async Task<Guid> CreateRoleAsync(string name, params string[] permissions)
    {
        var admin = await AdminAsync();
        await admin.StepUpAsync();
        var r = await admin.PostAsync("/api/v1/roles", new { name, permissions });
        Assert.Equal(HttpStatusCode.Created, r.StatusCode);
        return (await r.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetGuid();
    }

    public sealed record OrgSeed(Guid OrgId, Guid SiteId, Guid GroupId, string Token);

    /// <summary>Creates organization → site → group and an enrollment token through the API as the admin.</summary>
    public async Task<OrgSeed> SeedOrgAsync(string name)
    {
        var admin = await AdminAsync();
        var org = await admin.PostJsonAsync("/api/v1/organizations", new { name, consentMode = "none" });
        var orgId = org.GetProperty("id").GetGuid();
        var site = await admin.PostJsonAsync("/api/v1/sites", new { organizationId = orgId, name = name + " HQ" });
        var siteId = site.GetProperty("id").GetGuid();
        var group = await admin.PostJsonAsync("/api/v1/groups", new { siteId, name = name + " Laptops" });
        var groupId = group.GetProperty("id").GetGuid();
        var token = await admin.PostJsonAsync("/api/v1/enrollment-tokens", new { siteId, groupId, name = name + " token", maxUses = 100 });
        return new OrgSeed(orgId, siteId, groupId, token.GetProperty("token").GetString()!);
    }
}

/// <summary>Dashboard HTTP client with cookie jar, CSRF header and TOTP helper.</summary>
public sealed class ApiClient
{
    private readonly ServerFixture _fx;
    private readonly HttpClientHandler _handler = new() { CookieContainer = new CookieContainer(), UseCookies = true };
    private byte[]? _totpSecret;

    public ApiClient(ServerFixture fx)
    {
        _fx = fx;
        Http = new HttpClient(_handler) { BaseAddress = new Uri(fx.DashboardUrl) };
    }

    public HttpClient Http { get; }
    public string? Csrf { get; private set; }
    public Guid UserId { get; set; }
    public string[]? RecoveryCodes { get; private set; }
    public CookieContainer Cookies => _handler.CookieContainer;

    /// <summary>A fresh TOTP code. Advances the test clock one step so codes are never reused.</summary>
    public string NextCode()
    {
        _fx.Clock.Advance(TimeSpan.FromSeconds(31));
        return new Totp(_totpSecret!).ComputeTotp(_fx.Clock.GetUtcNow().UtcDateTime);
    }

    public async Task LoginAsync(string email, string password)
    {
        var login = await Http.PostAsJsonAsync("/api/v1/auth/login", new { email, password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        var challenge = body.GetProperty("challengeToken").GetString();
        JsonElement done;
        if (body.GetProperty("status").GetString() == "mfa_enrollment_required")
        {
            var start = await Http.PostAsJsonAsync("/api/v1/auth/mfa/enroll/start", new { challengeToken = challenge });
            Assert.Equal(HttpStatusCode.OK, start.StatusCode);
            _totpSecret = Base32Encoding.ToBytes((await start.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("secret").GetString());
            var verify = await Http.PostAsJsonAsync("/api/v1/auth/mfa/enroll/verify", new { challengeToken = challenge, code = NextCode() });
            Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
            done = await verify.Content.ReadFromJsonAsync<JsonElement>();
            RecoveryCodes = [.. done.GetProperty("recoveryCodes").EnumerateArray().Select(x => x.GetString()!)];
        }
        else
        {
            Assert.NotNull(_totpSecret);
            var verify = await Http.PostAsJsonAsync("/api/v1/auth/mfa/verify", new { challengeToken = challenge, code = NextCode() });
            Assert.Equal(HttpStatusCode.OK, verify.StatusCode);
            done = await verify.Content.ReadFromJsonAsync<JsonElement>();
        }
        Csrf = done.GetProperty("csrfToken").GetString();
    }

    public async Task StepUpAsync()
    {
        var r = await PostAsync("/api/v1/auth/step-up", new { code = NextCode() });
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    public Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body = null, bool withCsrf = true)
    {
        var req = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            req.Content = body as HttpContent ?? JsonContent.Create(body);
        }
        if (withCsrf && Csrf is not null)
        {
            req.Headers.Add("X-CSRF-Token", Csrf);
        }
        return Http.SendAsync(req);
    }

    public Task<HttpResponseMessage> GetAsync(string path) => SendAsync(HttpMethod.Get, path);

    public Task<HttpResponseMessage> PostAsync(string path, object? body = null) => SendAsync(HttpMethod.Post, path, body ?? new { });

    public Task<HttpResponseMessage> PatchAsync(string path, object body) => SendAsync(HttpMethod.Patch, path, body);

    public Task<HttpResponseMessage> PutAsync(string path, object body) => SendAsync(HttpMethod.Put, path, body);

    public Task<HttpResponseMessage> DeleteAsync(string path) => SendAsync(HttpMethod.Delete, path);

    public async Task<JsonElement> GetJsonAsync(string path)
    {
        var r = await GetAsync(path);
        Assert.True(r.IsSuccessStatusCode, $"GET {path} → {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
        return await r.Content.ReadFromJsonAsync<JsonElement>();
    }

    public async Task<JsonElement> PostJsonAsync(string path, object body)
    {
        var r = await PostAsync(path, body);
        Assert.True(r.IsSuccessStatusCode, $"POST {path} → {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
        var text = await r.Content.ReadAsStringAsync();
        return text.Length == 0 ? default : JsonSerializer.Deserialize<JsonElement>(text);
    }
}
