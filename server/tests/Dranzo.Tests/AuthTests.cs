using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Dranzo.Domain;
using Dranzo.Tests.Infra;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Tests;

[Collection("server")]
public class AuthTests(ServerFixture fx)
{
    [Fact]
    public async Task Login_requires_mfa_enrollment_then_issues_hardened_session()
    {
        var c = await fx.CreateUserAsync($"auth1-{Guid.NewGuid():N}@t.test", BuiltInRoles.ReadOnly, ScopeType.Partner, null);
        var me = await c.GetJsonAsync("/api/v1/auth/me");
        Assert.Contains("devices.read", me.GetProperty("permissions").EnumerateArray().Select(p => p.GetString()));
        Assert.Equal(10, c.RecoveryCodes!.Length);
        var cookie = c.Cookies.GetAllCookies().Single(k => k.Name == "dz_session");
        Assert.True(cookie.HttpOnly);
        // The session token is stored hashed, never in clear.
        var stored = await fx.DbAsync(db => db.UserSessions.IgnoreQueryFilters().Select(s => s.TokenHash).ToListAsync());
        Assert.DoesNotContain(cookie.Value, stored);
    }

    [Fact]
    public async Task No_session_without_second_factor()
    {
        var email = $"auth2-{Guid.NewGuid():N}@t.test";
        await fx.CreateUserAsync(email, BuiltInRoles.ReadOnly, ScopeType.Partner, null);
        var c = fx.NewClient();
        var login = await c.Http.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Another-Strong-Pass-77" });
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("mfa_required", body.GetProperty("status").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/api/v1/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/api/v1/devices")).StatusCode);
        var challenge = body.GetProperty("challengeToken").GetString();
        var bad = await c.Http.PostAsJsonAsync("/api/v1/auth/mfa/verify", new { challengeToken = challenge, code = "000000" });
        Assert.Equal(HttpStatusCode.Unauthorized, bad.StatusCode);
    }

    [Fact]
    public async Task Totp_code_cannot_be_replayed()
    {
        var email = $"auth3-{Guid.NewGuid():N}@t.test";
        var c = await fx.CreateUserAsync(email, BuiltInRoles.ReadOnly, ScopeType.Partner, null);
        var code = c.NextCode();
        Assert.Equal(HttpStatusCode.OK, (await c.PostAsync("/api/v1/auth/step-up", new { code })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.PostAsync("/api/v1/auth/step-up", new { code })).StatusCode);
    }

    [Fact]
    public async Task Recovery_code_works_once()
    {
        var email = $"auth4-{Guid.NewGuid():N}@t.test";
        var c = await fx.CreateUserAsync(email, BuiltInRoles.ReadOnly, ScopeType.Partner, null);
        var recovery = c.RecoveryCodes![0];
        for (var i = 0; i < 2; i++)
        {
            var c2 = fx.NewClient();
            var login = await c2.Http.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Another-Strong-Pass-77" });
            var challenge = (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("challengeToken").GetString();
            var r = await c2.Http.PostAsJsonAsync("/api/v1/auth/mfa/verify", new { challengeToken = challenge, recoveryCode = recovery });
            Assert.Equal(i == 0 ? HttpStatusCode.OK : HttpStatusCode.Unauthorized, r.StatusCode);
        }
    }

    [Fact]
    public async Task Wrong_passwords_lock_the_account()
    {
        var email = $"auth5-{Guid.NewGuid():N}@t.test";
        await fx.CreateUserAsync(email, BuiltInRoles.ReadOnly, ScopeType.Partner, null);
        var c = fx.NewClient();
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await c.Http.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "wrong-password-xx" })).StatusCode);
        }
        Assert.Equal((HttpStatusCode)423, (await c.Http.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Another-Strong-Pass-77" })).StatusCode);
        fx.Clock.Advance(TimeSpan.FromMinutes(16));
        Assert.Equal(HttpStatusCode.OK, (await c.Http.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Another-Strong-Pass-77" })).StatusCode);
    }

    [Fact]
    public async Task Unknown_user_and_wrong_password_look_the_same()
    {
        var c = fx.NewClient();
        var a = await c.Http.PostAsJsonAsync("/api/v1/auth/login", new { email = "nobody@t.test", password = "whatever-password" });
        var b = await c.Http.PostAsJsonAsync("/api/v1/auth/login", new { email = ServerFixture.AdminEmail, password = "whatever-password" });
        Assert.Equal(HttpStatusCode.Unauthorized, a.StatusCode);
        Assert.Equal(await a.Content.ReadAsStringAsync(), await b.Content.ReadAsStringAsync());
        // undo the failed attempt against the admin
        await fx.DbAsync(db => db.Users.IgnoreQueryFilters().ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLogins, 0)));
    }

    [Fact]
    public async Task Unsafe_requests_need_the_csrf_token()
    {
        var admin = await fx.AdminAsync();
        var without = await admin.SendAsync(HttpMethod.Post, "/api/v1/organizations", new { name = "csrf test" }, withCsrf: false);
        Assert.Equal(HttpStatusCode.Forbidden, without.StatusCode);
        Assert.Contains("csrf", await without.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Logout_and_idle_timeout_end_the_session()
    {
        var c = await fx.CreateUserAsync($"auth6-{Guid.NewGuid():N}@t.test", BuiltInRoles.ReadOnly, ScopeType.Partner, null);
        fx.Clock.Advance(TimeSpan.FromMinutes(31));
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/api/v1/auth/me")).StatusCode);

        var d = await fx.CreateUserAsync($"auth7-{Guid.NewGuid():N}@t.test", BuiltInRoles.ReadOnly, ScopeType.Partner, null);
        Assert.Equal(HttpStatusCode.NoContent, (await d.PostAsync("/api/v1/auth/logout")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await d.GetAsync("/api/v1/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Sensitive_actions_need_fresh_step_up()
    {
        var admin = await fx.AdminAsync();
        fx.Clock.Advance(TimeSpan.FromMinutes(6)); // any earlier step-up is now stale
        var org = await admin.PostJsonAsync("/api/v1/organizations", new { name = "StepUp " + Guid.NewGuid().ToString("N")[..6] });
        var id = org.GetProperty("id").GetGuid();
        var denied = await admin.DeleteAsync($"/api/v1/organizations/{id}");
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        Assert.Contains("step_up_required", await denied.Content.ReadAsStringAsync());
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync($"/api/v1/organizations/{id}")).StatusCode);
    }

    [Theory]
    [InlineData("short1A!")]
    [InlineData("aaaaaaaaaaaaaaaa")]
    [InlineData("password1234")]
    public async Task Weak_passwords_are_rejected(string password)
    {
        var admin = await fx.AdminAsync();
        var r = await admin.PostAsync("/api/v1/users", new { email = $"weak-{Guid.NewGuid():N}@t.test", displayName = "Weak", password });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }

    [Fact]
    public async Task Resetting_mfa_forces_re_enrollment_and_never_disables_it()
    {
        var email = $"auth8-{Guid.NewGuid():N}@t.test";
        var c = await fx.CreateUserAsync(email, BuiltInRoles.ReadOnly, ScopeType.Partner, null);
        var admin = await fx.AdminAsync();
        await admin.StepUpAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await admin.PostAsync($"/api/v1/users/{c.UserId}/reset-mfa")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await c.GetAsync("/api/v1/auth/me")).StatusCode);
        var login = await fx.NewClient().Http.PostAsJsonAsync("/api/v1/auth/login", new { email, password = "Another-Strong-Pass-77" });
        Assert.Equal("mfa_enrollment_required", (await login.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("status").GetString());
    }
}
