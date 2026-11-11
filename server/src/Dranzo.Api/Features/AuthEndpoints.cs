using Dranzo.Api.Auth;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

public static class AuthEndpoints
{
    public sealed record LoginRequest(string? Email, string? Password);

    public sealed record ChallengeRequest(string? ChallengeToken, string? Code, string? RecoveryCode);

    public sealed record CodeRequest(string? Code);

    public sealed record PasswordRequest(string? CurrentPassword, string? NewPassword);

    public static void Map(RouteGroupBuilder api)
    {
        var g = api.MapGroup("/auth");

        g.MapPost("/login", async (LoginRequest req, AuthService auth, HttpContext http, CancellationToken ct) =>
        {
            if (string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrEmpty(req.Password) || req.Email.Length > 254 || req.Password.Length > 128)
            {
                return Api.Error(401, "invalid_credentials", "Invalid email or password.");
            }
            var result = await auth.LoginAsync(req.Email, req.Password, http.Connection.RemoteIpAddress?.ToString(), ct);
            return result.Status switch
            {
                LoginStatus.MfaRequired => Results.Ok(new { status = "mfa_required", challengeToken = result.ChallengeToken }),
                LoginStatus.MfaEnrollmentRequired => Results.Ok(new { status = "mfa_enrollment_required", challengeToken = result.ChallengeToken }),
                LoginStatus.Locked => Api.Error(423, "locked", "Account temporarily locked. Try again later."),
                _ => Api.Error(401, "invalid_credentials", "Invalid email or password."),
            };
        }).Anonymous().RequireRateLimiting("auth");

        g.MapPost("/mfa/enroll/start", async (ChallengeRequest req, AuthService auth, CancellationToken ct) =>
        {
            var r = await auth.StartTotpEnrollmentAsync(req.ChallengeToken ?? "", ct);
            return r is null ? Api.Error(401, "invalid_challenge", "Sign in again.") : Results.Ok(new { secret = r.Value.Secret, otpauthUri = r.Value.Uri });
        }).Anonymous().RequireRateLimiting("auth");

        g.MapPost("/mfa/enroll/verify", async (ChallengeRequest req, AuthService auth, HttpContext http, IHostEnvironment env, IOptions<DranzoOptions> opt, CancellationToken ct) =>
        {
            var s = await auth.CompleteTotpEnrollmentAsync(req.ChallengeToken ?? "", req.Code ?? "", http.Connection.RemoteIpAddress?.ToString(), http.Request.Headers.UserAgent.ToString(), ct);
            if (s is null)
            {
                return Api.Error(401, "invalid_code", "Invalid code.");
            }
            SetCookie(http, env, opt.Value, s.Token);
            return Results.Ok(new { status = "ok", csrfToken = s.CsrfToken, recoveryCodes = s.RecoveryCodes });
        }).Anonymous().RequireRateLimiting("auth");

        g.MapPost("/mfa/verify", async (ChallengeRequest req, AuthService auth, HttpContext http, IHostEnvironment env, IOptions<DranzoOptions> opt, CancellationToken ct) =>
        {
            var s = await auth.VerifyMfaAsync(req.ChallengeToken ?? "", req.Code, req.RecoveryCode, http.Connection.RemoteIpAddress?.ToString(), http.Request.Headers.UserAgent.ToString(), ct);
            if (s is null)
            {
                return Api.Error(401, "invalid_code", "Invalid code.");
            }
            SetCookie(http, env, opt.Value, s.Token);
            return Results.Ok(new { status = "ok", csrfToken = s.CsrfToken });
        }).Anonymous().RequireRateLimiting("auth");

        g.MapPost("/logout", async (AuthService auth, CurrentPrincipal who, HttpContext http, IHostEnvironment env, Ctx c, CancellationToken ct) =>
        {
            await auth.LogoutAsync(who.SessionId, ct);
            http.Response.Cookies.Delete(AuthSchemes.CookieName(env), new CookieOptions { Path = "/" });
            await c.Audit("auth.logout", ct: ct);
            return Results.NoContent();
        }).AuthenticatedOnly();

        g.MapGet("/me", async (CurrentPrincipal who, ScopeResolver scopes, DranzoDbContext db, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
        {
            var user = await db.Users.IgnoreQueryFilters().AsNoTracking().FirstAsync(u => u.Id == who.UserId, ct);
            var partner = await db.Partners.IgnoreQueryFilters().AsNoTracking().FirstAsync(p => p.Id == who.PartnerId, ct);
            var assignments = await scopes.AssignmentsAsync(who, ct);
            return Results.Ok(new
            {
                user = new { user.Id, user.Email, user.DisplayName, user.MustChangePassword },
                partner = new { partner.Id, partner.Name },
                permissions = assignments.SelectMany(a => a.Role.Permissions).Distinct().Order(),
                partnerWide = assignments.Any(a => a.ScopeType == ScopeType.Partner),
                roles = assignments.Select(a => new { a.Role.Name, scopeType = a.ScopeType.ToString(), a.ScopeId }),
                csrfToken = who.CsrfToken,
                stepUpFresh = StepUp.IsFresh(who, opt.Value, clock),
                sessionIdleMinutes = opt.Value.Auth.SessionIdleMinutes,
                stepUpMinutes = opt.Value.Auth.StepUpMinutes,
                passwordMinLength = opt.Value.Auth.PasswordMinLength,
                bulkStepUpThreshold = opt.Value.Auth.BulkStepUpThreshold,
            });
        }).AuthenticatedOnly();

        g.MapPost("/step-up", async (CodeRequest req, AuthService auth, CurrentPrincipal who, CancellationToken ct) =>
            await auth.StepUpAsync(who.SessionId, req.Code ?? "", ct) ? Results.Ok(new { status = "ok" }) : Api.Error(401, "invalid_code", "Invalid code."))
            .AuthenticatedOnly().RequireRateLimiting("auth");

        g.MapPost("/password", async (PasswordRequest req, AuthService auth, CurrentPrincipal who, CancellationToken ct) =>
        {
            var problem = await auth.ChangePasswordAsync(who.UserId, who.SessionId, req.CurrentPassword ?? "", req.NewPassword ?? "", ct);
            return problem is null ? Results.NoContent() : Api.BadRequest(problem);
        }).AuthenticatedOnly().RequireRateLimiting("auth");

        // New recovery codes replace the old set. Needs a fresh authenticator code.
        g.MapPost("/recovery-codes", async (AuthService auth, CurrentPrincipal who, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
            StepUp.IsFresh(who, opt.Value, clock) ? Results.Ok(new { recoveryCodes = await auth.RegenerateRecoveryCodesAsync(who.UserId, ct) }) : StepUp.Required())
            .AuthenticatedOnly().RequireRateLimiting("auth");

        g.MapGet("/time-zones", () => Results.Ok(TimeZoneInfo.GetSystemTimeZones().Select(z => z.Id).Order())).AuthenticatedOnly();

        g.MapGet("/permissions", () => Results.Ok(new { permissions = Permissions.All, builtInRoles = BuiltInRoles.Definitions })).AuthenticatedOnly();
    }

    private static void SetCookie(HttpContext http, IHostEnvironment env, DranzoOptions opt, string token) =>
        http.Response.Cookies.Append(AuthSchemes.CookieName(env), token, new CookieOptions
        {
            HttpOnly = true,
            Secure = !env.IsDevelopment() || http.Request.IsHttps,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            IsEssential = true,
            MaxAge = TimeSpan.FromHours(opt.Auth.SessionAbsoluteHours),
        });
}
