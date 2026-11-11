using System.Security.Claims;
using System.Text.Encodings.Web;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Auth;

// ---------- Endpoint metadata ----------

public sealed record PermissionMetadata(string Permission, bool PartnerWide);

public sealed record StepUpMetadata;

public sealed record AuthenticatedOnlyMetadata;

public sealed record AnonymousMetadata;

public sealed record AgentListenerMetadata;

public static class AccessExtensions
{
    /// <summary>Caller must hold <paramref name="permission"/>; queries are scoped to where they hold it.</summary>
    public static T RequirePermission<T>(this T builder, string permission, bool partnerWide = false) where T : IEndpointConventionBuilder =>
        builder.WithMetadata(new PermissionMetadata(permission, partnerWide));

    /// <summary>Caller must have re-entered a TOTP code within the step-up window.</summary>
    public static T RequireStepUp<T>(this T builder) where T : IEndpointConventionBuilder => builder.WithMetadata(new StepUpMetadata());

    /// <summary>Any signed-in principal; the endpoint must only touch the caller's own data.</summary>
    public static T AuthenticatedOnly<T>(this T builder) where T : IEndpointConventionBuilder => builder.WithMetadata(new AuthenticatedOnlyMetadata());

    public static T Anonymous<T>(this T builder) where T : IEndpointConventionBuilder => builder.WithMetadata(new AnonymousMetadata());

    /// <summary>Reachable only on the agent (mTLS) listener.</summary>
    public static T AgentListener<T>(this T builder) where T : IEndpointConventionBuilder => builder.WithMetadata(new AgentListenerMetadata());
}

/// <summary>The authenticated caller of the current dashboard/API request.</summary>
public sealed class CurrentPrincipal
{
    public bool IsAuthenticated { get; set; }
    public bool IsApiKey { get; set; }
    public Guid PartnerId { get; set; }
    public Guid UserId { get; set; }
    public Guid? ApiKeyId { get; set; }
    public Guid SessionId { get; set; }
    public string Name { get; set; } = "";
    public string? CsrfToken { get; set; }
    public DateTimeOffset? StepUpAt { get; set; }
    public string? Ip { get; set; }
    /// <summary>Signed in with a temporary password: only the account endpoints work until it is changed.</summary>
    public bool MustChangePassword { get; set; }
}

// ---------- Authentication handlers ----------

public static class AuthSchemes
{
    public const string Session = "Session";
    public const string ApiKey = "ApiKey";
    public const string Selector = "Dranzo";

    public static string CookieName(IHostEnvironment env) => env.IsDevelopment() ? "dz_session" : "__Host-dz_session";
}

public sealed class SessionAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder,
    DranzoDbContext db, IOptions<DranzoOptions> dranzo, CurrentPrincipal current, IHostEnvironment env, TimeProvider clock)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.TryGetValue(AuthSchemes.CookieName(env), out var token) || string.IsNullOrEmpty(token) || token.Length > 128)
        {
            return AuthenticateResult.NoResult();
        }
        var hash = Hashing.Sha256Hex(token);
        var now = clock.GetUtcNow();
        var session = await db.UserSessions.IgnoreQueryFilters().FirstOrDefaultAsync(s => s.TokenHash == hash);
        if (session is null || session.RevokedAt is not null || session.ExpiresAt <= now
            || session.LastSeenAt.AddMinutes(dranzo.Value.Auth.SessionIdleMinutes) <= now)
        {
            return AuthenticateResult.Fail("Session expired.");
        }
        var user = await db.Users.IgnoreQueryFilters().AsNoTracking().FirstOrDefaultAsync(u => u.Id == session.UserId);
        if (user is null || user.Disabled || !user.TotpEnabled)
        {
            return AuthenticateResult.Fail("User not allowed.");
        }
        if (now - session.LastSeenAt > TimeSpan.FromSeconds(30))
        {
            session.LastSeenAt = now;
            await db.SaveChangesAsync();
        }
        current.IsAuthenticated = true;
        current.PartnerId = user.PartnerId;
        current.UserId = user.Id;
        current.SessionId = session.Id;
        current.Name = user.Email;
        current.CsrfToken = session.CsrfToken;
        current.StepUpAt = session.StepUpAt;
        current.MustChangePassword = user.MustChangePassword;
        var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()), new Claim(ClaimTypes.Name, user.Email), new Claim("sid", session.Id.ToString())], AuthSchemes.Session);
        var properties = new AuthenticationProperties { ExpiresUtc = session.ExpiresAt };
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), properties, AuthSchemes.Session));
    }
}

/// <summary><c>Authorization: Bearer dz_api_{keyId}_{secret}</c>.</summary>
public sealed class ApiKeyAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder,
    DranzoDbContext db, CurrentPrincipal current, TimeProvider clock)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string Prefix = "dz_api_";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer " + Prefix, StringComparison.Ordinal) || header.Length > 256)
        {
            return AuthenticateResult.NoResult();
        }
        var parts = header["Bearer ".Length..][Prefix.Length..].Split('_', 2);
        if (parts.Length != 2 || !Guid.TryParseExact(parts[0], "N", out var keyId))
        {
            return AuthenticateResult.Fail("Malformed API key.");
        }
        var key = await db.ApiKeys.IgnoreQueryFilters().FirstOrDefaultAsync(k => k.Id == keyId);
        var now = clock.GetUtcNow();
        if (key is null || key.RevokedAt is not null || (key.ExpiresAt is { } exp && exp <= now)
            || !Hashing.FixedTimeEquals(key.SecretHash, Hashing.Sha256Hex(parts[1])))
        {
            return AuthenticateResult.Fail("Invalid API key.");
        }
        if (key.LastUsedAt is null || now - key.LastUsedAt > TimeSpan.FromMinutes(1))
        {
            key.LastUsedAt = now;
            await db.SaveChangesAsync();
        }
        current.IsAuthenticated = true;
        current.IsApiKey = true;
        current.PartnerId = key.PartnerId;
        current.ApiKeyId = key.Id;
        current.Name = "apikey:" + key.Name;
        var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, key.Id.ToString()), new Claim(ClaimTypes.Name, current.Name)], AuthSchemes.ApiKey);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), AuthSchemes.ApiKey));
    }
}

// ---------- Scope resolution ----------

/// <summary>Turns role assignments into the <see cref="TenantContext"/> scope for one permission.</summary>
public sealed class ScopeResolver(DranzoDbContext db)
{
    public async Task<List<RoleAssignment>> AssignmentsAsync(CurrentPrincipal who, CancellationToken ct)
    {
        var q = db.RoleAssignments.IgnoreQueryFilters().AsNoTracking().Include(a => a.Role).Where(a => a.PartnerId == who.PartnerId);
        q = who.IsApiKey ? q.Where(a => a.ApiKeyId == who.ApiKeyId) : q.Where(a => a.UserId == who.UserId);
        return await q.ToListAsync(ct);
    }

    /// <summary>Returns false (and leaves the context empty) if the caller does not hold the permission anywhere.</summary>
    public async Task<bool> ApplyAsync(TenantContext tenant, CurrentPrincipal who, string permission, bool partnerWide, CancellationToken ct)
    {
        tenant.Clear();
        var granted = (await AssignmentsAsync(who, ct)).Where(a => a.Role.Permissions.Contains(permission)).ToList();
        if (granted.Count == 0)
        {
            return false;
        }
        if (granted.Any(a => a.ScopeType == ScopeType.Partner))
        {
            tenant.SetScope(who.PartnerId, true, [], [], [], [], []);
            return true;
        }
        if (partnerWide)
        {
            return false;
        }
        var orgIds = granted.Where(a => a.ScopeType == ScopeType.Organization && a.ScopeId != null).Select(a => a.ScopeId!.Value).Distinct().ToArray();
        var siteIds = granted.Where(a => a.ScopeType == ScopeType.Site && a.ScopeId != null).Select(a => a.ScopeId!.Value).Distinct().ToArray();
        var groupIds = granted.Where(a => a.ScopeType == ScopeType.Group && a.ScopeId != null).Select(a => a.ScopeId!.Value).Distinct().ToArray();

        // Resolve parents inside the caller's partner only; ids pointing at another partner resolve to nothing.
        var groups = groupIds.Length == 0 ? [] : await db.DeviceGroups.IgnoreQueryFilters().AsNoTracking()
            .Where(g => g.PartnerId == who.PartnerId && groupIds.Contains(g.Id)).Select(g => new { g.Id, g.SiteId, g.OrganizationId }).ToListAsync(ct);
        var sites = siteIds.Length == 0 ? [] : await db.Sites.IgnoreQueryFilters().AsNoTracking()
            .Where(s => s.PartnerId == who.PartnerId && siteIds.Contains(s.Id)).Select(s => new { s.Id, s.OrganizationId }).ToListAsync(ct);
        var liveOrgs = await db.Organizations.IgnoreQueryFilters().AsNoTracking()
            .Where(o => o.PartnerId == who.PartnerId && o.DeletedAt == null).Select(o => o.Id).ToListAsync(ct);

        orgIds = [.. orgIds.Intersect(liveOrgs)];
        siteIds = [.. sites.Where(s => liveOrgs.Contains(s.OrganizationId)).Select(s => s.Id)];
        groupIds = [.. groups.Where(g => liveOrgs.Contains(g.OrganizationId)).Select(g => g.Id)];
        if (orgIds.Length + siteIds.Length + groupIds.Length == 0)
        {
            return false;
        }
        Guid[] visibleOrgs = [.. orgIds.Concat(sites.Select(s => s.OrganizationId)).Concat(groups.Select(g => g.OrganizationId)).Intersect(liveOrgs).Distinct()];
        Guid[] visibleSites = [.. siteIds.Concat(groups.Where(g => groupIds.Contains(g.Id)).Select(g => g.SiteId)).Distinct()];
        tenant.SetScope(who.PartnerId, false, orgIds, siteIds, groupIds, visibleOrgs, visibleSites);
        return true;
    }

    public async Task<string[]> AllPermissionsAsync(CurrentPrincipal who, CancellationToken ct) =>
        [.. (await AssignmentsAsync(who, ct)).SelectMany(a => a.Role.Permissions).Distinct().Order()];
}

// ---------- The access middleware ----------

/// <summary>
/// Runs after routing and authentication. Fail-closed gate for every endpoint:
/// listener separation, authentication, CSRF, permission → tenant scope, step-up.
/// </summary>
public sealed class AccessMiddleware(RequestDelegate next, ILogger<AccessMiddleware> log)
{
    private static readonly HashSet<string> SafeMethods = new(StringComparer.OrdinalIgnoreCase) { "GET", "HEAD", "OPTIONS" };

    public async Task InvokeAsync(HttpContext ctx, TenantContext tenant, CurrentPrincipal who, ScopeResolver scopes, IOptions<DranzoOptions> options, TimeProvider clock)
    {
        var endpoint = ctx.GetEndpoint();
        if (endpoint is null)
        {
            await next(ctx);
            return;
        }
        var onAgentListener = ctx.Features.Get<ITlsHandshakeFeature>() is not null;
        var agentEndpoint = endpoint.Metadata.GetMetadata<AgentListenerMetadata>() is not null;
        if (onAgentListener != agentEndpoint)
        {
            ctx.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }
        var ip = ctx.Connection.RemoteIpAddress?.ToString();
        who.Ip = ip;
        if (agentEndpoint)
        {
            await next(ctx); // the gateway authenticates by client certificate itself
            return;
        }
        if (endpoint.Metadata.GetMetadata<AnonymousMetadata>() is not null)
        {
            tenant.SetActor("anonymous", null, "anonymous", ip);
            await next(ctx);
            return;
        }
        if (!who.IsAuthenticated)
        {
            await Deny(ctx, 401, "unauthenticated", "Sign in required.");
            return;
        }
        tenant.SetActor(who.IsApiKey ? "apikey" : "user", who.IsApiKey ? who.ApiKeyId : who.UserId, who.Name, ip);

        if (!who.IsApiKey && !SafeMethods.Contains(ctx.Request.Method))
        {
            var header = ctx.Request.Headers["X-CSRF-Token"].ToString();
            if (who.CsrfToken is null || header.Length == 0 || !Hashing.FixedTimeEquals(header, who.CsrfToken))
            {
                await Deny(ctx, 403, "csrf", "Missing or invalid CSRF token.");
                return;
            }
        }
        if (endpoint.Metadata.GetMetadata<AuthenticatedOnlyMetadata>() is not null)
        {
            if (who.IsApiKey)
            {
                await Deny(ctx, 403, "forbidden", "Not available to API keys.");
                return;
            }
            await next(ctx);
            return;
        }
        if (who.MustChangePassword)
        {
            await Deny(ctx, 403, "password_change_required", "Change your temporary password before doing anything else.");
            return;
        }
        var perm = endpoint.Metadata.GetMetadata<PermissionMetadata>();
        if (perm is null)
        {
            log.LogError("Endpoint {Endpoint} has no access metadata; denying.", endpoint.DisplayName);
            await Deny(ctx, 403, "forbidden", "Endpoint is not accessible.");
            return;
        }
        var stepUp = endpoint.Metadata.GetMetadata<StepUpMetadata>() is not null;
        if (who.IsApiKey && (stepUp || Permissions.InteractiveOnly.Contains(perm.Permission)))
        {
            await Deny(ctx, 403, "forbidden", "This action is not available to API keys.");
            return;
        }
        if (!await scopes.ApplyAsync(tenant, who, perm.Permission, perm.PartnerWide, ctx.RequestAborted))
        {
            await Deny(ctx, 403, "forbidden", $"Missing permission {perm.Permission}.");
            return;
        }
        if (stepUp && !StepUp.IsFresh(who, options.Value, clock))
        {
            await Deny(ctx, 401, "step_up_required", "Re-enter your authenticator code to continue.");
            return;
        }
        await next(ctx);
    }

    private static Task Deny(HttpContext ctx, int status, string error, string message)
    {
        ctx.Response.StatusCode = status;
        return ctx.Response.WriteAsJsonAsync(new { error, message });
    }
}

public static class StepUp
{
    public static bool IsFresh(CurrentPrincipal who, DranzoOptions options, TimeProvider clock) =>
        !who.IsApiKey && who.StepUpAt is { } at && clock.GetUtcNow() - at <= TimeSpan.FromMinutes(options.Auth.StepUpMinutes);

    public static IResult Required() =>
        Results.Json(new { error = "step_up_required", message = "Re-enter your authenticator code to continue." }, statusCode: 401);
}
