using Dranzo.Api.Auth;
using Dranzo.Domain;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

/// <summary>
/// Who can do what: every user and API key with their roles, scopes, effective permissions and review findings
/// (no MFA, inactive, never-expiring keys). Partner-wide <c>users.read</c> only.
/// </summary>
public static class AccessReviewEndpoints
{
    public static readonly TimeSpan InactiveAfter = TimeSpan.FromDays(90);

    public sealed record Grant(string Role, string Scope, string ScopeName);

    public sealed record Principal(
        string Kind, Guid Id, string Name, string? Email, bool Disabled, bool Locked, bool? MfaEnabled,
        DateTimeOffset? LastActiveAt, DateTimeOffset? ExpiresAt, Grant[] Grants, string[] Permissions, string[] Findings);

    /// <summary>Review findings for one principal. Pure, so the rules are unit-tested.</summary>
    public static string[] Findings(string kind, bool disabled, bool? mfa, DateTimeOffset? lastActive, DateTimeOffset createdAt,
        DateTimeOffset? expiresAt, bool partnerWideAdmin, DateTimeOffset now)
    {
        if (disabled)
        {
            return [];
        }
        var f = new List<string>();
        if (kind == "user" && mfa == false)
        {
            f.Add("MFA not set up");
        }
        if (now - (lastActive ?? createdAt) > InactiveAfter)
        {
            f.Add(lastActive is null ? "Never used (90+ days)" : "Inactive 90+ days");
        }
        if (kind == "apikey" && expiresAt is null)
        {
            f.Add("API key never expires");
        }
        if (partnerWideAdmin)
        {
            f.Add("Full admin rights over every organization");
        }
        return [.. f];
    }

    public static async Task<List<Principal>> BuildAsync(Ctx c, CancellationToken ct)
    {
        var users = await c.Db.Users.AsNoTracking().OrderBy(u => u.Email).ToListAsync(ct);
        var keys = await c.Db.ApiKeys.AsNoTracking().Where(k => k.RevokedAt == null).OrderBy(k => k.Name).ToListAsync(ct);
        var assignments = await c.Db.RoleAssignments.AsNoTracking().Include(a => a.Role).ToListAsync(ct);
        var orgs = await c.Db.Organizations.AsNoTracking().ToDictionaryAsync(o => o.Id, o => o.Name, ct);
        var sites = await c.Db.Sites.AsNoTracking().ToDictionaryAsync(s => s.Id, s => s.Name, ct);
        var groups = await c.Db.DeviceGroups.AsNoTracking().ToDictionaryAsync(g => g.Id, g => g.Name, ct);
        var allPermissions = Permissions.All.Count;

        string ScopeName(RoleAssignment a) => a.ScopeType switch
        {
            ScopeType.Partner => "All organizations",
            ScopeType.Organization => orgs.GetValueOrDefault(a.ScopeId ?? Guid.Empty) ?? "(deleted organization)",
            ScopeType.Site => sites.GetValueOrDefault(a.ScopeId ?? Guid.Empty) ?? "(deleted site)",
            ScopeType.Group => groups.GetValueOrDefault(a.ScopeId ?? Guid.Empty) ?? "(deleted group)",
            _ => "",
        };

        (Grant[] Grants, string[] Permissions, bool FullAdmin) Rights(IEnumerable<RoleAssignment> mine)
        {
            var list = mine.ToList();
            var grants = list.Select(a => new Grant(a.Role.Name, a.ScopeType.ToString(), ScopeName(a))).OrderBy(g => g.Role).ToArray();
            var perms = list.SelectMany(a => a.Role.Permissions).Distinct().Order(StringComparer.Ordinal).ToArray();
            var fullAdmin = list.Any(a => a.ScopeType == ScopeType.Partner && a.Role.Permissions.Distinct().Count() >= allPermissions);
            return (grants, perms, fullAdmin);
        }

        var result = new List<Principal>();
        foreach (var u in users)
        {
            var (grants, perms, fullAdmin) = Rights(assignments.Where(a => a.UserId == u.Id));
            result.Add(new Principal("user", u.Id, u.DisplayName, u.Email, u.Disabled, u.LockoutEnd > c.Now, u.TotpEnabled, u.LastLoginAt, null,
                grants, perms, Findings("user", u.Disabled, u.TotpEnabled, u.LastLoginAt, u.CreatedAt, null, fullAdmin, c.Now)));
        }
        foreach (var k in keys)
        {
            var (grants, perms, fullAdmin) = Rights(assignments.Where(a => a.ApiKeyId == k.Id));
            var expired = k.ExpiresAt <= c.Now;
            result.Add(new Principal("apikey", k.Id, k.Name, null, expired, false, null, k.LastUsedAt, k.ExpiresAt,
                grants, perms, Findings("apikey", expired, null, k.LastUsedAt, k.CreatedAt, k.ExpiresAt, fullAdmin, c.Now)));
        }
        return result;
    }

    public static ReportData Report(List<Principal> rows) => new("Access review",
        ["Type", "Name", "Email", "Status", "MFA", "Last active", "Expires", "Roles (scope)", "Permissions", "Findings"],
        [.. rows.Select(p => new object?[]
        {
            p.Kind == "user" ? "User" : "API key", p.Name, p.Email,
            p.Disabled ? "disabled" : p.Locked ? "locked" : "active",
            p.MfaEnabled is null ? "" : p.MfaEnabled.Value ? "yes" : "NO",
            p.LastActiveAt, p.ExpiresAt,
            string.Join("; ", p.Grants.Select(g => $"{g.Role} ({g.ScopeName})")),
            p.Permissions.Length, string.Join("; ", p.Findings),
        })]);

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/access-review", async (Ctx c, CancellationToken ct) =>
        {
            var rows = await BuildAsync(c, ct);
            await c.Audit("access_review.view", targetType: "report", targetId: "access-review", detail: new { rows = rows.Count }, ct: ct);
            return Results.Ok(new
            {
                generatedAt = c.Now,
                totalPermissions = Permissions.All.Count,
                principals = rows,
            });
        }).RequirePermission(Permissions.UsersRead, partnerWide: true);

        api.MapGet("/reports/access-review.{format}", async (string format, Ctx c, CancellationToken ct) =>
            await ReportEndpoints.RenderAsync(format, "access-review", Report(await BuildAsync(c, ct)), c, null, ct))
            .RequirePermission(Permissions.UsersRead, partnerWide: true);
    }
}
