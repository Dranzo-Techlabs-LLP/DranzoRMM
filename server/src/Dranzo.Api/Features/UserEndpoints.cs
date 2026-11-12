using Dranzo.Api.Auth;
using Dranzo.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

public static class UserEndpoints
{
    public sealed record CreateUserRequest(string? Email, string? DisplayName, string? Password);

    public sealed record UpdateUserRequest(string? DisplayName, bool? Disabled);

    public sealed record RoleRequest(string? Name, string[]? Permissions);

    public sealed record AssignmentRequest(Guid? UserId, Guid? ApiKeyId, Guid RoleId, string? ScopeType, Guid? ScopeId);

    public static void Map(RouteGroupBuilder api)
    {
        // ----- Users (partner-level; needs partner scope) -----
        api.MapGet("/users", async (Ctx c, CancellationToken ct) =>
        {
            var users = await c.Db.Users.AsNoTracking().OrderBy(u => u.Email).ToListAsync(ct);
            var assignments = await c.Db.RoleAssignments.AsNoTracking().Include(a => a.Role).Where(a => a.UserId != null).ToListAsync(ct);
            return Results.Ok(users.Select(u => new
            {
                u.Id, u.Email, u.DisplayName, u.Disabled, u.TotpEnabled, u.LastLoginAt, u.CreatedAt,
                locked = u.LockoutEnd > c.Now,
                assignments = assignments.Where(a => a.UserId == u.Id).Select(a => new { a.Id, a.RoleId, roleName = a.Role.Name, scopeType = a.ScopeType.ToString(), a.ScopeId }),
            }));
        }).RequirePermission(Permissions.UsersRead, partnerWide: true);

        api.MapPost("/users", async (CreateUserRequest req, Ctx c, IOptions<DranzoOptions> opt, CancellationToken ct) =>
        {
            var email = req.Email?.Trim().ToLowerInvariant() ?? "";
            if (email.Length is < 3 or > 254 || !email.Contains('@') || email.Any(char.IsWhiteSpace))
            {
                return Api.BadRequest("A valid email is required.");
            }
            if (Api.CleanName(req.DisplayName) is not { } name)
            {
                return Api.BadRequest("Display name is required.");
            }
            var problem = PasswordPolicy.Validate(req.Password ?? "", email, opt.Value.Auth.PasswordMinLength);
            if (problem is not null)
            {
                return Api.BadRequest(problem);
            }
            if (await c.Db.Users.IgnoreQueryFilters().AnyAsync(u => u.Email == email, ct))
            {
                return Api.Conflict("A user with this email already exists.");
            }
            var user = new User
            {
                Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, Email = email, DisplayName = name,
                PasswordHash = AuthService.HashPassword(req.Password!), CreatedAt = c.Now, PasswordChangedAt = c.Now, MustChangePassword = true,
            };
            c.Db.Users.Add(user);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("user.create", targetType: "user", targetId: user.Id, detail: new { email }, ct: ct);
            return Results.Created($"/api/v1/users/{user.Id}", new { user.Id, user.Email });
        }).RequirePermission(Permissions.UsersManage, partnerWide: true);

        api.MapPatch("/users/{id:guid}", async (Guid id, UpdateUserRequest req, Ctx c, ScopeResolver scopes, CancellationToken ct) =>
        {
            var user = await c.Db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
            if (user is null)
            {
                return Api.NotFound();
            }
            if (!await MayManageAsync(c, scopes, id, ct))
            {
                return TooPowerful();
            }
            if (req.DisplayName is not null)
            {
                if (Api.CleanName(req.DisplayName) is not { } name)
                {
                    return Api.BadRequest("Invalid display name.");
                }
                user.DisplayName = name;
            }
            if (req.Disabled is { } disabled)
            {
                if (disabled && id == c.Who.UserId)
                {
                    return Api.BadRequest("You cannot disable your own account.");
                }
                if (disabled && await IsLastPartnerAdmin(c, id, ct))
                {
                    return Api.Conflict("At least one enabled Partner Admin must remain.");
                }
                user.Disabled = disabled;
                if (disabled)
                {
                    var now = c.Now;
                    await c.Db.UserSessions.Where(s => s.UserId == id && s.RevokedAt == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), ct);
                }
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("user.update", targetType: "user", targetId: id, detail: new { user.DisplayName, user.Disabled }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.UsersManage, partnerWide: true);

        // Resets a user's authenticator. The user must enroll a new one at next sign-in; MFA is never switched off.
        api.MapPost("/users/{id:guid}/reset-mfa", async (Guid id, Ctx c, ScopeResolver scopes, CancellationToken ct) =>
        {
            var user = await c.Db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
            if (user is null)
            {
                return Api.NotFound();
            }
            if (!await MayManageAsync(c, scopes, id, ct))
            {
                return TooPowerful();
            }
            user.TotpEnabled = false;
            user.TotpSecretProtected = null;
            user.RecoveryCodeHashes = [];
            user.LastTotpStep = 0;
            var now = c.Now;
            await c.Db.UserSessions.Where(s => s.UserId == id && s.RevokedAt == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), ct);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("user.reset_mfa", targetType: "user", targetId: id, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.UsersManage, partnerWide: true).RequireStepUp();

        api.MapPost("/users/{id:guid}/unlock", async (Guid id, Ctx c, ScopeResolver scopes, CancellationToken ct) =>
        {
            var user = await c.Db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
            if (user is null)
            {
                return Api.NotFound();
            }
            if (!await MayManageAsync(c, scopes, id, ct))
            {
                return TooPowerful();
            }
            user.LockoutEnd = null;
            user.FailedLogins = 0;
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("user.unlock", targetType: "user", targetId: id, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.UsersManage, partnerWide: true);

        // Sets a temporary password: the user must change it at next sign-in and all their sessions end.
        api.MapPost("/users/{id:guid}/reset-password", async (Guid id, CreateUserRequest req, Ctx c, ScopeResolver scopes, IOptions<DranzoOptions> opt, CancellationToken ct) =>
        {
            var user = await c.Db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
            if (user is null)
            {
                return Api.NotFound();
            }
            if (!await MayManageAsync(c, scopes, id, ct))
            {
                return TooPowerful();
            }
            var problem = PasswordPolicy.Validate(req.Password ?? "", user.Email, opt.Value.Auth.PasswordMinLength);
            if (problem is not null)
            {
                return Api.BadRequest(problem);
            }
            user.PasswordHash = AuthService.HashPassword(req.Password!);
            user.PasswordChangedAt = c.Now;
            user.MustChangePassword = true;
            user.LockoutEnd = null;
            user.FailedLogins = 0;
            var now = c.Now;
            await c.Db.UserSessions.Where(s => s.UserId == id && s.RevokedAt == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), ct);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("user.reset_password", targetType: "user", targetId: id, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.UsersManage, partnerWide: true).RequireStepUp();

        api.MapDelete("/users/{id:guid}", async (Guid id, Ctx c, ScopeResolver scopes, CancellationToken ct) =>
        {
            var user = await c.Db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
            if (user is null)
            {
                return Api.NotFound();
            }
            if (!await MayManageAsync(c, scopes, id, ct))
            {
                return TooPowerful();
            }
            if (id == c.Who.UserId)
            {
                return Api.BadRequest("You cannot delete your own account.");
            }
            if (await IsLastPartnerAdmin(c, id, ct))
            {
                return Api.Conflict("At least one enabled Partner Admin must remain.");
            }
            await c.Db.UserSessions.Where(s => s.UserId == id).ExecuteDeleteAsync(ct);
            await c.Db.RoleAssignments.Where(a => a.UserId == id).ExecuteDeleteAsync(ct);
            c.Db.Users.Remove(user);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("user.delete", targetType: "user", targetId: id, detail: new { user.Email }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.UsersManage, partnerWide: true).RequireStepUp();

        // ----- Roles -----
        api.MapGet("/roles", async (Ctx c, CancellationToken ct) =>
            Results.Ok(await c.Db.Roles.AsNoTracking().OrderByDescending(r => r.IsBuiltIn).ThenBy(r => r.Name)
                .Select(r => new { r.Id, r.Name, r.IsBuiltIn, r.Permissions }).ToListAsync(ct)))
            .RequirePermission(Permissions.UsersRead, partnerWide: true);

        api.MapPost("/roles", async (RoleRequest req, Ctx c, CancellationToken ct) =>
        {
            if (Api.CleanName(req.Name, 64) is not { } name)
            {
                return Api.BadRequest("Name is required.");
            }
            var perms = (req.Permissions ?? []).Distinct().ToArray();
            if (perms.Length == 0 || perms.Any(p => !Permissions.All.Contains(p)))
            {
                return Api.BadRequest("Permissions must be a non-empty list of known permissions.");
            }
            if (await c.Db.Roles.AnyAsync(r => r.Name == name, ct))
            {
                return Api.Conflict("A role with this name already exists.");
            }
            var role = new Role { Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, Name = name, Permissions = perms };
            c.Db.Roles.Add(role);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("role.create", targetType: "role", targetId: role.Id, detail: new { name, permissions = perms }, ct: ct);
            return Results.Created($"/api/v1/roles/{role.Id}", new { role.Id, role.Name });
        }).RequirePermission(Permissions.RolesManage, partnerWide: true).RequireStepUp();

        api.MapPatch("/roles/{id:guid}", async (Guid id, RoleRequest req, Ctx c, CancellationToken ct) =>
        {
            var role = await c.Db.Roles.FirstOrDefaultAsync(r => r.Id == id, ct);
            if (role is null)
            {
                return Api.NotFound();
            }
            if (role.IsBuiltIn)
            {
                return Api.Conflict("Built-in roles cannot be changed.");
            }
            if (req.Name is not null)
            {
                if (Api.CleanName(req.Name, 64) is not { } name)
                {
                    return Api.BadRequest("Invalid name.");
                }
                role.Name = name;
            }
            if (req.Permissions is not null)
            {
                var perms = req.Permissions.Distinct().ToArray();
                if (perms.Length == 0 || perms.Any(p => !Permissions.All.Contains(p)))
                {
                    return Api.BadRequest("Permissions must be a non-empty list of known permissions.");
                }
                role.Permissions = perms;
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("role.update", targetType: "role", targetId: id, detail: new { role.Name, permissions = role.Permissions }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.RolesManage, partnerWide: true).RequireStepUp();

        api.MapDelete("/roles/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var role = await c.Db.Roles.FirstOrDefaultAsync(r => r.Id == id, ct);
            if (role is null)
            {
                return Api.NotFound();
            }
            if (role.IsBuiltIn)
            {
                return Api.Conflict("Built-in roles cannot be deleted.");
            }
            c.Db.Roles.Remove(role);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("role.delete", targetType: "role", targetId: id, detail: new { role.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.RolesManage, partnerWide: true).RequireStepUp();

        // ----- Role assignments -----
        api.MapPost("/role-assignments", async (AssignmentRequest req, Ctx c, CancellationToken ct) =>
        {
            if ((req.UserId is null) == (req.ApiKeyId is null))
            {
                return Api.BadRequest("Give exactly one of userId or apiKeyId.");
            }
            if (!Enum.TryParse<ScopeType>(req.ScopeType, true, out var scopeType) || !Enum.IsDefined(scopeType) || int.TryParse(req.ScopeType, out _))
            {
                return Api.BadRequest("scopeType must be Partner, Organization, Site or Group.");
            }
            var role = await c.Db.Roles.FirstOrDefaultAsync(r => r.Id == req.RoleId, ct);
            if (role is null)
            {
                return Api.NotFound();
            }
            if (req.UserId is { } uid && !await c.Db.Users.AnyAsync(u => u.Id == uid, ct))
            {
                return Api.NotFound();
            }
            if (req.ApiKeyId is { } kid)
            {
                if (!await c.Db.ApiKeys.AnyAsync(k => k.Id == kid, ct))
                {
                    return Api.NotFound();
                }
                if (role.Permissions.Any(Permissions.InteractiveOnly.Contains))
                {
                    return Api.BadRequest("This role contains interactive-only permissions and cannot be given to an API key.");
                }
            }
            // The scope target must exist inside this partner (queries are partner-filtered).
            var scopeOk = scopeType switch
            {
                ScopeType.Partner => req.ScopeId is null,
                ScopeType.Organization => req.ScopeId is { } id && await c.Db.Organizations.AnyAsync(o => o.Id == id, ct),
                ScopeType.Site => req.ScopeId is { } id && await c.Db.Sites.AnyAsync(s => s.Id == id, ct),
                ScopeType.Group => req.ScopeId is { } id && await c.Db.DeviceGroups.AnyAsync(g => g.Id == id, ct),
                _ => false,
            };
            if (!scopeOk)
            {
                return Api.BadRequest("Scope target not found.");
            }
            var a = new RoleAssignment
            {
                Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, UserId = req.UserId, ApiKeyId = req.ApiKeyId, RoleId = role.Id,
                ScopeType = scopeType, ScopeId = req.ScopeId, CreatedAt = c.Now,
            };
            c.Db.RoleAssignments.Add(a);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("role.assign", targetType: req.UserId is null ? "apikey" : "user", targetId: req.UserId ?? req.ApiKeyId,
                detail: new { role = role.Name, scopeType = scopeType.ToString(), req.ScopeId }, ct: ct);
            return Results.Created($"/api/v1/role-assignments/{a.Id}", new { a.Id });
        }).RequirePermission(Permissions.RolesManage, partnerWide: true).RequireStepUp();

        api.MapDelete("/role-assignments/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var a = await c.Db.RoleAssignments.Include(x => x.Role).FirstOrDefaultAsync(x => x.Id == id, ct);
            if (a is null)
            {
                return Api.NotFound();
            }
            if (a.UserId is { } uid && a.ScopeType == ScopeType.Partner && a.Role.Permissions.Contains(Permissions.RolesManage) && await IsLastPartnerAdmin(c, uid, ct))
            {
                return Api.Conflict("At least one enabled Partner Admin must remain.");
            }
            c.Db.RoleAssignments.Remove(a);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("role.unassign", targetType: a.UserId is null ? "apikey" : "user", targetId: a.UserId ?? a.ApiKeyId,
                detail: new { role = a.Role.Name, scopeType = a.ScopeType.ToString(), a.ScopeId }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.RolesManage, partnerWide: true).RequireStepUp();
    }

    /// <summary>
    /// A user manager may only act on accounts that are not more powerful than themselves: the target may not hold any
    /// permission the caller lacks. Otherwise users.manage alone could reset a Partner Admin's password and MFA.
    /// </summary>
    private static async Task<bool> MayManageAsync(Ctx c, ScopeResolver scopes, Guid targetUserId, CancellationToken ct)
    {
        if (targetUserId == c.Who.UserId)
        {
            return true;
        }
        var mine = (await scopes.AssignmentsAsync(c.Who, ct)).Where(a => a.ScopeType == ScopeType.Partner).SelectMany(a => a.Role.Permissions).ToHashSet();
        var theirs = await c.Db.RoleAssignments.AsNoTracking().Include(a => a.Role).Where(a => a.UserId == targetUserId).ToListAsync(ct);
        return theirs.All(a => a.Role.Permissions.All(mine.Contains));
    }

    private static IResult TooPowerful() => Api.Error(403, "forbidden", "This account has permissions you do not have; ask a Partner Admin.");

    /// <summary>True if <paramref name="userId"/> is the only enabled user holding partner-wide role management.</summary>
    private static async Task<bool> IsLastPartnerAdmin(Ctx c, Guid userId, CancellationToken ct)
    {
        var admins = await c.Db.RoleAssignments.Include(a => a.Role)
            .Where(a => a.UserId != null && a.ScopeType == ScopeType.Partner && a.Role.Permissions.Contains(Permissions.RolesManage))
            .Select(a => a.UserId!.Value).Distinct().ToListAsync(ct);
        var enabled = await c.Db.Users.Where(u => admins.Contains(u.Id) && !u.Disabled).Select(u => u.Id).ToListAsync(ct);
        return enabled.Contains(userId) && enabled.Count == 1;
    }
}
