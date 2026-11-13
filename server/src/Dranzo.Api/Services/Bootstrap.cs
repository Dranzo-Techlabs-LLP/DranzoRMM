using Dranzo.Api.Auth;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Services;

public static class Bootstrap
{
    /// <summary>Keeps built-in roles in sync with code and creates the first partner + admin when configured.</summary>
    public static async Task RunAsync(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<DranzoDbContext>();
        var options = sp.GetRequiredService<IOptions<DranzoOptions>>().Value;
        var log = sp.GetRequiredService<ILoggerFactory>().CreateLogger("Bootstrap");
        var now = sp.GetRequiredService<TimeProvider>().GetUtcNow();

        // The agent registry is in-process, so nothing is connected right after start.
        await db.Devices.Where(d => d.IsOnline).ExecuteUpdateAsync(s => s.SetProperty(d => d.IsOnline, false));

        var b = options.Bootstrap;
        if (!await db.Partners.AnyAsync() && !string.IsNullOrWhiteSpace(b.AdminEmail) && !string.IsNullOrEmpty(b.AdminPassword))
        {
            var email = b.AdminEmail.Trim().ToLowerInvariant();
            var problem = PasswordPolicy.Validate(b.AdminPassword, email, options.Auth.PasswordMinLength);
            if (problem is not null)
            {
                throw new InvalidOperationException("Bootstrap admin password rejected: " + problem);
            }
            var partner = new Partner { Id = Guid.NewGuid(), Name = b.PartnerName ?? "My IT Company", CreatedAt = now };
            db.Partners.Add(partner);
            var roles = await EnsureRolesAsync(db, partner.Id);
            var admin = new User
            {
                Id = Guid.NewGuid(), PartnerId = partner.Id, Email = email, DisplayName = "Administrator",
                PasswordHash = AuthService.HashPassword(b.AdminPassword), CreatedAt = now, PasswordChangedAt = now,
            };
            db.Users.Add(admin);
            db.RoleAssignments.Add(new RoleAssignment
            {
                Id = Guid.NewGuid(), PartnerId = partner.Id, UserId = admin.Id, RoleId = roles[BuiltInRoles.PartnerAdmin].Id, ScopeType = ScopeType.Partner, CreatedAt = now,
            });
            db.AlertRules.AddRange(Dranzo.Api.Features.AlertTypes.DefaultsFor(partner.Id, now));
            await db.SaveChangesAsync();
            log.LogInformation("Created partner {Partner} and first administrator {Email}. MFA enrollment is required at first sign-in.", partner.Name, email);
        }

        foreach (var partnerId in await db.Partners.Select(p => p.Id).ToListAsync())
        {
            await EnsureRolesAsync(db, partnerId);
            // Default alert rules for types added after the partner was created (disable a rule rather than delete it,
            // or it is added again at the next start).
            var types = await db.AlertRules.Where(r => r.PartnerId == partnerId).Select(r => r.Type).Distinct().ToListAsync();
            db.AlertRules.AddRange(Dranzo.Api.Features.AlertTypes.DefaultsFor(partnerId, now)
                .Where(r => Dranzo.Api.Features.AlertTypes.AddedLater.Contains(r.Type) && !types.Contains(r.Type)));
        }
        await db.SaveChangesAsync();
    }

    public static async Task<Dictionary<string, Role>> EnsureRolesAsync(DranzoDbContext db, Guid partnerId)
    {
        var existing = await db.Roles.Where(r => r.PartnerId == partnerId && r.IsBuiltIn).ToListAsync();
        var result = new Dictionary<string, Role>();
        foreach (var (name, perms) in BuiltInRoles.Definitions)
        {
            var role = existing.FirstOrDefault(r => r.Name == name) ?? db.Roles.Local.FirstOrDefault(r => r.PartnerId == partnerId && r.Name == name);
            if (role is null)
            {
                role = new Role { Id = Guid.NewGuid(), PartnerId = partnerId, Name = name, IsBuiltIn = true, Permissions = perms };
                db.Roles.Add(role);
            }
            else if (!role.Permissions.Order().SequenceEqual(perms.Order()))
            {
                role.Permissions = perms;
            }
            result[name] = role;
        }
        return result;
    }
}
