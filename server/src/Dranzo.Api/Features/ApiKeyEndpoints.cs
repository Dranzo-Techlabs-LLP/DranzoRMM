using Dranzo.Api.Auth;
using Dranzo.Domain;
using Dranzo.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

public static class ApiKeyEndpoints
{
    public sealed record KeyRequest(string? Name, int? ExpiresInDays);

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/api-keys", async (Ctx c, CancellationToken ct) =>
        {
            var keys = await c.Db.ApiKeys.AsNoTracking().OrderByDescending(k => k.CreatedAt).ToListAsync(ct);
            var assignments = await c.Db.RoleAssignments.AsNoTracking().Include(a => a.Role).Where(a => a.ApiKeyId != null).ToListAsync(ct);
            return Results.Ok(keys.Select(k => new
            {
                k.Id, k.Name, k.CreatedAt, k.ExpiresAt, k.RevokedAt, k.LastUsedAt, prefix = ApiKeyAuthHandler.Prefix + k.Id.ToString("N")[..8] + "…",
                assignments = assignments.Where(a => a.ApiKeyId == k.Id).Select(a => new { a.Id, a.RoleId, roleName = a.Role.Name, scopeType = a.ScopeType.ToString(), a.ScopeId }),
            }));
        }).RequirePermission(Permissions.ApiKeysManage, partnerWide: true);

        // A new key has no permissions until a role is assigned to it (POST /role-assignments with apiKeyId).
        api.MapPost("/api-keys", async (KeyRequest req, Ctx c, CancellationToken ct) =>
        {
            if (Api.CleanName(req.Name) is not { } name)
            {
                return Api.BadRequest("Name is required.");
            }
            var days = req.ExpiresInDays ?? 365;
            if (days is < 1 or > 730)
            {
                return Api.BadRequest("expiresInDays must be 1..730.");
            }
            var id = Guid.NewGuid();
            var secret = Hashing.NewToken("", 32);
            c.Db.ApiKeys.Add(new ApiKey { Id = id, PartnerId = c.Who.PartnerId, Name = name, SecretHash = Hashing.Sha256Hex(secret), CreatedAt = c.Now, ExpiresAt = c.Now.AddDays(days), CreatedByUserId = c.Who.UserId });
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("api_key.create", targetType: "api_key", targetId: id, detail: new { name, days }, ct: ct);
            // Shown once; only the hash is stored.
            return Results.Created($"/api/v1/api-keys/{id}", new { id, key = $"{ApiKeyAuthHandler.Prefix}{id:N}_{secret}", expiresAt = c.Now.AddDays(days) });
        }).RequirePermission(Permissions.ApiKeysManage, partnerWide: true).RequireStepUp();

        api.MapDelete("/api-keys/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var key = await c.Db.ApiKeys.FirstOrDefaultAsync(k => k.Id == id, ct);
            if (key is null)
            {
                return Api.NotFound();
            }
            key.RevokedAt ??= c.Now;
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("api_key.revoke", targetType: "api_key", targetId: id, detail: new { key.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.ApiKeysManage, partnerWide: true).RequireStepUp();
    }
}
