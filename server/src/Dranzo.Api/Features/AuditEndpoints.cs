using System.Text;
using Dranzo.Api.Auth;
using Dranzo.Domain;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

public static class AuditEndpoints
{
    public sealed class AuditQuery
    {
        public Guid? OrganizationId { get; set; }
        public Guid? DeviceId { get; set; }
        public string? Action { get; set; }
        public string? Actor { get; set; }
        public DateTimeOffset? From { get; set; }
        public DateTimeOffset? To { get; set; }
        public int? Page { get; set; }
        public int? PageSize { get; set; }
    }

    public static IQueryable<AuditEvent> Filter(IQueryable<AuditEvent> q, AuditQuery f)
    {
        if (f.OrganizationId is { } org)
        {
            q = q.Where(a => a.OrganizationId == org);
        }
        if (f.DeviceId is { } dev)
        {
            q = q.Where(a => a.DeviceId == dev);
        }
        if (!string.IsNullOrWhiteSpace(f.Action))
        {
            q = q.Where(a => EF.Functions.ILike(a.Action, Api.LikeLiteral(f.Action) + "%", Api.LikeEscape));
        }
        if (!string.IsNullOrWhiteSpace(f.Actor))
        {
            q = q.Where(a => EF.Functions.ILike(a.ActorName, "%" + Api.LikeLiteral(f.Actor) + "%", Api.LikeEscape));
        }
        if (f.From is { } from)
        {
            q = q.Where(a => a.OccurredAt >= from);
        }
        if (f.To is { } to)
        {
            q = q.Where(a => a.OccurredAt <= to);
        }
        return q;
    }

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/audit", async ([AsParameters] AuditQuery query, Ctx c, CancellationToken ct) =>
        {
            var (skip, take, page) = Api.Paging(query.Page, query.PageSize);
            var q = Filter(c.Db.AuditEvents.AsNoTracking(), query);
            var total = await q.CountAsync(ct);
            var items = (await q.OrderByDescending(a => a.Sequence).Skip(skip).Take(take).ToListAsync(ct)).Select(a => new
            {
                a.Sequence, a.OccurredAt, a.ActorType, a.ActorId, a.ActorName, a.Action, a.TargetType, a.TargetId, a.OrganizationId, a.DeviceId,
                a.Ip, a.Result, detail = System.Text.Json.JsonSerializer.Deserialize<System.Text.Json.JsonElement>(a.Detail), a.ContentSha256, a.Hash,
            });
            return Results.Ok(new { total, page, pageSize = take, items });
        }).RequirePermission(Permissions.AuditRead);

        api.MapGet("/audit/export.csv", async ([AsParameters] AuditQuery query, Ctx c, CancellationToken ct) =>
        {
            var rows = await Filter(c.Db.AuditEvents.AsNoTracking(), query).OrderBy(a => a.Sequence).Take(100_000).ToListAsync(ct);
            var csv = Api.Csv(
                ["sequence", "occurred_at_utc", "actor_type", "actor", "action", "target_type", "target_id", "organization_id", "device_id", "ip", "result", "detail", "content_sha256", "prev_hash", "hash"],
                rows.Select(a => new object?[] { a.Sequence, a.OccurredAt, a.ActorType, a.ActorName, a.Action, a.TargetType, a.TargetId, a.OrganizationId, a.DeviceId, a.Ip, a.Result, a.Detail, a.ContentSha256, a.PrevHash, a.Hash }));
            await c.Audit("audit.export", detail: new { rows = rows.Count }, ct: ct);
            return Results.File(Encoding.UTF8.GetBytes(csv), "text/csv", "audit-log.csv");
        }).RequirePermission(Permissions.AuditRead);

        // Recomputes the whole hash chain for the caller's partner.
        api.MapGet("/audit/verify", async (Ctx c, IServiceScopeFactory scopes, CancellationToken ct) =>
        {
            await using var scope = scopes.CreateAsyncScope();
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            var result = await AuditLog.VerifyAsync(scope.ServiceProvider.GetRequiredService<DranzoDbContext>(), c.Who.PartnerId, ct);
            return Results.Ok(result);
        }).RequirePermission(Permissions.AuditRead, partnerWide: true);
    }
}
