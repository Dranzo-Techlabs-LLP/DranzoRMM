using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Dranzo.Infrastructure.Audit;

public sealed record AuditEntry(
    string Action,
    string Result = "success",
    Guid? OrganizationId = null,
    Guid? DeviceId = null,
    string? TargetType = null,
    string? TargetId = null,
    object? Detail = null,
    string? ContentSha256 = null,
    string? ActorType = null,
    Guid? ActorId = null,
    string? ActorName = null,
    string? Ip = null);

public interface IAuditLog
{
    Task WriteAsync(Guid partnerId, AuditEntry entry, CancellationToken ct = default);
}

public sealed record AuditVerification(bool Ok, long Count, long? FirstBadSequence, string? Problem);

/// <summary>
/// Append-only, hash-chained audit log (one chain per partner).
/// Each write runs in its own transaction under a per-partner advisory lock so the chain is strictly ordered.
/// </summary>
public sealed class AuditLog(IServiceScopeFactory scopes, TenantContext caller, TimeProvider clock) : IAuditLog
{
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    public async Task WriteAsync(Guid partnerId, AuditEntry entry, CancellationToken ct = default)
    {
        await using var scope = scopes.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
        var db = scope.ServiceProvider.GetRequiredService<DranzoDbContext>();
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.Database.ExecuteSqlAsync($"SELECT pg_advisory_xact_lock(hashtextextended({partnerId.ToString()}, 7))", ct);

        var last = await db.AuditEvents.Where(a => a.PartnerId == partnerId).OrderByDescending(a => a.Sequence)
            .Select(a => new { a.Sequence, a.Hash }).FirstOrDefaultAsync(ct);

        var now = clock.GetUtcNow();
        var ev = new AuditEvent
        {
            PartnerId = partnerId,
            OrganizationId = entry.OrganizationId,
            Sequence = (last?.Sequence ?? 0) + 1,
            OccurredAt = new DateTimeOffset(now.Ticks - (now.Ticks % TimeSpan.TicksPerMillisecond), TimeSpan.Zero),
            ActorType = entry.ActorType ?? caller.ActorType,
            ActorId = entry.ActorId ?? caller.ActorId,
            ActorName = Truncate(entry.ActorName ?? caller.ActorName, 256),
            Action = entry.Action,
            TargetType = entry.TargetType,
            TargetId = entry.TargetId,
            DeviceId = entry.DeviceId,
            Ip = entry.Ip ?? caller.Ip,
            Result = entry.Result,
            Detail = entry.Detail is null ? "{}" : JsonSerializer.Serialize(entry.Detail, JsonSerializerOptions.Web),
            ContentSha256 = entry.ContentSha256,
            PrevHash = last?.Hash ?? GenesisHash,
            Hash = "",
        };
        ev.Hash = ComputeHash(ev);
        db.AuditEvents.Add(ev);
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    public static string ComputeHash(AuditEvent e)
    {
        string?[] fields =
        [
            e.PrevHash, e.PartnerId.ToString("D"), e.Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            e.OccurredAt.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            e.ActorType, e.ActorId?.ToString("D"), e.ActorName, e.Action, e.TargetType, e.TargetId,
            e.OrganizationId?.ToString("D"), e.DeviceId?.ToString("D"), e.Ip, e.Result, e.Detail, e.ContentSha256,
        ];
        // A JSON array of strings is an unambiguous, order-preserving encoding of the fields.
        var canonical = JsonSerializer.Serialize(fields);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>Recomputes a partner's chain. The caller must use a system-scoped context.</summary>
    public static async Task<AuditVerification> VerifyAsync(DranzoDbContext db, Guid partnerId, CancellationToken ct)
    {
        var prev = GenesisHash;
        long expected = 1, count = 0;
        await foreach (var e in db.AuditEvents.IgnoreQueryFilters().AsNoTracking().Where(a => a.PartnerId == partnerId).OrderBy(a => a.Sequence).AsAsyncEnumerable().WithCancellation(ct))
        {
            count++;
            if (e.Sequence != expected)
            {
                return new AuditVerification(false, count, expected, $"Missing or out-of-order event (expected sequence {expected}, found {e.Sequence}).");
            }
            if (e.PrevHash != prev || ComputeHash(e) != e.Hash)
            {
                return new AuditVerification(false, count, e.Sequence, "Hash mismatch: the event or one before it was modified.");
            }
            prev = e.Hash;
            expected++;
        }
        return new AuditVerification(true, count, null, null);
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max];
}
