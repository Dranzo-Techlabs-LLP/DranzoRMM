using Dranzo.Api.Notifications;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Services;

/// <summary>Recomputes every partner's audit hash chain once a day and raises the alarm if it does not verify.</summary>
public sealed class AuditVerifier(IServiceScopeFactory scopes, ILogger<AuditVerifier> log) : PeriodicService(scopes, log, TimeSpan.FromHours(24))
{
    private readonly ILogger _log = log;

    protected override Task TickAsync(IServiceProvider sp, CancellationToken ct) => RunAsync(sp, _log, ct);

    public static async Task<int> RunAsync(IServiceProvider sp, ILogger log, CancellationToken ct)
    {
        var db = sp.GetRequiredService<DranzoDbContext>();
        var notifications = sp.GetRequiredService<NotificationService>();
        var audit = sp.GetRequiredService<IAuditLog>();
        var failures = 0;
        foreach (var partnerId in await db.Partners.Select(p => p.Id).ToListAsync(ct))
        {
            var result = await AuditLog.VerifyAsync(db, partnerId, ct);
            if (result.Ok)
            {
                continue;
            }
            failures++;
            log.LogCritical("AUDIT LOG INTEGRITY FAILURE for partner {PartnerId} at sequence {Sequence}: {Problem}", partnerId, result.FirstBadSequence, result.Problem);
            await audit.WriteAsync(partnerId, new AuditEntry("audit.integrity_failed", "failure", Detail: new { result.FirstBadSequence, result.Problem }, ActorType: "system", ActorName: "audit-verifier"), ct);
            await notifications.PublishEventAsync(partnerId, null, "audit.integrity_failed", new { firstBadSequence = result.FirstBadSequence, problem = result.Problem }, ct);
        }
        return failures;
    }
}
