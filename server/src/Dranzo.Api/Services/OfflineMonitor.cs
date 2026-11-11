using Dranzo.Api.Agents;
using Dranzo.Api.Live;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Services;

/// <summary>Base for periodic background work that runs in a system-scoped DI scope.</summary>
public abstract class PeriodicService(IServiceScopeFactory scopes, ILogger log, TimeSpan interval) : BackgroundService
{
    protected IServiceScopeFactory Scopes => scopes;

    protected abstract Task TickAsync(IServiceProvider sp, CancellationToken ct);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(interval);
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
                await TickAsync(scope.ServiceProvider, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                log.LogError(ex, "{Service} tick failed", GetType().Name);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}

/// <summary>Marks devices offline after the configured number of missed heartbeats or a dropped connection.</summary>
public sealed class OfflineMonitor : PeriodicService
{
    private readonly AgentRegistry _registry;
    private readonly IOptions<DranzoOptions> _options;

    public OfflineMonitor(IServiceScopeFactory scopes, ILogger<OfflineMonitor> log, AgentRegistry registry, IOptions<DranzoOptions> options)
        : base(scopes, log, TimeSpan.FromSeconds(15))
    {
        _registry = registry;
        _options = options;
        registry.DeviceGone += id => _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(10)); // grace for a quick reconnect
            if (registry.IsConnected(id))
            {
                return;
            }
            try
            {
                await using var scope = Scopes.CreateAsyncScope();
                scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
                await MarkOfflineAsync(scope.ServiceProvider, d => d.Id == id, default);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Failed to mark device {DeviceId} offline", id);
            }
        });
    }

    protected override Task TickAsync(IServiceProvider sp, CancellationToken ct)
    {
        var a = _options.Value.Agents;
        var threshold = sp.GetRequiredService<TimeProvider>().GetUtcNow().AddSeconds(-a.HeartbeatSeconds * a.MissedHeartbeats);
        return MarkOfflineAsync(sp, d => d.LastSeenAt == null || d.LastSeenAt < threshold, ct);
    }

    private async Task MarkOfflineAsync(IServiceProvider sp, System.Linq.Expressions.Expression<Func<Dranzo.Domain.Device, bool>> predicate, CancellationToken ct)
    {
        var db = sp.GetRequiredService<DranzoDbContext>();
        var live = sp.GetRequiredService<LiveNotifier>();
        var devices = await db.Devices.Where(d => d.IsOnline).Where(predicate).ToListAsync(ct);
        foreach (var d in devices)
        {
            d.IsOnline = false;
            _registry.Disconnect(d.Id, "heartbeat timeout");
        }
        await db.SaveChangesAsync(ct);
        var notifications = sp.GetRequiredService<Dranzo.Api.Notifications.NotificationService>();
        foreach (var d in devices)
        {
            await live.DeviceChangedAsync(d);
            await notifications.PublishEventAsync(d.PartnerId, d.OrganizationId, "device.offline", new { deviceId = d.Id, hostname = d.Hostname, lastSeenAt = d.LastSeenAt }, ct);
        }
    }
}
