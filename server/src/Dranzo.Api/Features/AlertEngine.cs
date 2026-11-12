using System.Text.Json;
using Dranzo.Api.Live;
using Dranzo.Api.Notifications;
using Dranzo.Api.Services;
using Dranzo.Domain;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

public static class AlertTypes
{
    public const string DeviceOffline = "device.offline";
    public const string DiskUsage = "disk.usage";
    public const string AntivirusOff = "antivirus.off";
    public const string FirewallOff = "firewall.off";
    public const string EncryptionOff = "encryption.off";
    public const string PatchFailed = "patch.failed";
    public const string LocalAdminNew = "localadmin.new";
    public const string AgentTamper = "agent.tamper";
    public const string ComplianceDrift = "compliance.drift";
    public const string KnownExploited = "vulnerability.known_exploited";

    public static readonly string[] All = [DeviceOffline, DiskUsage, AntivirusOff, FirewallOff, EncryptionOff, PatchFailed, LocalAdminNew, AgentTamper, ComplianceDrift, KnownExploited];
    public static readonly string[] Severities = ["info", "warning", "critical"];

    /// <summary>Rules created for a new partner so alerting works out of the box.</summary>
    public static IEnumerable<AlertRule> Defaults(Guid partnerId, DateTimeOffset now) =>
    [
        Rule("Device offline for 30 minutes", DeviceOffline, "warning", "{\"minutes\":30}"),
        Rule("Disk above 90%", DiskUsage, "warning", "{\"percent\":90}"),
        Rule("Antivirus off or out of date", AntivirusOff, "critical", "{}"),
        Rule("Firewall off", FirewallOff, "warning", "{}"),
        Rule("Disk encryption off", EncryptionOff, "warning", "{}"),
        Rule("Update failed to install", PatchFailed, "warning", "{}"),
        Rule("New local administrator", LocalAdminNew, "critical", "{}"),
        Rule("Agent tampering or uninstall", AgentTamper, "critical", "{}"),
        Rule("Compliance drift", ComplianceDrift, "warning", "{}"),
        Rule("Known exploited vulnerability present", KnownExploited, "critical", "{}"),
    ];

    private static AlertRule Rule(string name, string type, string severity, string json) =>
        new() { Id = Guid.NewGuid(), Name = name, Type = type, Severity = severity, ParamsJson = json, CreatedAt = DateTimeOffset.UtcNow };

    public static IEnumerable<AlertRule> DefaultsFor(Guid partnerId, DateTimeOffset now) => Defaults(partnerId, now).Select(r =>
    {
        r.PartnerId = partnerId;
        r.CreatedAt = now;
        return r;
    });
}

/// <summary>
/// Evaluates alert rules for a device. Conditions are state-based: an alert opens when the condition becomes
/// true (deduplicated by key), and resolves itself when the condition clears.
/// </summary>
public sealed class AlertEngine(DranzoDbContext db, NotificationService notifications, LiveNotifier live, IAuditLog audit, TimeProvider clock)
{
    private sealed record Condition(string Key, string Title, string Detail);

    public async Task EvaluateDeviceAsync(Guid deviceId, CancellationToken ct)
    {
        var device = await db.Devices.FirstOrDefaultAsync(d => d.Id == deviceId && d.Status == DeviceStatus.Active, ct);
        if (device is null)
        {
            return;
        }
        var rules = await db.AlertRules.Where(r => r.PartnerId == device.PartnerId && r.Enabled && (r.OrganizationId == null || r.OrganizationId == device.OrganizationId)).ToListAsync(ct);
        if (rules.Count == 0)
        {
            return;
        }
        var now = clock.GetUtcNow();
        var posture = await db.PostureSnapshots.AsNoTracking().Where(p => p.DeviceId == deviceId && p.IsLatest).FirstOrDefaultAsync(ct);
        var inventory = await db.InventorySnapshots.AsNoTracking().Where(p => p.DeviceId == deviceId && p.IsLatest).Select(p => p.DataJson).FirstOrDefaultAsync(ct);
        var failedPatches = await db.DevicePatchStates.Where(s => s.DeviceId == deviceId && s.Status == PatchStatus.Failed).Select(s => s.CatalogEntry.Title).Take(5).ToListAsync(ct);
        var drift = await db.ComplianceResults.Where(r => r.DeviceId == deviceId && !r.Compliant && r.Supported != false).Select(r => r.PolicyId).ToListAsync(ct);
        var kev = await db.DeviceVulnerabilities.Where(v => v.DeviceId == deviceId && v.KnownExploited).Select(v => v.CveId).Distinct().Take(5).ToListAsync(ct);
        var open = await db.Alerts.Where(a => a.DeviceId == deviceId && a.State != AlertState.Resolved).ToListAsync(ct);

        foreach (var rule in rules)
        {
            using var p = JsonDocument.Parse(rule.ParamsJson);
            var active = new List<Condition>();
            switch (rule.Type)
            {
                case AlertTypes.DeviceOffline:
                    var minutes = p.RootElement.TryGetProperty("minutes", out var m) && m.TryGetInt32(out var mv) ? Math.Clamp(mv, 1, 60 * 24 * 30) : 30;
                    var since = device.LastSeenAt ?? device.EnrolledAt;
                    if (!device.IsOnline && since <= now.AddMinutes(-minutes))
                    {
                        active.Add(new("offline", $"{device.Hostname} is offline", $"No contact since {since:u} (threshold {minutes} min)."));
                    }
                    break;
                case AlertTypes.DiskUsage:
                    var percent = p.RootElement.TryGetProperty("percent", out var pc) && pc.TryGetDouble(out var pv) ? Math.Clamp(pv, 1, 100) : 90;
                    if (inventory is not null)
                    {
                        using var inv = JsonDocument.Parse(inventory);
                        var full = Agents.J.Arr(inv.RootElement, "disks", 64)
                            .Select(d => (Mount: Agents.J.Str(d, "mountPoint", 128), Total: Agents.J.Long(d, "totalBytes") ?? 0, Free: Agents.J.Long(d, "freeBytes") ?? 0))
                            .Where(d => d.Total > 0 && (d.Total - d.Free) * 100.0 / d.Total >= percent).OrderByDescending(d => (d.Total - d.Free) * 1.0 / d.Total).ToList();
                        // One alert per device, however many disks: an agent cannot open alerts by inventing mount points.
                        if (full.Count > 0)
                        {
                            var top = full[0];
                            var title = full.Count == 1
                                ? $"Disk {top.Mount} on {device.Hostname} is {(top.Total - top.Free) * 100.0 / top.Total:F0}% full"
                                : $"{full.Count} disks on {device.Hostname} are above {percent:F0}%";
                            var detail = string.Join("; ", full.Take(5).Select(d => $"{d.Mount}: {d.Free / 1_073_741_824.0:F1} GiB free of {d.Total / 1_073_741_824.0:F1} GiB"));
                            active.Add(new("disk", title, detail + $" (threshold {percent:F0}%)"));
                        }
                    }
                    break;
                case AlertTypes.AntivirusOff when posture?.AntivirusOk == false:
                    active.Add(new("av", $"Antivirus is off or out of date on {device.Hostname}", "No enabled, up-to-date antivirus product was reported."));
                    break;
                case AlertTypes.FirewallOff when posture?.FirewallOk == false:
                    active.Add(new("fw", $"Firewall is off on {device.Hostname}", "The host firewall reports disabled."));
                    break;
                case AlertTypes.EncryptionOff when posture?.EncryptionOk == false:
                    active.Add(new("enc", $"Disk encryption is off on {device.Hostname}", "At least one volume is not encrypted."));
                    break;
                case AlertTypes.PatchFailed when failedPatches.Count > 0:
                    active.Add(new("patch", $"Updates failed to install on {device.Hostname}", string.Join("; ", failedPatches)));
                    break;
                case AlertTypes.ComplianceDrift when drift.Count > 0:
                    active.Add(new("drift", $"{device.Hostname} is out of compliance", $"{drift.Count} policy check(s) are failing."));
                    break;
                case AlertTypes.KnownExploited when kev.Count > 0:
                    active.Add(new("kev", $"Known exploited vulnerability on {device.Hostname}", string.Join(", ", kev)));
                    break;
            }

            // Event-style alerts (new local admin, tampering) are opened by RaiseAsync and closed by a person.
            if (rule.Type is AlertTypes.LocalAdminNew or AlertTypes.AgentTamper)
            {
                continue;
            }
            foreach (var c in active)
            {
                var key = $"{rule.Id:N}:{c.Key}";
                if (open.All(a => a.DedupKey != key))
                {
                    await OpenAsync(device, rule, key, c.Title, c.Detail, now, ct);
                }
            }
            foreach (var stale in open.Where(a => a.RuleId == rule.Id && active.All(c => $"{rule.Id:N}:{c.Key}" != a.DedupKey)))
            {
                stale.State = AlertState.Resolved;
                stale.ResolvedAt = now;
                await live.AlertAsync(stale, device);
            }
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Opens an event-style alert (one per rule of that type) unless the same key is already open.</summary>
    public async Task RaiseAsync(Device device, string type, string key, string title, string detail, CancellationToken ct)
    {
        var rules = await db.AlertRules.Where(r => r.PartnerId == device.PartnerId && r.Enabled && r.Type == type && (r.OrganizationId == null || r.OrganizationId == device.OrganizationId)).ToListAsync(ct);
        var now = clock.GetUtcNow();
        foreach (var rule in rules)
        {
            var dedup = $"{rule.Id:N}:{key}";
            if (!await db.Alerts.AnyAsync(a => a.DeviceId == device.Id && a.DedupKey == dedup && a.State != AlertState.Resolved, ct))
            {
                await OpenAsync(device, rule, dedup, title, detail, now, ct);
            }
        }
        await db.SaveChangesAsync(ct);
    }

    private async Task OpenAsync(Device device, AlertRule rule, string key, string title, string detail, DateTimeOffset now, CancellationToken ct)
    {
        var alert = new Alert
        {
            Id = Guid.NewGuid(), PartnerId = device.PartnerId, OrganizationId = device.OrganizationId, DeviceId = device.Id, RuleId = rule.Id, Type = rule.Type,
            Severity = rule.Severity, Title = title.Length > 300 ? title[..300] : title, Detail = detail.Length > 2000 ? detail[..2000] : detail, DedupKey = key,
            State = AlertState.Open, OpenedAt = now, NotifiedAt = rule.ChannelIds.Length > 0 ? now : null,
        };
        db.Alerts.Add(alert);
        var payload = new
        {
            type = "alert.opened", title = alert.Title, text = $"{alert.Detail}\nSeverity: {alert.Severity}\nDevice: {device.Hostname}", alertId = alert.Id, alertType = alert.Type, severity = alert.Severity,
            deviceId = device.Id, hostname = device.Hostname, organizationId = device.OrganizationId, openedAt = now,
        };
        notifications.Enqueue(device.PartnerId, rule.ChannelIds, "alert.opened", payload);
        await notifications.PublishEventAsync(device.PartnerId, device.OrganizationId, "alert.opened", payload, ct);
        await audit.WriteAsync(device.PartnerId, new AuditEntry("alert.open", OrganizationId: device.OrganizationId, DeviceId: device.Id, TargetType: "alert", TargetId: alert.Id.ToString(),
            Detail: new { alert.Type, alert.Severity, alert.Title }, ActorType: "system", ActorName: "alert-engine"), ct);
        await live.AlertAsync(alert, device);
    }
}

/// <summary>Re-evaluates time-based conditions (offline) and anything that changed without an agent report.</summary>
public sealed class AlertMonitor(IServiceScopeFactory scopes, ILogger<AlertMonitor> log) : PeriodicService(scopes, log, TimeSpan.FromSeconds(60))
{
    protected override Task TickAsync(IServiceProvider sp, CancellationToken ct) => SweepAsync(sp, ct);

    public static async Task SweepAsync(IServiceProvider sp, CancellationToken ct)
    {
        var db = sp.GetRequiredService<DranzoDbContext>();
        var engine = sp.GetRequiredService<AlertEngine>();
        // Offline devices, plus devices that currently have an open alert (so recovered conditions close).
        var ids = await db.Devices.Where(d => d.Status == DeviceStatus.Active && !d.IsOnline).Select(d => d.Id)
            .Union(db.Alerts.Where(a => a.State != AlertState.Resolved).Select(a => a.DeviceId)).Take(20_000).ToListAsync(ct);
        foreach (var id in ids)
        {
            await engine.EvaluateDeviceAsync(id, ct);
        }
    }
}
