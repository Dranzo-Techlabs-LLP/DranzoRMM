using System.Text.Json;
using Dranzo.Api.Auth;
using Dranzo.Api.Notifications;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

public static class AlertEndpoints
{
    public sealed record RuleRequest(string? Name, string? Type, string? Severity, JsonElement? Params, bool? Enabled, Guid[]? ChannelIds, Guid? OrganizationId);

    public sealed record ChannelRequest(string? Name, string? Type, Guid? OrganizationId, bool? Enabled, string[]? To, string? Url, string? Secret, string[]? EventTypes);

    private static readonly string[] ChannelTypes = ["email", "webhook", "teams", "slack"];

    public static readonly string[] WebhookEvents = ["alert.opened", "device.enrolled", "device.offline", "job.finished", "session.started", "session.ended", "audit.integrity_failed", "test"];

    public static void Map(RouteGroupBuilder api)
    {
        // ----- Alerts -----
        api.MapGet("/alerts", async (string? state, Guid? organizationId, Guid? deviceId, string? severity, int? page, int? pageSize, Ctx c, CancellationToken ct) =>
        {
            var (skip, take, p) = Api.Paging(page, pageSize);
            var q = c.Db.Alerts.AsNoTracking().Where(a => (organizationId == null || a.OrganizationId == organizationId) && (deviceId == null || a.DeviceId == deviceId) && (severity == null || a.Severity == severity));
            if (state is not null)
            {
                if (!Enum.TryParse<AlertState>(state, true, out var st))
                {
                    return Api.BadRequest("state must be open, acknowledged or resolved.");
                }
                q = q.Where(a => a.State == st);
            }
            var total = await q.CountAsync(ct);
            var items = await q.OrderByDescending(a => a.OpenedAt).Skip(skip).Take(take).Select(a => new
            {
                a.Id, a.DeviceId, hostname = a.Device.Hostname, a.OrganizationId, a.Type, a.Severity, a.Title, a.Detail, state = a.State.ToString().ToLower(), a.OpenedAt, a.AcknowledgedAt, a.ResolvedAt, a.NotifiedAt,
            }).ToListAsync(ct);
            return Results.Ok(new { total, page = p, pageSize = take, items });
        }).RequirePermission(Permissions.AlertsRead);

        api.MapPost("/alerts/{id:guid}/acknowledge", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var a = await c.Db.Alerts.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (a is null)
            {
                return Api.NotFound();
            }
            if (a.State == AlertState.Open)
            {
                a.State = AlertState.Acknowledged;
                a.AcknowledgedAt = c.Now;
                a.AcknowledgedByUserId = c.Who.UserId;
                await c.Db.SaveChangesAsync(ct);
                await c.Audit("alert.acknowledge", organizationId: a.OrganizationId, deviceId: a.DeviceId, targetType: "alert", targetId: id, ct: ct);
            }
            return Results.NoContent();
        }).RequirePermission(Permissions.AlertsManage);

        api.MapPost("/alerts/{id:guid}/resolve", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var a = await c.Db.Alerts.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (a is null)
            {
                return Api.NotFound();
            }
            if (a.State != AlertState.Resolved)
            {
                a.State = AlertState.Resolved;
                a.ResolvedAt = c.Now;
                await c.Db.SaveChangesAsync(ct);
                await c.Audit("alert.resolve", organizationId: a.OrganizationId, deviceId: a.DeviceId, targetType: "alert", targetId: id, ct: ct);
            }
            return Results.NoContent();
        }).RequirePermission(Permissions.AlertsManage);

        // ----- Rules -----
        api.MapGet("/alert-rules", async (Ctx c, CancellationToken ct) =>
            Results.Ok((await c.Db.AlertRules.AsNoTracking().OrderBy(r => r.Name).ToListAsync(ct)).Select(r => new
            {
                r.Id, r.Name, r.Type, r.Severity, r.Enabled, r.OrganizationId, r.ChannelIds, @params = JsonSerializer.Deserialize<JsonElement>(r.ParamsJson),
            })))
            .RequirePermission(Permissions.AlertsRead);

        api.MapGet("/alert-rules/types", () => Results.Ok(new { types = AlertTypes.All, severities = AlertTypes.Severities, webhookEvents = WebhookEvents }))
            .RequirePermission(Permissions.AlertsRead);

        api.MapPost("/alert-rules", async (RuleRequest req, Ctx c, CancellationToken ct) =>
        {
            if (req.OrganizationId is { } org ? !c.Tenant.CoversOrganization(org) || !await c.Db.Organizations.AnyAsync(o => o.Id == org, ct) : !c.Tenant.AllOrgs)
            {
                return req.OrganizationId is null ? Api.Error(403, "forbidden", "Shared alert rules need partner-wide scope; set organizationId.") : Api.NotFound();
            }
            var rule = new AlertRule { Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = req.OrganizationId, Name = "", Type = "", CreatedAt = c.Now };
            if (await ApplyRuleAsync(rule, req, c, true, ct) is { } problem)
            {
                return Api.BadRequest(problem);
            }
            c.Db.AlertRules.Add(rule);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("alert_rule.create", organizationId: rule.OrganizationId, targetType: "alert_rule", targetId: rule.Id, detail: new { rule.Name, rule.Type, rule.Severity }, ct: ct);
            return Results.Created($"/api/v1/alert-rules/{rule.Id}", new { rule.Id });
        }).RequirePermission(Permissions.AlertsManage);

        api.MapPatch("/alert-rules/{id:guid}", async (Guid id, RuleRequest req, Ctx c, CancellationToken ct) =>
        {
            var rule = await c.Db.AlertRules.FirstOrDefaultAsync(r => r.Id == id, ct);
            if (rule is null || (rule.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            if (await ApplyRuleAsync(rule, req, c, false, ct) is { } problem)
            {
                return Api.BadRequest(problem);
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("alert_rule.update", organizationId: rule.OrganizationId, targetType: "alert_rule", targetId: id, detail: new { rule.Name, rule.Type, rule.Severity, rule.Enabled }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.AlertsManage);

        api.MapDelete("/alert-rules/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var rule = await c.Db.AlertRules.FirstOrDefaultAsync(r => r.Id == id, ct);
            if (rule is null || (rule.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            c.Db.AlertRules.Remove(rule);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("alert_rule.delete", organizationId: rule.OrganizationId, targetType: "alert_rule", targetId: id, detail: new { rule.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.AlertsManage);

        // ----- Notification channels (configuration is write-only: secrets and URLs are never returned) -----
        api.MapGet("/notification-channels", async (Ctx c, NotificationService n, CancellationToken ct) =>
            Results.Ok((await c.Db.NotificationChannels.AsNoTracking().OrderBy(x => x.Name).ToListAsync(ct)).Select(x =>
            {
                var cfg = n.Unprotect(x.ConfigProtected);
                return new
                {
                    x.Id, x.Name, x.Type, x.OrganizationId, x.Enabled, x.EventTypes, x.CreatedAt,
                    to = cfg.To, urlHost = cfg.Url is null ? null : new Uri(cfg.Url).Host, hasSecret = !string.IsNullOrEmpty(cfg.Secret),
                };
            })))
            .RequirePermission(Permissions.NotificationsManage);

        api.MapPost("/notification-channels", async (ChannelRequest req, Ctx c, NotificationService n, IOptions<NotificationOptions> nopt, CancellationToken ct) =>
        {
            if (req.OrganizationId is { } org ? !c.Tenant.CoversOrganization(org) || !await c.Db.Organizations.AnyAsync(o => o.Id == org, ct) : !c.Tenant.AllOrgs)
            {
                return req.OrganizationId is null ? Api.Error(403, "forbidden", "Shared channels need partner-wide scope; set organizationId.") : Api.NotFound();
            }
            if (Api.CleanName(req.Name) is not { } name || !ChannelTypes.Contains(req.Type))
            {
                return Api.BadRequest("name and type (email, webhook, teams, slack) are required.");
            }
            if (ValidateChannel(req.Type!, req, nopt.Value.AllowPrivateTargets) is { } problem)
            {
                return Api.BadRequest(problem);
            }
            var channel = new NotificationChannel
            {
                Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = req.OrganizationId, Name = name, Type = req.Type!, Enabled = req.Enabled ?? true,
                ConfigProtected = n.Protect(new ChannelConfig(req.To, req.Url, req.Secret)), EventTypes = req.Type == "webhook" ? [.. (req.EventTypes ?? []).Distinct()] : [], CreatedAt = c.Now,
            };
            c.Db.NotificationChannels.Add(channel);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("notification_channel.create", organizationId: channel.OrganizationId, targetType: "notification_channel", targetId: channel.Id, detail: new { name, channel.Type, channel.EventTypes }, ct: ct);
            return Results.Created($"/api/v1/notification-channels/{channel.Id}", new { channel.Id });
        }).RequirePermission(Permissions.NotificationsManage);

        api.MapPatch("/notification-channels/{id:guid}", async (Guid id, ChannelRequest req, Ctx c, NotificationService n, IOptions<NotificationOptions> nopt, CancellationToken ct) =>
        {
            var channel = await c.Db.NotificationChannels.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (channel is null || (channel.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            if (req.Name is not null)
            {
                if (Api.CleanName(req.Name) is not { } name)
                {
                    return Api.BadRequest("Invalid name.");
                }
                channel.Name = name;
            }
            if (req.To is not null || req.Url is not null || req.Secret is not null)
            {
                var old = n.Unprotect(channel.ConfigProtected);
                var merged = req with { To = req.To ?? old.To, Url = req.Url ?? old.Url, Secret = req.Secret ?? old.Secret };
                if (ValidateChannel(channel.Type, merged, nopt.Value.AllowPrivateTargets) is { } problem)
                {
                    return Api.BadRequest(problem);
                }
                channel.ConfigProtected = n.Protect(new ChannelConfig(merged.To, merged.Url, merged.Secret));
            }
            if (req.EventTypes is not null && channel.Type == "webhook")
            {
                if (req.EventTypes.Any(e => !WebhookEvents.Contains(e)))
                {
                    return Api.BadRequest("Unknown event type.");
                }
                channel.EventTypes = [.. req.EventTypes.Distinct()];
            }
            channel.Enabled = req.Enabled ?? channel.Enabled;
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("notification_channel.update", organizationId: channel.OrganizationId, targetType: "notification_channel", targetId: id, detail: new { channel.Name, channel.Enabled, channel.EventTypes }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.NotificationsManage);

        api.MapDelete("/notification-channels/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var channel = await c.Db.NotificationChannels.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (channel is null || (channel.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            c.Db.NotificationChannels.Remove(channel);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("notification_channel.delete", organizationId: channel.OrganizationId, targetType: "notification_channel", targetId: id, detail: new { channel.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.NotificationsManage);

        api.MapPost("/notification-channels/{id:guid}/test", async (Guid id, Ctx c, NotificationService n, CancellationToken ct) =>
        {
            var channel = await c.Db.NotificationChannels.FirstOrDefaultAsync(x => x.Id == id, ct);
            if (channel is null)
            {
                return Api.NotFound();
            }
            n.Enqueue(channel.PartnerId, [channel.Id], "test", new { type = "test", title = "DranzoRMM test notification", text = $"Channel '{channel.Name}' is working. Sent by {c.Who.Name}." });
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("notification_channel.test", organizationId: channel.OrganizationId, targetType: "notification_channel", targetId: id, ct: ct);
            return Results.Accepted();
        }).RequirePermission(Permissions.NotificationsManage);

        api.MapGet("/notification-channels/{id:guid}/deliveries", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            if (!await c.Db.NotificationChannels.AnyAsync(x => x.Id == id, ct))
            {
                return Api.NotFound();
            }
            // The channel was loaded through the tenant filter; deliveries are keyed by it.
            return Results.Ok(await c.Db.WebhookDeliveries.IgnoreQueryFilters().AsNoTracking().Where(d => d.ChannelId == id && d.PartnerId == c.Who.PartnerId)
                .OrderByDescending(d => d.CreatedAt).Take(50).Select(d => new { d.Id, d.EventType, d.CreatedAt, d.DeliveredAt, d.Attempts, d.LastError }).ToListAsync(ct));
        }).RequirePermission(Permissions.NotificationsManage);
    }

    private static string? ValidateChannel(string type, ChannelRequest req, bool allowPrivate)
    {
        if (type == "email")
        {
            return req.To is { Length: > 0 and <= 20 } && req.To.All(t => t is { Length: > 2 and <= 254 } && t.Contains('@') && !t.Any(char.IsWhiteSpace) && !t.Contains(','))
                ? null : "to: 1 to 20 email addresses are required.";
        }
        if ((req.Secret?.Length ?? 0) > 256)
        {
            return "secret is too long.";
        }
        if (req.EventTypes is not null && req.EventTypes.Any(e => !WebhookEvents.Contains(e)))
        {
            return "Unknown event type.";
        }
        return SafeOutbound.ValidateUrl(req.Url, allowPrivate);
    }

    private static async Task<string?> ApplyRuleAsync(AlertRule rule, RuleRequest req, Ctx c, bool creating, CancellationToken ct)
    {
        if (req.Name is not null || creating)
        {
            if (Api.CleanName(req.Name) is not { } name)
            {
                return "Name is required.";
            }
            rule.Name = name;
        }
        if (creating)
        {
            if (!AlertTypes.All.Contains(req.Type))
            {
                return "type must be one of: " + string.Join(", ", AlertTypes.All);
            }
            rule.Type = req.Type!;
        }
        if (req.Severity is not null)
        {
            if (!AlertTypes.Severities.Contains(req.Severity))
            {
                return "severity must be info, warning or critical.";
            }
            rule.Severity = req.Severity;
        }
        if (req.Params is { } p)
        {
            if (p.ValueKind != JsonValueKind.Object || p.GetRawText().Length > 2000)
            {
                return "params must be a small JSON object.";
            }
            rule.ParamsJson = p.GetRawText();
        }
        if (req.ChannelIds is not null)
        {
            // Only channels the caller can see (same partner, in scope) may be attached.
            var visible = await c.Db.NotificationChannels.Where(x => req.ChannelIds.Contains(x.Id)).Select(x => x.Id).ToListAsync(ct);
            if (visible.Count != req.ChannelIds.Distinct().Count())
            {
                return "Unknown notification channel.";
            }
            rule.ChannelIds = [.. visible];
        }
        rule.Enabled = req.Enabled ?? rule.Enabled;
        return null;
    }
}
