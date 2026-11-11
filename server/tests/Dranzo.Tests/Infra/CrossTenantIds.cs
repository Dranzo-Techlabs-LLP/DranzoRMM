using Microsoft.EntityFrameworkCore;

namespace Dranzo.Tests.Infra;

/// <summary>
/// One resource of every routable kind inside "organization B", used by the generated cross-tenant test.
/// When a new route family is added, seed a B resource here and map its first path segment.
/// </summary>
public sealed class CrossTenantIds
{
    private readonly Dictionary<string, Guid> _bySegment = [];

    public List<string> Markers { get; } = [];

    public Guid For(string routeTemplate)
    {
        // /api/v1/{segment}/...
        var segment = routeTemplate.Split('/', StringSplitOptions.RemoveEmptyEntries)[2];
        return _bySegment[segment];
    }

    public void Map(string segment, Guid id, bool leakMarker = true)
    {
        _bySegment[segment] = id;
        if (leakMarker)
        {
            Markers.Add(id.ToString());
        }
    }

    public static async Task<CrossTenantIds> SeedAsync(ServerFixture fx, ServerFixture.OrgSeed b, Guid deviceB)
    {
        var ids = new CrossTenantIds();
        ids.Markers.AddRange(["xb-secret", "XB-SECRET"]);
        ids.Map("organizations", b.OrgId);
        ids.Map("sites", b.SiteId);
        ids.Map("groups", b.GroupId);
        ids.Map("devices", deviceB);
        var tokenId = await fx.DbAsync(db => db.EnrollmentTokens.Where(t => t.OrganizationId == b.OrgId).Select(t => t.Id).FirstAsync());
        ids.Map("enrollment-tokens", tokenId);
        // Partner-level families: an org-scoped caller gets 403 before any id is looked at.
        ids.Map("users", Guid.NewGuid(), leakMarker: false);
        ids.Map("roles", Guid.NewGuid(), leakMarker: false);
        ids.Map("role-assignments", Guid.NewGuid(), leakMarker: false);
        await CrossTenantSeedExtensions.SeedLaterPhasesAsync(fx, ids, b, deviceB);
        return ids;
    }
}

public static partial class CrossTenantSeedExtensions
{
    public static async Task SeedLaterPhasesAsync(ServerFixture fx, CrossTenantIds ids, ServerFixture.OrgSeed b, Guid deviceB)
    {
        var admin = await fx.AdminAsync();
        // Phase 2: a script, a job with a run, and a saved filter that all belong to organization B.
        var script = await admin.PostJsonAsync("/api/v1/scripts", new { name = "xb-secret script", language = "sh", body = "echo xb-secret", organizationId = b.OrgId });
        ids.Map("scripts", script.GetProperty("id").GetGuid());
        var job = await admin.PostJsonAsync("/api/v1/jobs/run-script", new { scriptId = script.GetProperty("id").GetGuid(), target = new { deviceIds = new[] { deviceB } } });
        ids.Map("jobs", job.GetProperty("jobId").GetGuid());
        ids.Map("runs", job.GetProperty("runs")[0].GetProperty("id").GetGuid());
        var filter = await admin.PostJsonAsync("/api/v1/saved-filters", new { name = "xb-secret filter", organizationId = b.OrgId, filter = new { os = "linux" } });
        ids.Map("saved-filters", filter.GetProperty("id").GetGuid());
        // Phase 3: a package owned by organization B.
        var upload = await admin.SendAsync(HttpMethod.Put, "/api/v1/packages/upload?fileName=xb-secret.deb", new ByteArrayContent([1, 2, 3, 4]));
        var blobId = (await System.Net.Http.Json.HttpContentJsonExtensions.ReadFromJsonAsync<System.Text.Json.JsonElement>(upload.Content)).GetProperty("blobId").GetGuid();
        var package = await admin.PostJsonAsync("/api/v1/packages", new { name = "xb-secret package", type = "deb", blobId, organizationId = b.OrgId, uninstallCommand = new[] { "apt-get", "remove", "-y", "x" } });
        ids.Map("packages", package.GetProperty("id").GetGuid());
        // Phase 4: a patch policy for organization B ("/patches" has list routes only).
        var patchPolicy = await admin.PostJsonAsync("/api/v1/patch-policies", new { name = "xb-secret patch policy", organizationId = b.OrgId });
        ids.Map("patch-policies", patchPolicy.GetProperty("id").GetGuid());
        // Phase 5: an alert, an alert rule and a notification channel in organization B.
        var channel = await admin.PostJsonAsync("/api/v1/notification-channels", new { name = "xb-secret channel", type = "slack", url = "https://hooks.example.test/xb-secret", organizationId = b.OrgId });
        ids.Map("notification-channels", channel.GetProperty("id").GetGuid());
        var rule = await admin.PostJsonAsync("/api/v1/alert-rules", new { name = "xb-secret rule", type = "firewall.off", organizationId = b.OrgId });
        ids.Map("alert-rules", rule.GetProperty("id").GetGuid());
        var alertId = Guid.NewGuid();
        await fx.DbAsync(async db =>
        {
            var d = await db.Devices.FirstAsync(x => x.Id == deviceB);
            db.Alerts.Add(new Dranzo.Domain.Alert { Id = alertId, PartnerId = d.PartnerId, OrganizationId = d.OrganizationId, DeviceId = d.Id, Type = "firewall.off", Title = "xb-secret alert", DedupKey = "x", OpenedAt = DateTimeOffset.UtcNow });
            await db.SaveChangesAsync();
        });
        ids.Map("alerts", alertId);
        // Phase 6: a remote session on organization B's device.
        var sessionId = Guid.NewGuid();
        await fx.DbAsync(async db =>
        {
            var d = await db.Devices.FirstAsync(x => x.Id == deviceB);
            db.RemoteSessions.Add(new Dranzo.Domain.RemoteSession { Id = sessionId, PartnerId = d.PartnerId, OrganizationId = d.OrganizationId, DeviceId = d.Id, UserId = Guid.NewGuid(), UserName = "xb-secret tech", Kind = "terminal", RequestedAt = DateTimeOffset.UtcNow, State = Dranzo.Domain.RemoteSessionState.Ended });
            await db.SaveChangesAsync();
        });
        ids.Map("sessions", sessionId);
        // Phase 7: a policy owned by organization B.
        var policy = await admin.PostJsonAsync("/api/v1/policies", new { name = "xb-secret policy", check = "firewall.enabled", organizationId = b.OrgId });
        ids.Map("policies", policy.GetProperty("id").GetGuid());
        ids.Map("compliance", Guid.NewGuid(), leakMarker: false);
        // Phase 8: partner-level families and list/report routes.
        ids.Map("releases", Guid.NewGuid(), leakMarker: false);
        ids.Map("api-keys", Guid.NewGuid(), leakMarker: false);
        ids.Map("reports", Guid.NewGuid(), leakMarker: false);
        ids.Map("overview", Guid.NewGuid(), leakMarker: false);
        ids.Map("security", Guid.NewGuid(), leakMarker: false);
        ids.Map("vulnerabilities", Guid.NewGuid(), leakMarker: false);
        ids.Map("patches", Guid.NewGuid(), leakMarker: false);
        ids.Map("software", Guid.NewGuid(), leakMarker: false);
        ids.Map("schedules", Guid.NewGuid(), leakMarker: false);
        ids.Map("audit", Guid.NewGuid(), leakMarker: false);
        ids.Map("agent", Guid.NewGuid(), leakMarker: false);
    }
}
