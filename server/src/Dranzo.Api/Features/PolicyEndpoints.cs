using System.Text.Json;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Jobs;
using Dranzo.Api.Services;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

public static class PolicyChecks
{
    public const string Script = "script";
    public const string UnsupportedPrefix = "not supported on this OS";

    /// <summary>Built-in checks and the operating systems they exist on.</summary>
    public static readonly IReadOnlyDictionary<string, string[]> Os = new Dictionary<string, string[]>
    {
        ["firewall.enabled"] = ["windows", "macos", "linux"],
        ["antivirus.enabled"] = ["windows", "macos", "linux"],
        ["screenlock.timeout"] = ["windows", "macos", "linux"],
        ["localadmins.allowed"] = ["windows", "macos", "linux"],
        ["usb.storage.blocked"] = ["windows"],
        ["password.policy"] = ["windows"],
        ["diskencryption.enabled"] = ["windows", "macos", "linux"],
        [Script] = ["windows", "macos", "linux"],
    };

    public static string? ValidateParams(string check, JsonElement p)
    {
        if (p.ValueKind != JsonValueKind.Object || p.GetRawText().Length > 1_200_000)
        {
            return "params must be a JSON object.";
        }
        switch (check)
        {
            case "screenlock.timeout":
                return p.TryGetProperty("maxSeconds", out var s) && s.TryGetInt32(out var sec) && sec is >= 30 and <= 86400 ? null : "params.maxSeconds must be 30..86400.";
            case "localadmins.allowed":
                return p.TryGetProperty("allowed", out var a) && a.ValueKind == JsonValueKind.Array && a.GetArrayLength() <= 100
                    && a.EnumerateArray().All(x => x.ValueKind == JsonValueKind.String && x.GetString() is { Length: > 0 and <= 128 } n && !n.Any(char.IsControl))
                    ? null : "params.allowed must be a list of up to 100 account names.";
            case "password.policy":
                return (!p.TryGetProperty("minLength", out var ml) || (ml.TryGetInt32(out var m) && m is >= 0 and <= 128))
                    && (!p.TryGetProperty("maxAgeDays", out var ma) || (ma.TryGetInt32(out var d) && d is >= 0 and <= 999))
                    ? null : "params.minLength must be 0..128 and maxAgeDays 0..999.";
            case Script:
                if (!p.TryGetProperty("language", out var lang) || !ScriptEndpoints.LanguageOs.ContainsKey(lang.GetString() ?? ""))
                {
                    return "params.language is required.";
                }
                if (!p.TryGetProperty("checkScript", out var cs) || cs.GetString() is not { Length: > 0 and <= ScriptEndpoints.MaxBodyChars })
                {
                    return "params.checkScript is required.";
                }
                return p.TryGetProperty("remediationScript", out var rs) && rs.ValueKind != JsonValueKind.Null && rs.GetString() is not { Length: <= ScriptEndpoints.MaxBodyChars }
                    ? "params.remediationScript is too long." : null;
            default:
                return null;
        }
    }
}

/// <summary>Stores compliance results from <c>policy.evaluate</c> and raises drift alerts.</summary>
public sealed class PolicyResultHandler(DranzoDbContext db, AlertEngine alerts, TimeProvider clock) : IJobResultHandler
{
    public bool Handles(string kind) => kind == JobKinds.PolicyEvaluate;

    public async Task HandleAsync(JobRun run, Device device, JsonElement result, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        // Only policies that were actually sent in this run may be reported on.
        var sent = JsonDocument.Parse(run.SpecJson).RootElement.Arr("checks", 500).Select(c => c.GuidOrNull("policyId")).Where(g => g is not null).Select(g => g!.Value).ToHashSet();
        var existing = await db.ComplianceResults.Where(r => r.DeviceId == device.Id && sent.Contains(r.PolicyId)).ToListAsync(ct);
        foreach (var item in result.Arr("results", 500))
        {
            if (item.GuidOrNull("policyId") is not { } policyId || !sent.Contains(policyId))
            {
                continue;
            }
            var detail = item.Str("detail", 2000);
            var supported = !detail.StartsWith(PolicyChecks.UnsupportedPrefix, StringComparison.OrdinalIgnoreCase);
            var compliant = supported && item.Bool("compliant");
            var row = existing.FirstOrDefault(r => r.PolicyId == policyId);
            if (row is null)
            {
                row = new ComplianceResult { Id = Guid.NewGuid(), PartnerId = device.PartnerId, OrganizationId = device.OrganizationId, DeviceId = device.Id, PolicyId = policyId };
                db.ComplianceResults.Add(row);
                existing.Add(row);
            }
            row.NonCompliantSince = compliant || !supported ? null : row.NonCompliantSince ?? now;
            row.Compliant = compliant;
            row.Remediated = item.Bool("remediated");
            row.Detail = detail;
            row.Supported = supported;
            row.EvaluatedAt = now;
        }
        await db.SaveChangesAsync(ct);
        await alerts.EvaluateDeviceAsync(device.Id, ct);
    }
}

/// <summary>Sends due policy checks to online devices.</summary>
public sealed class PolicyEvaluator(IServiceScopeFactory scopes, ILogger<PolicyEvaluator> log) : PeriodicService(scopes, log, TimeSpan.FromMinutes(5))
{
    protected override Task TickAsync(IServiceProvider sp, CancellationToken ct) => RunAsync(sp, null, false, ct);

    /// <summary>
    /// Builds one <c>policy.evaluate</c> job per partner for devices with due policies.
    /// <paramref name="onlyDevices"/> limits the run (manual trigger); <paramref name="force"/> ignores intervals.
    /// </summary>
    public static async Task<int> RunAsync(IServiceProvider sp, IReadOnlyCollection<Guid>? onlyDevices, bool force, CancellationToken ct, Guid? userId = null, string requestedBy = "system")
    {
        var db = sp.GetRequiredService<DranzoDbContext>();
        var jobs = sp.GetRequiredService<JobService>();
        var agents = sp.GetRequiredService<AgentRegistry>();
        var now = sp.GetRequiredService<TimeProvider>().GetUtcNow();
        var online = agents.ConnectedDeviceIds;
        var deviceIds = onlyDevices is null ? online : [.. onlyDevices];
        if (deviceIds.Count == 0)
        {
            return 0;
        }
        var devices = await db.Devices.Where(d => deviceIds.Contains(d.Id) && d.Status == DeviceStatus.Active).ToListAsync(ct);
        var total = 0;
        foreach (var partnerGroup in devices.GroupBy(d => d.PartnerId))
        {
            var policies = await db.Policies.Where(p => p.PartnerId == partnerGroup.Key && p.Enabled).ToListAsync(ct);
            if (policies.Count == 0)
            {
                continue;
            }
            var assignments = await db.PolicyAssignments.Where(a => a.PartnerId == partnerGroup.Key).ToListAsync(ct);
            var ids = partnerGroup.Select(d => d.Id).ToList();
            var last = (await db.ComplianceResults.Where(r => ids.Contains(r.DeviceId)).Select(r => new { r.DeviceId, r.PolicyId, r.EvaluatedAt }).ToListAsync(ct))
                .ToDictionary(r => (r.DeviceId, r.PolicyId), r => r.EvaluatedAt);
            var busy = (await db.JobRuns.Where(r => ids.Contains(r.DeviceId) && r.Kind == JobKinds.PolicyEvaluate
                && (r.Status == JobRunStatus.Pending || r.Status == JobRunStatus.Dispatched || r.Status == JobRunStatus.Running)).Select(r => r.DeviceId).ToListAsync(ct)).ToHashSet();
            var perDevice = new Dictionary<Guid, object>();
            foreach (var d in partnerGroup.Where(d => !busy.Contains(d.Id)))
            {
                var checks = policies.Where(p => Applies(p, d, assignments) && (force || !last.TryGetValue((d.Id, p.Id), out var at) || at.AddMinutes(p.IntervalMinutes) <= now))
                    .Select(p => new { policyId = p.Id, check = p.Check, @params = JsonSerializer.Deserialize<JsonElement>(p.ParamsJson), remediate = p.Remediate }).ToList();
                if (checks.Count > 0)
                {
                    perDevice[d.Id] = new { checks };
                }
            }
            if (perDevice.Count == 0)
            {
                continue;
            }
            var targets = partnerGroup.Where(d => perDevice.ContainsKey(d.Id)).ToList();
            await jobs.CreateAsync(new NewJob("Policy evaluation", JobKinds.PolicyEvaluate, new JobTarget(DeviceIds: [.. targets.Select(d => d.Id)]), new { }, 900,
                IsSystem: userId is null, PerDeviceSpec: perDevice, ExpiresAfter: TimeSpan.FromMinutes(30)), targets, partnerGroup.Key, userId, requestedBy, ct);
            total += targets.Count;
        }
        return total;
    }

    /// <summary>A policy applies to a device when its OS matches and an assignment covers the device.</summary>
    public static bool Applies(Policy p, Device d, IEnumerable<PolicyAssignment> assignments) =>
        (p.OsTargets.Length == 0 || p.OsTargets.Contains(d.Os)) && PolicyChecks.Os.TryGetValue(p.Check, out var os) && os.Contains(d.Os)
        && (p.OrganizationId == null || p.OrganizationId == d.OrganizationId)
        && assignments.Any(a => a.PolicyId == p.Id && a.ScopeType switch
        {
            ScopeType.Partner => true,
            ScopeType.Organization => a.ScopeId == d.OrganizationId,
            ScopeType.Site => a.ScopeId == d.SiteId,
            ScopeType.Group => d.GroupId != null && a.ScopeId == d.GroupId,
            _ => false,
        });
}

public static class PolicyEndpoints
{
    public sealed record PolicyRequest(string? Name, string? Description, string? Check, JsonElement? Params, string[]? OsTargets, bool? Remediate, bool? Enabled, int? IntervalMinutes, Guid? OrganizationId);

    public sealed record AssignRequest(string? ScopeType, Guid? ScopeId);

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/policies", async (Ctx c, CancellationToken ct) =>
        {
            var policies = await c.Db.Policies.AsNoTracking().OrderBy(p => p.Name).ToListAsync(ct);
            var ids = policies.Select(p => p.Id).ToList();
            // Policies were loaded through the tenant filter; their assignments are read by policy id inside the partner
            // and then narrowed to the ones whose target the caller can see (shared policies are assigned across clients).
            var assignments = new List<PolicyAssignment>();
            foreach (var a in await c.Db.PolicyAssignments.AsNoTracking().Where(a => ids.Contains(a.PolicyId)).ToListAsync(ct))
            {
                if (await CoversAssignmentAsync(a, c, ct))
                {
                    assignments.Add(a);
                }
            }
            return Results.Ok(new
            {
                checks = PolicyChecks.Os,
                items = policies.Select(p => new
                {
                    p.Id, p.Name, p.Description, p.Check, p.OsTargets, p.Remediate, p.Enabled, p.IntervalMinutes, p.OrganizationId, @params = JsonSerializer.Deserialize<JsonElement>(p.ParamsJson),
                    assignments = assignments.Where(a => a.PolicyId == p.Id).Select(a => new { a.Id, scopeType = a.ScopeType.ToString(), a.ScopeId }),
                }),
            });
        }).RequirePermission(Permissions.PoliciesRead);

        api.MapPost("/policies", async (PolicyRequest req, Ctx c, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
        {
            if (req.OrganizationId is { } org ? !c.Tenant.CoversOrganization(org) || !await c.Db.Organizations.AnyAsync(o => o.Id == org, ct) : !c.Tenant.AllOrgs)
            {
                return req.OrganizationId is null ? Api.Error(403, "forbidden", "Shared policies need partner-wide scope; set organizationId.") : Api.NotFound();
            }
            var policy = new Policy { Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = req.OrganizationId, Name = "", Check = "", CreatedAt = c.Now };
            if (Apply(policy, req, creating: true) is { } problem)
            {
                return Api.BadRequest(problem);
            }
            // Script policies run arbitrary code as root/SYSTEM on a schedule: same bar as other wide actions.
            if (policy.Check == PolicyChecks.Script && !StepUp.IsFresh(c.Who, opt.Value, clock))
            {
                return StepUp.Required();
            }
            c.Db.Policies.Add(policy);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("policy.create", organizationId: policy.OrganizationId, targetType: "policy", targetId: policy.Id, detail: new { policy.Name, policy.Check, policy.Remediate, policy.OsTargets },
                contentSha256: policy.Check == PolicyChecks.Script ? Hashing.Sha256Hex(policy.ParamsJson) : null, ct: ct);
            return Results.Created($"/api/v1/policies/{policy.Id}", new { policy.Id });
        }).RequirePermission(Permissions.PoliciesManage);

        api.MapPatch("/policies/{id:guid}", async (Guid id, PolicyRequest req, Ctx c, IOptions<DranzoOptions> opt, TimeProvider clock, CancellationToken ct) =>
        {
            var policy = await c.Db.Policies.FirstOrDefaultAsync(p => p.Id == id, ct);
            if (policy is null || (policy.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            if (Apply(policy, req, creating: false) is { } problem)
            {
                return Api.BadRequest(problem);
            }
            if (policy.Check == PolicyChecks.Script && !StepUp.IsFresh(c.Who, opt.Value, clock))
            {
                return StepUp.Required();
            }
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("policy.update", organizationId: policy.OrganizationId, targetType: "policy", targetId: id, detail: new { policy.Name, policy.Check, policy.Remediate, policy.Enabled, policy.OsTargets },
                contentSha256: policy.Check == PolicyChecks.Script ? Hashing.Sha256Hex(policy.ParamsJson) : null, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.PoliciesManage);

        api.MapDelete("/policies/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var policy = await c.Db.Policies.FirstOrDefaultAsync(p => p.Id == id, ct);
            if (policy is null || (policy.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            await c.Db.ComplianceResults.IgnoreQueryFilters().Where(r => r.PolicyId == id && r.PartnerId == c.Who.PartnerId).ExecuteDeleteAsync(ct);
            c.Db.Policies.Remove(policy);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("policy.delete", organizationId: policy.OrganizationId, targetType: "policy", targetId: id, detail: new { policy.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.PoliciesManage);

        api.MapPost("/policies/{id:guid}/assignments", async (Guid id, AssignRequest req, Ctx c, CancellationToken ct) =>
        {
            var policy = await c.Db.Policies.FirstOrDefaultAsync(p => p.Id == id, ct);
            if (policy is null)
            {
                return Api.NotFound();
            }
            if (!Enum.TryParse<ScopeType>(req.ScopeType, true, out var scopeType) || !Enum.IsDefined(scopeType) || int.TryParse(req.ScopeType, out _))
            {
                return Api.BadRequest("scopeType must be Partner, Organization, Site or Group.");
            }
            // The caller must hold policies.manage over the whole scope being assigned, and an organization-owned
            // policy can only be assigned inside its organization.
            Guid? scopeOrg = null;
            var ok = false;
            switch (scopeType)
            {
                case ScopeType.Partner:
                    ok = req.ScopeId is null && c.Tenant.AllOrgs && policy.OrganizationId is null;
                    break;
                case ScopeType.Organization:
                    scopeOrg = req.ScopeId;
                    ok = req.ScopeId is { } o && c.Tenant.CoversOrganization(o) && await c.Db.Organizations.AnyAsync(x => x.Id == o, ct);
                    break;
                case ScopeType.Site:
                    var site = req.ScopeId is { } s ? await c.Db.Sites.FirstOrDefaultAsync(x => x.Id == s, ct) : null;
                    scopeOrg = site?.OrganizationId;
                    ok = site is not null && c.Tenant.CoversSite(site.OrganizationId, site.Id);
                    break;
                case ScopeType.Group:
                    var group = req.ScopeId is { } g ? await c.Db.DeviceGroups.FirstOrDefaultAsync(x => x.Id == g, ct) : null;
                    scopeOrg = group?.OrganizationId;
                    ok = group is not null;
                    break;
            }
            if (!ok || (policy.OrganizationId is { } po && scopeOrg != po))
            {
                return Api.BadRequest("Scope target not found, or outside what this policy and your role cover.");
            }
            var a = new PolicyAssignment { Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, PolicyId = id, ScopeType = scopeType, ScopeId = req.ScopeId, CreatedAt = c.Now };
            c.Db.PolicyAssignments.Add(a);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("policy.assign", organizationId: scopeOrg, targetType: "policy", targetId: id, detail: new { policy.Name, scopeType = scopeType.ToString(), req.ScopeId }, ct: ct);
            return Results.Created($"/api/v1/policies/{id}", new { a.Id });
        }).RequirePermission(Permissions.PoliciesManage);

        api.MapDelete("/policies/{id:guid}/assignments/{assignmentId:guid}", async (Guid id, Guid assignmentId, Ctx c, CancellationToken ct) =>
        {
            var policy = await c.Db.Policies.FirstOrDefaultAsync(p => p.Id == id, ct);
            var a = policy is null ? null : await c.Db.PolicyAssignments.FirstOrDefaultAsync(x => x.Id == assignmentId && x.PolicyId == id, ct);
            if (a is null || !await CoversAssignmentAsync(a, c, ct))
            {
                return Api.NotFound();
            }
            c.Db.PolicyAssignments.Remove(a);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("policy.unassign", targetType: "policy", targetId: id, detail: new { policy!.Name, scopeType = a.ScopeType.ToString(), a.ScopeId }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.PoliciesManage);

        api.MapPost("/policies/evaluate", async (JobEndpoints.TargetRequest req, Ctx c, JobService jobs, IServiceProvider sp, CancellationToken ct) =>
        {
            var (_, devices, error) = await JobEndpoints.ResolveTargetAsync(req, c, jobs, ct);
            if (error is not null)
            {
                return error;
            }
            // Device ids were resolved inside the caller's scope; evaluation itself runs with a system context.
            await using var scope = sp.GetRequiredService<IServiceScopeFactory>().CreateAsyncScope();
            scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
            var count = await PolicyEvaluator.RunAsync(scope.ServiceProvider, [.. devices.Select(d => d.Id)], true, ct, c.Who.UserId, c.Who.Name);
            await c.Audit("policy.evaluate", targetType: "policy", detail: new { devices = count }, ct: ct);
            return Results.Ok(new { deviceCount = count });
        }).RequirePermission(Permissions.PoliciesManage);

        // ----- Compliance -----
        api.MapGet("/compliance", async (Guid? organizationId, Ctx c, CancellationToken ct) =>
        {
            var rows = await c.Db.ComplianceResults.AsNoTracking().Where(r => organizationId == null || r.OrganizationId == organizationId)
                .Select(r => new { r.PolicyId, r.DeviceId, hostname = r.Device.Hostname, r.OrganizationId, r.Compliant, r.Remediated, r.Supported, r.Detail, r.EvaluatedAt, r.NonCompliantSince }).Take(50_000).ToListAsync(ct);
            var policyIds = rows.Select(r => r.PolicyId).Distinct().ToList();
            var names = await c.Db.Policies.IgnoreQueryFilters().AsNoTracking().Where(p => p.PartnerId == c.Who.PartnerId && policyIds.Contains(p.Id)).ToDictionaryAsync(p => p.Id, p => new { p.Name, p.Check }, ct);
            var devices = rows.GroupBy(r => r.DeviceId).ToList();
            return Results.Ok(new
            {
                devices = devices.Count,
                compliantDevices = devices.Count(g => g.Where(r => r.Supported != false).All(r => r.Compliant)),
                policies = rows.GroupBy(r => r.PolicyId).Select(g => new
                {
                    policyId = g.Key, name = names.GetValueOrDefault(g.Key)?.Name, check = names.GetValueOrDefault(g.Key)?.Check,
                    compliant = g.Count(r => r.Compliant), nonCompliant = g.Count(r => !r.Compliant && r.Supported != false), unsupported = g.Count(r => r.Supported == false), remediated = g.Count(r => r.Remediated),
                }).OrderBy(p => p.name),
                nonCompliant = rows.Where(r => !r.Compliant && r.Supported != false).OrderBy(r => r.hostname)
                    .Select(r => new { r.PolicyId, policy = names.GetValueOrDefault(r.PolicyId)?.Name, r.DeviceId, r.hostname, r.OrganizationId, r.Detail, r.EvaluatedAt, r.NonCompliantSince }).Take(5000),
            });
        }).RequirePermission(Permissions.PoliciesRead);

        api.MapGet("/devices/{id:guid}/compliance", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            if (!await c.Db.Devices.AnyAsync(d => d.Id == id, ct))
            {
                return Api.NotFound();
            }
            var rows = await c.Db.ComplianceResults.AsNoTracking().Where(r => r.DeviceId == id).ToListAsync(ct);
            var ids = rows.Select(r => r.PolicyId).ToList();
            var names = await c.Db.Policies.IgnoreQueryFilters().AsNoTracking().Where(p => p.PartnerId == c.Who.PartnerId && ids.Contains(p.Id)).ToDictionaryAsync(p => p.Id, p => new { p.Name, p.Check }, ct);
            return Results.Ok(rows.Select(r => new { r.PolicyId, policy = names.GetValueOrDefault(r.PolicyId)?.Name, check = names.GetValueOrDefault(r.PolicyId)?.Check, r.Compliant, r.Remediated, r.Supported, r.Detail, r.EvaluatedAt, r.NonCompliantSince }));
        }).RequirePermission(Permissions.PoliciesRead);
    }

    /// <summary>True when the caller's policies scope covers the whole target of the assignment.</summary>
    private static async Task<bool> CoversAssignmentAsync(PolicyAssignment a, Ctx c, CancellationToken ct)
    {
        switch (a.ScopeType)
        {
            case ScopeType.Partner:
                return c.Tenant.AllOrgs;
            case ScopeType.Organization:
                return a.ScopeId is { } o && c.Tenant.CoversOrganization(o);
            case ScopeType.Site:
                var site = a.ScopeId is { } s ? await c.Db.Sites.AsNoTracking().FirstOrDefaultAsync(x => x.Id == s, ct) : null;
                return site is not null && c.Tenant.CoversSite(site.OrganizationId, site.Id);
            case ScopeType.Group:
                var group = a.ScopeId is { } g ? await c.Db.DeviceGroups.AsNoTracking().FirstOrDefaultAsync(x => x.Id == g, ct) : null;
                return group is not null && (c.Tenant.CoversSite(group.OrganizationId, group.SiteId) || c.Tenant.GroupIds.Contains(group.Id));
            default:
                return false;
        }
    }

    private static string? Apply(Policy p, PolicyRequest req, bool creating)
    {
        if (req.Name is not null || creating)
        {
            if (Api.CleanName(req.Name) is not { } name)
            {
                return "Name is required.";
            }
            p.Name = name;
        }
        if (creating)
        {
            if (req.Check is null || !PolicyChecks.Os.ContainsKey(req.Check))
            {
                return "check must be one of: " + string.Join(", ", PolicyChecks.Os.Keys);
            }
            p.Check = req.Check;
        }
        if (req.Params is { } prm)
        {
            if (PolicyChecks.ValidateParams(p.Check, prm) is { } problem)
            {
                return problem;
            }
            p.ParamsJson = prm.GetRawText();
        }
        else if (creating && PolicyChecks.ValidateParams(p.Check, JsonDocument.Parse("{}").RootElement) is { } missing)
        {
            return missing;
        }
        if (req.OsTargets is { } os)
        {
            if (os.Any(o => !PolicyChecks.Os[p.Check].Contains(o)))
            {
                return $"{p.Check} is available on: {string.Join(", ", PolicyChecks.Os[p.Check])}";
            }
            p.OsTargets = [.. os.Distinct()];
        }
        p.Description = req.Description?.Trim() is { Length: <= 1000 } d ? d : p.Description;
        p.Remediate = req.Remediate ?? p.Remediate;
        p.Enabled = req.Enabled ?? p.Enabled;
        p.IntervalMinutes = Math.Clamp(req.IntervalMinutes ?? p.IntervalMinutes, 15, 7 * 24 * 60);
        return null;
    }
}
