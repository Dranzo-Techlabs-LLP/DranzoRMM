using System.Text.Json;
using System.Text.Json.Nodes;
using Dranzo.Api.Features;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Jobs;

/// <summary>Which devices a job applies to. Exactly one selector is used, in this order of precedence.</summary>
public sealed record JobTarget(Guid[]? DeviceIds = null, Guid? GroupId = null, Guid? SiteId = null, Guid? OrganizationId = null, DeviceFilter? Filter = null)
{
    public bool IsExplicit => DeviceIds is { Length: > 0 };

    /// <summary>True when the selector means "every device of an organization" (or wider).</summary>
    public bool IsWholeOrganizationOrWider => !IsExplicit && GroupId is null && SiteId is null
        && (Filter is null || (Filter.SiteId is null && Filter.GroupId is null && Filter.Os is null && Filter.Online is null && string.IsNullOrWhiteSpace(Filter.Search) && string.IsNullOrWhiteSpace(Filter.Tag)));

    public IQueryable<Device> Apply(IQueryable<Device> devices)
    {
        devices = devices.Where(d => d.Status == DeviceStatus.Active);
        if (IsExplicit)
        {
            return devices.Where(d => DeviceIds!.Contains(d.Id));
        }
        if (GroupId is { } g)
        {
            return devices.Where(d => d.GroupId == g);
        }
        if (SiteId is { } s)
        {
            return devices.Where(d => d.SiteId == s);
        }
        if (Filter is not null)
        {
            var f = OrganizationId is { } forced ? Filter with { OrganizationId = forced } : Filter;
            return f.Apply(devices);
        }
        if (OrganizationId is { } o)
        {
            return devices.Where(d => d.OrganizationId == o);
        }
        return devices.Where(_ => false);
    }
}

public sealed record NewJob(
    string Name,
    string Kind,
    JobTarget Target,
    object Spec,
    int TimeoutSeconds = 300,
    int MaxOutputBytes = 1_048_576,
    int MaxAttempts = 1,
    int MaxParallel = 0,
    string? Cron = null,
    string? TimeZone = null,
    Guid? ScriptId = null,
    int? ScriptVersion = null,
    string ContentSha256 = "",
    bool IsSystem = false,
    Guid? SessionId = null,
    DateTimeOffset? NotBefore = null,
    /// <summary>Pending runs are dropped after this long (default: the configured pending-run expiry).</summary>
    TimeSpan? ExpiresAfter = null,
    /// <summary>Per-device spec overrides (device id → spec object); used by policy evaluation.</summary>
    IReadOnlyDictionary<Guid, object>? PerDeviceSpec = null);

public sealed record JobCreated(Job Job, List<JobRun> Runs);

/// <summary>Creates jobs and their per-device runs. Device resolution always goes through the caller's (filtered) context.</summary>
public sealed class JobService(DranzoDbContext db, JobDispatcher dispatcher, IOptions<DranzoOptions> options, TimeProvider clock)
{
    public static readonly JsonSerializerOptions Json = AgentJson.Options;

    /// <summary>Resolves the target inside the current tenant scope.</summary>
    public Task<List<Device>> ResolveAsync(JobTarget target, CancellationToken ct) => target.Apply(db.Devices).OrderBy(d => d.Hostname).Take(50_000).ToListAsync(ct);

    public async Task<JobCreated> CreateAsync(NewJob request, IReadOnlyList<Device> devices, Guid partnerId, Guid? requestedByUserId, string requestedByName, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var orgIds = devices.Select(d => d.OrganizationId).Distinct().ToList();
        var job = new Job
        {
            Id = Guid.NewGuid(), PartnerId = partnerId,
            OrganizationId = request.Target.OrganizationId ?? (orgIds.Count == 1 ? orgIds[0] : null),
            Name = request.Name, Kind = request.Kind, SpecJson = JsonSerializer.Serialize(request.Spec, Json),
            TargetJson = JsonSerializer.Serialize(request.Target, Json), Cron = request.Cron, TimeZone = request.TimeZone,
            RequestedByUserId = requestedByUserId, RequestedByName = requestedByName, CreatedAt = now,
            TimeoutSeconds = Math.Clamp(request.TimeoutSeconds, 5, 24 * 3600), MaxOutputBytes = Math.Clamp(request.MaxOutputBytes, 1024, 16 * 1024 * 1024),
            MaxAttempts = Math.Clamp(request.MaxAttempts, 1, 5), MaxParallel = Math.Max(0, request.MaxParallel),
            ScriptId = request.ScriptId, ScriptVersion = request.ScriptVersion, ContentSha256 = request.ContentSha256, IsSystem = request.IsSystem,
        };
        db.Jobs.Add(job);
        var runs = new List<JobRun>();
        if (request.Cron is null)
        {
            runs = AddRuns(job, devices, request.SessionId, request.NotBefore, request.PerDeviceSpec, request.ExpiresAfter);
        }
        else
        {
            job.NextRunAt = Scheduler.NextOccurrence(request.Cron, request.TimeZone ?? "UTC", now);
        }
        await db.SaveChangesAsync(ct);
        foreach (var run in runs)
        {
            dispatcher.Kick(run.DeviceId);
        }
        return new JobCreated(job, runs);
    }

    public List<JobRun> AddRuns(Job job, IReadOnlyList<Device> devices, Guid? sessionId = null, DateTimeOffset? notBefore = null, IReadOnlyDictionary<Guid, object>? perDeviceSpec = null, TimeSpan? expiresAfter = null)
    {
        var now = clock.GetUtcNow();
        var batch = Guid.NewGuid();
        var runs = devices.Select(d => new JobRun
        {
            Id = Guid.NewGuid(), PartnerId = d.PartnerId, OrganizationId = d.OrganizationId, DeviceId = d.Id, JobId = job.Id, BatchId = batch,
            Kind = job.Kind, Status = JobRunStatus.Pending, CreatedAt = now, NotBefore = notBefore,
            SpecJson = perDeviceSpec is not null && perDeviceSpec.TryGetValue(d.Id, out var spec) ? JsonSerializer.Serialize(spec, Json) : "{}",
            ExpiresAt = (notBefore ?? now).Add(expiresAfter ?? TimeSpan.FromHours(options.Value.Agents.PendingRunExpiryHours)),
            Attempt = 1, MaxAttempts = job.MaxAttempts, TimeoutSeconds = job.TimeoutSeconds, MaxOutputBytes = job.MaxOutputBytes, SessionId = sessionId,
        }).ToList();
        db.JobRuns.AddRange(runs);
        return runs;
    }

    /// <summary>
    /// Builds the wire <c>spec</c> for one device at dispatch time. Returns null with a reason when the job
    /// does not apply to the device (reported as an <c>Unsupported</c> run).
    /// </summary>
    /// <summary>apt for Debian-family, dnf for Red Hat-family distributions; null when unknown.</summary>
    public static string? LinuxPackageManager(string osName)
    {
        var n = osName.ToLowerInvariant();
        if (new[] { "ubuntu", "debian", "mint", "pop!_os", "raspbian", "kali" }.Any(n.Contains))
        {
            return "apt";
        }
        return new[] { "red hat", "rhel", "rocky", "alma", "fedora", "centos", "oracle", "amazon" }.Any(n.Contains) ? "dnf" : null;
    }

    public static (JsonNode? Spec, string? Unsupported) BuildWireSpec(Job job, JobRun run, Device device, Organization? org)
    {
        var source = run.SpecJson is { Length: > 2 } ? run.SpecJson : job.SpecJson;
        var spec = JsonNode.Parse(source)!.AsObject();
        if (job.Kind == JobKinds.Script)
        {
            var osTargets = spec["osTargets"]?.AsArray().Select(x => x!.GetValue<string>()).ToArray() ?? [];
            if (osTargets.Length > 0 && !osTargets.Contains(device.Os))
            {
                return (null, $"Script does not target {device.Os}.");
            }
            var language = spec["language"]?.GetValue<string>() ?? "";
            spec["requireSignedPowerShell"] = language == "powershell" && (org?.RequireSignedPowerShell ?? false);
            spec.Remove("osTargets");
            spec.Remove("scriptId");
            spec.Remove("version");
        }
        else if (job.Kind is JobKinds.SoftwareInstall or JobKinds.SoftwareUninstall)
        {
            // The job carries one package id per package manager; pick the one for this device.
            var manager = device.Os switch
            {
                "windows" => "winget",
                "macos" => "brew",
                "linux" => LinuxPackageManager(device.OsName),
                _ => null,
            };
            var id = manager is null ? null : spec["packages"]?[manager]?.GetValue<string>();
            if (string.IsNullOrEmpty(id))
            {
                return (null, manager is null ? $"Could not determine the package manager for '{device.OsName}'." : $"No {manager} package id was given for this software.");
            }
            spec = new JsonObject { ["manager"] = manager, ["packageId"] = id, ["version"] = spec["version"]?.DeepClone() };
        }
        else if (spec["os"] is JsonValue osValue && osValue.TryGetValue<string>(out var os) && os.Length > 0)
        {
            if (os != device.Os)
            {
                return (null, $"Not applicable to {device.Os}.");
            }
            spec.Remove("os");
        }
        if (device.Capabilities.Length > 0 && !device.Capabilities.Contains(job.Kind))
        {
            return (null, $"The agent on this device does not support '{job.Kind}'.");
        }
        return (spec, null);
    }
}
