using System.Text.Json;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Jobs;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

/// <summary>Records the isolation state when network.isolate / network.release succeed on the device.</summary>
public sealed class IsolationResultHandler(DranzoDbContext db, TimeProvider clock) : IJobResultHandler
{
    public bool Handles(string kind) => kind is JobKinds.NetworkIsolate or JobKinds.NetworkRelease;

    public async Task HandleAsync(JobRun run, Device device, JsonElement result, CancellationToken ct)
    {
        if (run.Status != JobRunStatus.Succeeded)
        {
            return;
        }
        var job = await db.Jobs.IgnoreQueryFilters().AsNoTracking().FirstAsync(j => j.Id == run.JobId && j.PartnerId == device.PartnerId, ct);
        if (run.Kind == JobKinds.NetworkIsolate)
        {
            var reason = JsonSerializer.Deserialize<JsonElement>(job.SpecJson).Str("reason", 500);
            await db.Devices.IgnoreQueryFilters().Where(d => d.Id == device.Id && d.PartnerId == device.PartnerId)
                .ExecuteUpdateAsync(s => s.SetProperty(d => d.IsolatedAt, clock.GetUtcNow()).SetProperty(d => d.IsolatedBy, job.RequestedByName).SetProperty(d => d.IsolationReason, reason), ct);
        }
        else
        {
            await db.Devices.IgnoreQueryFilters().Where(d => d.Id == device.Id && d.PartnerId == device.PartnerId)
                .ExecuteUpdateAsync(s => s.SetProperty(d => d.IsolatedAt, (DateTimeOffset?)null).SetProperty(d => d.IsolatedBy, (string?)null).SetProperty(d => d.IsolationReason, (string?)null), ct);
        }
    }
}

public static class IsolationEndpoints
{
    public sealed record IsolateRequest(string? Reason, string? Message);

    private static string? CleanText(string? s, int max) =>
        string.IsNullOrWhiteSpace(s) ? null : new string([.. s.Trim().Select(ch => char.IsControl(ch) ? ' ' : ch)]) is { } t && t.Length <= max ? t : null;

    public static void Map(RouteGroupBuilder api)
    {
        api.MapPost("/devices/{id:guid}/isolate", async (Guid id, IsolateRequest req, Ctx c, JobService jobs, IOptions<DranzoOptions> opt, CancellationToken ct) =>
        {
            var device = await c.Db.Devices.FirstOrDefaultAsync(d => d.Id == id, ct);
            if (device is null)
            {
                return Api.NotFound();
            }
            if (device.Status != DeviceStatus.Active)
            {
                return Api.Conflict("This device is revoked.");
            }
            if (CleanText(req.Reason, 500) is not { } reason)
            {
                return Api.BadRequest("Give a reason of up to 500 characters (it is recorded in the audit log).");
            }
            if (req.Message is { Length: > 0 } && CleanText(req.Message, 512) is null)
            {
                return Api.BadRequest("The message to the user is limited to 512 characters.");
            }
            // Keep remote desktop working while isolated, so the device can still be investigated.
            var allow = new List<object>();
            if (Uri.TryCreate(opt.Value.Mesh.Url, UriKind.Absolute, out var mesh) && mesh.Scheme == Uri.UriSchemeHttps)
            {
                allow.Add(new { host = mesh.Host, port = mesh.Port });
            }
            var created = await jobs.CreateAsync(new NewJob("Isolate from the network", JobKinds.NetworkIsolate, new JobTarget(DeviceIds: [id]),
                new { allow, message = CleanText(req.Message, 512), reason }, 300), [device], c.Who.PartnerId, c.Who.UserId, c.Who.Name, ct);
            await c.Audit("device.isolate", organizationId: device.OrganizationId, deviceId: id, targetType: "job", targetId: created.Job.Id, detail: new { reason }, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id });
        }).RequirePermission(Permissions.DevicesIsolate).RequireStepUp();

        api.MapPost("/devices/{id:guid}/release", async (Guid id, IsolateRequest req, Ctx c, JobService jobs, CancellationToken ct) =>
        {
            var device = await c.Db.Devices.FirstOrDefaultAsync(d => d.Id == id, ct);
            if (device is null)
            {
                return Api.NotFound();
            }
            if (device.Status != DeviceStatus.Active)
            {
                return Api.Conflict("This device is revoked.");
            }
            var reason = CleanText(req.Reason, 500);
            var created = await jobs.CreateAsync(new NewJob("Release network isolation", JobKinds.NetworkRelease, new JobTarget(DeviceIds: [id]),
                new { message = CleanText(req.Message, 512) }, 300), [device], c.Who.PartnerId, c.Who.UserId, c.Who.Name, ct);
            await c.Audit("device.release", organizationId: device.OrganizationId, deviceId: id, targetType: "job", targetId: created.Job.Id, detail: new { reason }, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id });
        }).RequirePermission(Permissions.DevicesIsolate).RequireStepUp();
    }
}
