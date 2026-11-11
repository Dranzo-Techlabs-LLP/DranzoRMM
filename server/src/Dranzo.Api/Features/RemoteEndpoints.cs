using System.Text.Json;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Jobs;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Storage;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

public static class RemoteEndpoints
{
    public sealed record TerminalRequest(int? Cols, int? Rows, string? RunAs);

    public sealed record PathRequest(string? Path);

    public sealed record MeshOrgRequest(string? MeshUser, string? MeshGroupId);

    private static async Task<IResult> StartAsync(Guid deviceId, string kind, object? extra, Ctx c, RemoteSessionService sessions, CancellationToken ct)
    {
        var device = await c.Db.Devices.AsNoTracking().FirstOrDefaultAsync(d => d.Id == deviceId && d.Status == DeviceStatus.Active, ct);
        if (device is null)
        {
            return Api.NotFound();
        }
        // The device was loaded through the tenant filter; its organization row is fetched by id inside the same partner.
        var org = await c.Db.Organizations.IgnoreQueryFilters().AsNoTracking().FirstAsync(o => o.Id == device.OrganizationId && o.PartnerId == c.Who.PartnerId, ct);
        var user = await c.Db.Users.IgnoreQueryFilters().AsNoTracking().FirstAsync(u => u.Id == c.Who.UserId, ct);
        var partner = await c.Db.Partners.IgnoreQueryFilters().AsNoTracking().FirstAsync(p => p.Id == c.Who.PartnerId, ct);
        var (session, error) = await sessions.StartAsync(device, org, kind, c.Who.UserId, c.Who.Name, $"{user.DisplayName} ({partner.Name})", c.Who.Ip, extra, ct);
        return session is null
            ? Api.Conflict(error!)
            : Results.Created($"/api/v1/sessions/{session.Id}", new { sessionId = session.Id, state = "requested", consent = org.ConsentMode.ToString().ToLowerInvariant() });
    }

    /// <summary>The caller's own, active session of the given kind, loaded through the tenant filter.</summary>
    private static async Task<(RemoteSession? Session, IResult? Error)> OwnActiveAsync(Guid id, string kind, Ctx c, SessionRegistry registry, CancellationToken ct)
    {
        var session = await c.Db.RemoteSessions.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct);
        if (session is null || session.UserId != c.Who.UserId || session.Kind != kind)
        {
            return (null, Api.NotFound());
        }
        if (session.State != RemoteSessionState.Active || registry.Get(id) is not { Active: true })
        {
            return (null, Api.Conflict("The session is not active."));
        }
        return (session, null);
    }

    private static string? CleanPath(string? path) => string.IsNullOrEmpty(path) || path.Length > 4096 || path.Contains('\0') ? null : path;

    private static async Task<JobRun?> RunFileJobAsync(Ctx c, JobService jobs, RemoteSession session, string kind, object spec, string name, int waitSeconds, CancellationToken ct)
    {
        var device = await c.Db.Devices.FirstAsync(d => d.Id == session.DeviceId, ct);
        var created = await jobs.CreateAsync(new NewJob(name, kind, new JobTarget(DeviceIds: [device.Id]), spec, 300, SessionId: session.Id, ExpiresAfter: TimeSpan.FromMinutes(2)),
            [device], c.Who.PartnerId, c.Who.UserId, c.Who.Name, ct);
        var runId = created.Runs[0].Id;
        var deadline = DateTime.UtcNow.AddSeconds(waitSeconds);
        while (DateTime.UtcNow < deadline)
        {
            var run = await c.Db.JobRuns.AsNoTracking().FirstAsync(r => r.Id == runId, ct);
            if (run.Status is not (JobRunStatus.Pending or JobRunStatus.Dispatched or JobRunStatus.Running))
            {
                return run;
            }
            await Task.Delay(150, ct);
        }
        return null;
    }

    private static IResult FileFailure(JobRun? run) => run is null
        ? Api.Error(504, "timeout", "The device did not answer in time.")
        : Api.Error(422, "file_operation_failed", run.Message ?? $"The device reported: {run.Status.ToString().ToLowerInvariant()}.");

    public static void Map(RouteGroupBuilder api)
    {
        // Opening any session needs fresh step-up: it gives interactive access to a client computer.
        api.MapPost("/devices/{id:guid}/sessions/terminal", (Guid id, TerminalRequest req, Ctx c, RemoteSessionService s, CancellationToken ct) =>
            req.RunAs is not (null or "system" or "user")
                ? Task.FromResult(Api.BadRequest("runAs must be system or user."))
                : StartAsync(id, "terminal", new { cols = Math.Clamp(req.Cols ?? 120, 10, 500), rows = Math.Clamp(req.Rows ?? 30, 5, 300), runAs = req.RunAs ?? "system" }, c, s, ct))
            .RequirePermission(Permissions.RemoteTerminal).RequireStepUp();

        api.MapPost("/devices/{id:guid}/sessions/files", (Guid id, Ctx c, RemoteSessionService s, CancellationToken ct) => StartAsync(id, "files", null, c, s, ct))
            .RequirePermission(Permissions.RemoteFiles).RequireStepUp();

        api.MapPost("/devices/{id:guid}/sessions/desktop", async (Guid id, Ctx c, RemoteSessionService s, MeshCentral mesh, CancellationToken ct) =>
        {
            if (!mesh.Configured)
            {
                return Api.Conflict("Remote desktop is not configured on this server (MeshCentral).");
            }
            return await StartAsync(id, "desktop", null, c, s, ct);
        }).RequirePermission(Permissions.RemoteDesktop).RequireStepUp();

        api.MapGet("/sessions", async (Guid? deviceId, Guid? organizationId, string? state, int? page, int? pageSize, Ctx c, CancellationToken ct) =>
        {
            var (skip, take, p) = Api.Paging(page, pageSize);
            var q = c.Db.RemoteSessions.AsNoTracking().Where(s => (deviceId == null || s.DeviceId == deviceId) && (organizationId == null || s.OrganizationId == organizationId));
            if (state is not null)
            {
                if (!Enum.TryParse<RemoteSessionState>(state, true, out var st))
                {
                    return Api.BadRequest("Unknown state.");
                }
                q = q.Where(s => s.State == st);
            }
            var total = await q.CountAsync(ct);
            var items = await q.OrderByDescending(s => s.RequestedAt).Skip(skip).Take(take).Select(s => new
            {
                s.Id, s.DeviceId, hostname = s.Device.Hostname, s.OrganizationId, s.UserId, s.UserName, s.Kind, consent = s.ConsentMode.ToString().ToLower(), state = s.State.ToString().ToLower(),
                s.ConsentResult, s.EndReason, s.RequestedAt, s.StartedAt, s.EndedAt, s.Ip, s.BytesIn, s.BytesOut,
            }).ToListAsync(ct);
            return Results.Ok(new { total, page = p, pageSize = take, items });
        }).RequirePermission(Permissions.SessionsRead);

        api.MapGet("/sessions/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var s = await c.Db.RemoteSessions.AsNoTracking().Include(x => x.Device).FirstOrDefaultAsync(x => x.Id == id, ct);
            return s is null ? Api.NotFound() : Results.Ok(new
            {
                s.Id, s.DeviceId, hostname = s.Device.Hostname, s.OrganizationId, s.UserId, s.UserName, s.Kind, consent = s.ConsentMode.ToString().ToLower(), state = s.State.ToString().ToLower(),
                s.ConsentResult, s.EndReason, s.RequestedAt, s.StartedAt, s.EndedAt, s.BytesIn, s.BytesOut, s.InputSha256, mine = s.UserId == c.Who.UserId,
            });
        }).RequirePermission(Permissions.SessionsRead);

        // Anyone who may see a session may end it (ending is always the safe direction).
        api.MapPost("/sessions/{id:guid}/end", async (Guid id, Ctx c, RemoteSessionService sessions, CancellationToken ct) =>
        {
            var s = await c.Db.RemoteSessions.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
            if (s is null)
            {
                return Api.NotFound();
            }
            await sessions.EndAsync(id, s.UserId == c.Who.UserId ? "ended by technician" : $"ended by {c.Who.Name}", ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.SessionsRead);

        // ----- File browser (inside an active "files" session owned by the caller) -----
        api.MapPost("/sessions/{id:guid}/files/list", async (Guid id, PathRequest req, Ctx c, SessionRegistry registry, JobService jobs, CancellationToken ct) =>
        {
            var (session, error) = await OwnActiveAsync(id, "files", c, registry, ct);
            if (error is not null)
            {
                return error;
            }
            if (CleanPath(req.Path) is not { } path)
            {
                return Api.BadRequest("path is required.");
            }
            var run = await RunFileJobAsync(c, jobs, session!, JobKinds.FileList, new { path }, "List folder", 30, ct);
            await c.Audit("file.list", run?.Status == JobRunStatus.Succeeded ? "success" : "failure", session!.OrganizationId, session.DeviceId, "remote_session", id, new { path }, ct: ct);
            return run?.Status == JobRunStatus.Succeeded && run.ResultJson is not null ? Results.Ok(JsonSerializer.Deserialize<JsonElement>(run.ResultJson)) : FileFailure(run);
        }).RequirePermission(Permissions.RemoteFiles);

        api.MapPost("/sessions/{id:guid}/files/download", async (Guid id, PathRequest req, Ctx c, SessionRegistry registry, JobService jobs, IOptions<DranzoOptions> opt, CancellationToken ct) =>
        {
            var (session, error) = await OwnActiveAsync(id, "files", c, registry, ct);
            if (error is not null)
            {
                return error;
            }
            if (CleanPath(req.Path) is not { } path)
            {
                return Api.BadRequest("path is required.");
            }
            var max = opt.Value.Storage.MaxFileTransferBytes;
            var ticket = new UploadTicket { Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, DeviceId = session!.DeviceId, JobRunId = session.Id, MaxBytes = max, ExpiresAt = c.Now.AddMinutes(10) };
            c.Db.UploadTickets.Add(ticket);
            await c.Db.SaveChangesAsync(ct);
            var run = await RunFileJobAsync(c, jobs, session, JobKinds.FileRead, new { path, uploadId = ticket.Id, maxBytes = max }, "Download file", 120, ct);
            var sha = run?.ResultJson is null ? null : JsonSerializer.Deserialize<JsonElement>(run.ResultJson).StrOrNull("sha256", 64);
            await c.Audit("file.download", run?.Status == JobRunStatus.Succeeded ? "success" : "failure", session.OrganizationId, session.DeviceId, "remote_session", id, new { path }, sha, ct);
            if (run?.Status != JobRunStatus.Succeeded)
            {
                return FileFailure(run);
            }
            var blobId = await c.Db.UploadTickets.IgnoreQueryFilters().Where(t => t.Id == ticket.Id && t.PartnerId == c.Who.PartnerId).Select(t => t.BlobId).FirstAsync(ct);
            return blobId is null ? Api.Error(422, "file_operation_failed", "The device did not upload the file.") : Results.Ok(new { ticketId = ticket.Id, fileName = BlobService.SafeFileName(path), sha256 = sha });
        }).RequirePermission(Permissions.RemoteFiles);

        api.MapGet("/sessions/{id:guid}/files/content/{ticketId:guid}", async (Guid id, Guid ticketId, string? fileName, Ctx c, IObjectStore store, HttpContext http, CancellationToken ct) =>
        {
            var session = await c.Db.RemoteSessions.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct);
            if (session is null || session.UserId != c.Who.UserId)
            {
                return Api.NotFound();
            }
            // Tickets carry the session id they were created for; only that session's owner can fetch the content.
            var ticket = await c.Db.UploadTickets.IgnoreQueryFilters().AsNoTracking()
                .FirstOrDefaultAsync(t => t.Id == ticketId && t.PartnerId == c.Who.PartnerId && t.JobRunId == session.Id && t.DeviceId == session.DeviceId && t.BlobId != null, ct);
            var blob = ticket is null ? null : await c.Db.Blobs.IgnoreQueryFilters().AsNoTracking().FirstOrDefaultAsync(b => b.Id == ticket.BlobId && b.PartnerId == c.Who.PartnerId, ct);
            if (blob is null)
            {
                return Api.NotFound();
            }
            // Always a download, never rendered: files from client machines are untrusted content.
            http.Response.Headers.ContentDisposition = new System.Net.Mime.ContentDisposition { FileName = BlobService.SafeFileName(fileName ?? "download"), Inline = false }.ToString();
            return Results.Stream(await store.OpenReadAsync(blob.StorageKey, ct), "application/octet-stream");
        }).RequirePermission(Permissions.RemoteFiles);

        api.MapPut("/sessions/{id:guid}/files/upload", async (Guid id, string? path, bool? overwrite, HttpContext http, Ctx c, SessionRegistry registry, JobService jobs, BlobService blobs, IOptions<DranzoOptions> opt, CancellationToken ct) =>
        {
            var (session, error) = await OwnActiveAsync(id, "files", c, registry, ct);
            if (error is not null)
            {
                return error;
            }
            if (CleanPath(path) is not { } target)
            {
                return Api.BadRequest("path is required.");
            }
            var max = opt.Value.Storage.MaxFileTransferBytes;
            http.Features.Get<IHttpMaxRequestBodySizeFeature>()!.MaxRequestBodySize = max + 1;
            if (http.Request.ContentLength > max)
            {
                return Api.Error(413, "too_large", $"Files are limited to {max} bytes.");
            }
            var stored = await blobs.SaveAsync(c.Who.PartnerId, http.Request.Body, target, "file-transfer", max, TimeSpan.FromHours(1), ct);
            if (stored is null)
            {
                return Api.Error(413, "too_large", "Upload was empty or exceeded the size limit.");
            }
            var run = await RunFileJobAsync(c, jobs, session!, JobKinds.FileWrite, new { path = target, blobId = stored.Id, sha256 = stored.Sha256, sizeBytes = stored.SizeBytes, overwrite = overwrite ?? false }, "Upload file", 120, ct);
            await c.Audit("file.upload", run?.Status == JobRunStatus.Succeeded ? "success" : "failure", session!.OrganizationId, session.DeviceId, "remote_session", id, new { path = target, stored.SizeBytes }, stored.Sha256, ct);
            return run?.Status == JobRunStatus.Succeeded ? Results.Ok(new { sizeBytes = stored.SizeBytes, sha256 = stored.Sha256 }) : FileFailure(run);
        }).RequirePermission(Permissions.RemoteFiles);

        // ----- Remote desktop (MeshCentral) -----
        api.MapGet("/sessions/{id:guid}/desktop-url", async (Guid id, Ctx c, SessionRegistry registry, MeshCentral mesh, CancellationToken ct) =>
        {
            var (session, error) = await OwnActiveAsync(id, "desktop", c, registry, ct);
            if (error is not null)
            {
                return error;
            }
            var device = await c.Db.Devices.AsNoTracking().FirstAsync(d => d.Id == session!.DeviceId, ct);
            var org = await c.Db.Organizations.IgnoreQueryFilters().AsNoTracking().FirstAsync(o => o.Id == device.OrganizationId && o.PartnerId == c.Who.PartnerId, ct);
            if (!mesh.Configured || device.MeshNodeId is null)
            {
                return Api.Conflict("The remote desktop agent is not installed on this device yet.");
            }
            if (mesh.UserFor(org) is not { } meshUser)
            {
                return Api.Conflict("This organization has no MeshCentral account configured. A shared account would expose other organizations' devices, so it is refused.");
            }
            await c.Audit("session.desktop_url", organizationId: session!.OrganizationId, deviceId: session.DeviceId, targetType: "remote_session", targetId: id, ct: ct);
            // Short-lived, single-purpose link; never logged or stored.
            return Results.Ok(new { url = mesh.DesktopUrl(device.MeshNodeId, meshUser) });
        }).RequirePermission(Permissions.RemoteDesktop);

        api.MapPost("/devices/{id:guid}/mesh/install", async (Guid id, Ctx c, JobService jobs, BlobService blobs, MeshCentral mesh, IOptions<DranzoOptions> opt, CancellationToken ct) =>
        {
            var device = await c.Db.Devices.FirstOrDefaultAsync(d => d.Id == id, ct);
            if (device is null)
            {
                return Api.NotFound();
            }
            var org = await c.Db.Organizations.IgnoreQueryFilters().AsNoTracking().FirstAsync(o => o.Id == device.OrganizationId && o.PartnerId == c.Who.PartnerId, ct);
            var group = org.MeshGroupId ?? opt.Value.Mesh.MeshId;
            if (!mesh.Configured || string.IsNullOrEmpty(group))
            {
                return Api.Conflict("MeshCentral is not configured for this organization.");
            }
            StoredBlob? stored;
            string fileName;
            try
            {
                var (content, name) = await mesh.DownloadAgentAsync(device.Os, device.Arch, group, ct);
                await using (content)
                {
                    fileName = name;
                    stored = await blobs.SaveAsync(c.Who.PartnerId, content, name, "mesh-agent", 200 * 1024 * 1024, TimeSpan.FromHours(2), ct);
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException)
            {
                return Api.Error(502, "mesh_unavailable", "Could not fetch the remote desktop agent from MeshCentral: " + ex.Message);
            }
            if (stored is null)
            {
                return Api.Error(502, "mesh_unavailable", "MeshCentral returned an empty agent.");
            }
            var created = await jobs.CreateAsync(new NewJob("Install remote desktop agent", JobKinds.MeshInstall, new JobTarget(DeviceIds: [id]),
                new { blobId = stored.Id, sha256 = stored.Sha256, sizeBytes = stored.SizeBytes, fileName }, 900, ContentSha256: stored.Sha256), [device], c.Who.PartnerId, c.Who.UserId, c.Who.Name, ct);
            await c.Audit("mesh.install", organizationId: device.OrganizationId, deviceId: id, targetType: "job", targetId: created.Job.Id, contentSha256: stored.Sha256, ct: ct);
            return Results.Created($"/api/v1/jobs/{created.Job.Id}", new { jobId = created.Job.Id });
        }).RequirePermission(Permissions.RemoteDesktop);

        api.MapPatch("/organizations/{id:guid}/mesh", async (Guid id, MeshOrgRequest req, Ctx c, CancellationToken ct) =>
        {
            var org = await c.Db.Organizations.FirstOrDefaultAsync(o => o.Id == id, ct);
            if (org is null)
            {
                return Api.NotFound();
            }
            if ((req.MeshUser?.Length ?? 0) > 128 || (req.MeshGroupId?.Length ?? 0) > 256 || (req.MeshUser is { Length: > 0 } u && !u.StartsWith("user/", StringComparison.Ordinal)))
            {
                return Api.BadRequest("meshUser must look like user/<domain>/<name>.");
            }
            org.MeshUser = string.IsNullOrEmpty(req.MeshUser) ? null : req.MeshUser;
            org.MeshGroupId = string.IsNullOrEmpty(req.MeshGroupId) ? null : req.MeshGroupId;
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("organization.mesh_update", organizationId: id, targetType: "organization", targetId: id, detail: new { org.MeshUser, org.MeshGroupId }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.SettingsManage, partnerWide: true).RequireStepUp();
    }
}
