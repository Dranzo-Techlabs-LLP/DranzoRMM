using System.Security.Claims;
using Dranzo.Api.Auth;
using Dranzo.Api.Features;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Live;

/// <summary>
/// Pushes live events to dashboards. A connection is placed in the groups that match the caller's
/// <c>devices.read</c> scope; finer subscriptions (one run, one session) are checked against the caller's scope.
/// </summary>
public sealed class LiveHub(ScopeResolver scopes, TenantContext tenant, DranzoDbContext db, SessionRegistry sessions, RemoteSessionService remote, TimeProvider clock) : Hub
{
    private async Task<CurrentPrincipal?> PrincipalAsync()
    {
        var user = Context.User;
        if (user?.Identity?.IsAuthenticated != true || user.Identity.AuthenticationType != AuthSchemes.Session
            || !Guid.TryParse(user.FindFirstValue("sid"), out var sid))
        {
            return null;
        }
        // Re-validate the session on every hub call; it may have been revoked since the socket opened.
        var now = clock.GetUtcNow();
        var session = await db.UserSessions.IgnoreQueryFilters().AsNoTracking().FirstOrDefaultAsync(s => s.Id == sid && s.RevokedAt == null && s.ExpiresAt > now);
        if (session is null)
        {
            return null;
        }
        return new CurrentPrincipal
        {
            IsAuthenticated = true, PartnerId = session.PartnerId, UserId = session.UserId, SessionId = session.Id,
            Name = user.Identity.Name ?? "", StepUpAt = session.StepUpAt, Ip = Context.GetHttpContext()?.Connection.RemoteIpAddress?.ToString(),
        };
    }

    /// <summary>Scopes this hub invocation to where the caller holds <paramref name="permission"/>.</summary>
    internal async Task<CurrentPrincipal?> ScopeAsync(string permission)
    {
        var who = await PrincipalAsync();
        if (who is null || !await scopes.ApplyAsync(tenant, who, permission, false, Context.ConnectionAborted))
        {
            tenant.Clear();
            return null;
        }
        tenant.SetActor("user", who.UserId, who.Name, who.Ip);
        return who;
    }

    public override async Task OnConnectedAsync()
    {
        if (await ScopeAsync(Permissions.DevicesRead) is null)
        {
            Context.Abort();
            return;
        }
        if (tenant.AllOrgs)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, $"partner:{tenant.PartnerId}");
        }
        foreach (var id in tenant.OrgIds)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, $"org:{id}");
        }
        foreach (var id in tenant.SiteIds)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, $"site:{id}");
        }
        foreach (var id in tenant.GroupIds)
        {
            await Groups.AddToGroupAsync(Context.ConnectionId, $"group:{id}");
        }
        await base.OnConnectedAsync();
    }

    public async Task<bool> SubscribeRun(Guid runId)
    {
        if (await ScopeAsync(Permissions.JobsRead) is null || !await db.JobRuns.AnyAsync(r => r.Id == runId))
        {
            return false;
        }
        await Groups.AddToGroupAsync(Context.ConnectionId, $"run:{runId}");
        return true;
    }

    public Task UnsubscribeRun(Guid runId) => Groups.RemoveFromGroupAsync(Context.ConnectionId, $"run:{runId}");

    private static string PermissionFor(string kind) => kind switch
    {
        "terminal" => Permissions.RemoteTerminal,
        "files" => Permissions.RemoteFiles,
        _ => Permissions.RemoteDesktop,
    };

    /// <summary>The caller's own live session, re-authorised against their current scope on every call.</summary>
    private async Task<LiveSession?> OwnSessionAsync(Guid sessionId)
    {
        var live = sessions.Get(sessionId);
        if (live is null)
        {
            return null;
        }
        var who = await ScopeAsync(PermissionFor(live.Kind));
        if (who is null || who.UserId != live.UserId || who.PartnerId != live.PartnerId || !await db.Devices.AnyAsync(d => d.Id == live.DeviceId))
        {
            return null;
        }
        return live;
    }

    /// <summary>Receive state changes and terminal output of a session the caller started.</summary>
    public async Task<bool> JoinSession(Guid sessionId)
    {
        if (await OwnSessionAsync(sessionId) is null)
        {
            return false;
        }
        await Groups.AddToGroupAsync(Context.ConnectionId, $"session:{sessionId}");
        return true;
    }

    /// <summary>Keystrokes for a terminal session. Each frame is signed by the server before it goes to the agent.</summary>
    public async Task<bool> TerminalInput(Guid sessionId, string dataBase64)
    {
        if (dataBase64.Length > 32 * 1024 || await OwnSessionAsync(sessionId) is not { } live)
        {
            return false;
        }
        byte[] data;
        try
        {
            data = Convert.FromBase64String(dataBase64);
        }
        catch (FormatException)
        {
            return false;
        }
        return await remote.SendInputAsync(live, "data", data, null, null, Context.ConnectionAborted);
    }

    public async Task<bool> TerminalResize(Guid sessionId, int cols, int rows) =>
        await OwnSessionAsync(sessionId) is { } live && await remote.SendInputAsync(live, "resize", null, cols, rows, Context.ConnectionAborted);

    public async Task<bool> SubscribeJob(Guid jobId)
    {
        if (await ScopeAsync(Permissions.JobsRead) is null || !await db.JobRuns.AnyAsync(r => r.JobId == jobId))
        {
            return false;
        }
        await Groups.AddToGroupAsync(Context.ConnectionId, $"job:{jobId}");
        return true;
    }
}

/// <summary>Server-side publisher for <see cref="LiveHub"/> events.</summary>
public sealed class LiveNotifier(IHubContext<LiveHub> hub, ILogger<LiveNotifier> log)
{
    private static string[] DeviceGroups(Guid partnerId, Guid orgId, Guid siteId, Guid? groupId) => groupId is { } g
        ? [$"partner:{partnerId}", $"org:{orgId}", $"site:{siteId}", $"group:{g}"]
        : [$"partner:{partnerId}", $"org:{orgId}", $"site:{siteId}"];

    private async Task SendAsync(IReadOnlyList<string> groups, string method, object payload)
    {
        try
        {
            await hub.Clients.Groups(groups).SendAsync(method, payload);
        }
        catch (Exception ex)
        {
            log.LogDebug(ex, "Live event {Method} not delivered", method);
        }
    }

    public Task DeviceChangedAsync(Device d) => SendAsync(DeviceGroups(d.PartnerId, d.OrganizationId, d.SiteId, d.GroupId), "device",
        new { id = d.Id, d.OrganizationId, d.SiteId, d.GroupId, d.IsOnline, d.LastSeenAt, d.Hostname, d.PendingReboot, d.ConsoleUser, d.Tags, status = d.Status.ToString().ToLowerInvariant() });

    public Task RunChangedAsync(JobRun r, Device d) => Task.WhenAll(
        SendAsync([$"run:{r.Id}", $"job:{r.JobId}"], "run", new { id = r.Id, r.JobId, r.DeviceId, status = r.Status.ToString().ToLowerInvariant(), r.ExitCode, r.Message, r.Truncated, r.FinishedAt }),
        SendAsync(DeviceGroups(d.PartnerId, d.OrganizationId, d.SiteId, d.GroupId), "runSummary", new { id = r.Id, r.JobId, r.DeviceId, status = r.Status.ToString().ToLowerInvariant() }));

    public Task RunOutputAsync(Guid runId, int seq, string stream, string data) =>
        SendAsync([$"run:{runId}"], "runOutput", new { runId, seq, stream, data });

    public Task AlertAsync(Alert a, Device d) => SendAsync(DeviceGroups(d.PartnerId, d.OrganizationId, d.SiteId, d.GroupId), "alert",
        new { id = a.Id, a.DeviceId, a.Type, a.Severity, a.Title, state = a.State.ToString().ToLowerInvariant() });

    public Task SessionAsync(Guid sessionId, string method, object payload) => SendAsync([$"session:{sessionId}"], method, payload);
}
