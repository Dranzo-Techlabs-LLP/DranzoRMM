using System.Text.Json;
using System.Text.RegularExpressions;
using Dranzo.Api.Auth;
using Dranzo.Domain;
using Dranzo.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

public sealed record ScriptParameter(string Name, string Type, bool Required, string? Default);

public static partial class ScriptEndpoints
{
    public const int MaxBodyChars = 512 * 1024;

    public static readonly IReadOnlyDictionary<string, string[]> LanguageOs = new Dictionary<string, string[]>
    {
        ["powershell"] = ["windows"], ["cmd"] = ["windows"],
        ["bash"] = ["macos", "linux"], ["zsh"] = ["macos", "linux"], ["sh"] = ["macos", "linux"],
        ["python"] = ["windows", "macos", "linux"],
    };

    private static readonly string[] ParamTypes = ["string", "int", "bool"];

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]{0,63}$")]
    public static partial Regex EnvName();

    public sealed record ScriptRequest(string? Name, string? Description, string? Language, string[]? OsTargets, string? Body, ScriptParameter[]? Parameters, Guid? OrganizationId, string? ChangeNote);

    private static string? Validate(ScriptRequest req, string language, out string[] osTargets, out ScriptParameter[] parameters)
    {
        osTargets = [];
        parameters = req.Parameters ?? [];
        if (!LanguageOs.TryGetValue(language, out var allowed))
        {
            return "language must be one of: " + string.Join(", ", LanguageOs.Keys);
        }
        osTargets = req.OsTargets is { Length: > 0 } ? [.. req.OsTargets.Distinct()] : allowed;
        if (osTargets.Any(o => !allowed.Contains(o)))
        {
            return $"{language} scripts can only target: {string.Join(", ", allowed)}";
        }
        if (string.IsNullOrEmpty(req.Body) || req.Body.Length > MaxBodyChars)
        {
            return $"body is required (max {MaxBodyChars} characters).";
        }
        if (req.Body.Contains('\0'))
        {
            return "body must be text.";
        }
        if (parameters.Length > 32 || parameters.Any(p => p.Name is null || !EnvName().IsMatch(p.Name) || !ParamTypes.Contains(p.Type) || (p.Default?.Length ?? 0) > 1024)
            || parameters.Select(p => p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != parameters.Length)
        {
            return "parameters: up to 32, unique names matching [A-Za-z_][A-Za-z0-9_]*, type string|int|bool.";
        }
        return null;
    }

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/scripts", async (Guid? organizationId, Ctx c, CancellationToken ct) =>
            Results.Ok(await c.Db.Scripts.AsNoTracking().Where(s => s.DeletedAt == null && (organizationId == null || s.OrganizationId == null || s.OrganizationId == organizationId))
                .OrderBy(s => s.Name).Select(s => new { s.Id, s.OrganizationId, s.Name, s.Description, s.Language, s.OsTargets, s.CurrentVersion, s.UpdatedAt }).ToListAsync(ct)))
            .RequirePermission(Permissions.ScriptsRead);

        api.MapGet("/scripts/{id:guid}", async (Guid id, int? version, Ctx c, CancellationToken ct) =>
        {
            var s = await c.Db.Scripts.AsNoTracking().Include(x => x.Versions).FirstOrDefaultAsync(x => x.Id == id && x.DeletedAt == null, ct);
            if (s is null)
            {
                return Api.NotFound();
            }
            var v = s.Versions.FirstOrDefault(x => x.Version == (version ?? s.CurrentVersion));
            if (v is null)
            {
                return Api.NotFound();
            }
            return Results.Ok(new
            {
                s.Id, s.OrganizationId, s.Name, s.Description, s.Language, s.OsTargets, s.CurrentVersion, s.CreatedAt, s.UpdatedAt,
                version = v.Version, v.Body, v.BodySha256, parameters = JsonSerializer.Deserialize<JsonElement>(v.ParametersJson),
                versions = s.Versions.OrderByDescending(x => x.Version).Select(x => new { x.Version, x.CreatedAt, x.CreatedByUserId, x.ChangeNote, x.BodySha256 }),
            });
        }).RequirePermission(Permissions.ScriptsRead);

        api.MapPost("/scripts", async (ScriptRequest req, Ctx c, CancellationToken ct) =>
        {
            if (Api.CleanName(req.Name) is not { } name)
            {
                return Api.BadRequest("Name is required.");
            }
            var problem = Validate(req, req.Language ?? "", out var osTargets, out var parameters);
            if (problem is not null)
            {
                return Api.BadRequest(problem);
            }
            // Shared (partner-wide) scripts can run on any organization, so creating them needs partner scope.
            if (req.OrganizationId is { } org ? !c.Tenant.CoversOrganization(org) || !await c.Db.Organizations.AnyAsync(o => o.Id == org, ct) : !c.Tenant.AllOrgs)
            {
                return req.OrganizationId is null ? Api.Error(403, "forbidden", "Shared scripts need partner-wide scope; set organizationId.") : Api.NotFound();
            }
            var script = new Script
            {
                Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, OrganizationId = req.OrganizationId, Name = name, Description = req.Description?.Trim() ?? "",
                Language = req.Language!, OsTargets = osTargets, CurrentVersion = 1, CreatedAt = c.Now, UpdatedAt = c.Now,
            };
            var sha = Hashing.Sha256Hex(req.Body!);
            script.Versions.Add(new ScriptVersion
            {
                Id = Guid.NewGuid(), PartnerId = c.Who.PartnerId, ScriptId = script.Id, Version = 1, Body = req.Body!, BodySha256 = sha,
                ParametersJson = JsonSerializer.Serialize(parameters, JsonSerializerOptions.Web), CreatedByUserId = c.Who.UserId, CreatedAt = c.Now, ChangeNote = req.ChangeNote,
            });
            c.Db.Scripts.Add(script);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("script.create", organizationId: script.OrganizationId, targetType: "script", targetId: script.Id, detail: new { name, script.Language, version = 1 }, contentSha256: sha, ct: ct);
            return Results.Created($"/api/v1/scripts/{script.Id}", new { script.Id, version = 1 });
        }).RequirePermission(Permissions.ScriptsManage);

        // Saving creates a new immutable version; old versions stay available for history and audit.
        api.MapPut("/scripts/{id:guid}", async (Guid id, ScriptRequest req, Ctx c, CancellationToken ct) =>
        {
            var script = await c.Db.Scripts.FirstOrDefaultAsync(x => x.Id == id && x.DeletedAt == null, ct);
            if (script is null || (script.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            var problem = Validate(req, req.Language ?? script.Language, out var osTargets, out var parameters);
            if (problem is not null)
            {
                return Api.BadRequest(problem);
            }
            if (req.Name is not null)
            {
                if (Api.CleanName(req.Name) is not { } name)
                {
                    return Api.BadRequest("Invalid name.");
                }
                script.Name = name;
            }
            script.Description = req.Description?.Trim() ?? script.Description;
            script.Language = req.Language ?? script.Language;
            script.OsTargets = osTargets;
            script.CurrentVersion++;
            script.UpdatedAt = c.Now;
            var sha = Hashing.Sha256Hex(req.Body!);
            c.Db.ScriptVersions.Add(new ScriptVersion
            {
                Id = Guid.NewGuid(), PartnerId = script.PartnerId, ScriptId = script.Id, Version = script.CurrentVersion, Body = req.Body!, BodySha256 = sha,
                ParametersJson = JsonSerializer.Serialize(parameters, JsonSerializerOptions.Web), CreatedByUserId = c.Who.UserId, CreatedAt = c.Now, ChangeNote = req.ChangeNote,
            });
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("script.update", organizationId: script.OrganizationId, targetType: "script", targetId: id, detail: new { script.Name, version = script.CurrentVersion }, contentSha256: sha, ct: ct);
            return Results.Ok(new { script.Id, version = script.CurrentVersion });
        }).RequirePermission(Permissions.ScriptsManage);

        api.MapDelete("/scripts/{id:guid}", async (Guid id, Ctx c, CancellationToken ct) =>
        {
            var script = await c.Db.Scripts.FirstOrDefaultAsync(x => x.Id == id && x.DeletedAt == null, ct);
            if (script is null || (script.OrganizationId is null && !c.Tenant.AllOrgs))
            {
                return Api.NotFound();
            }
            script.DeletedAt = c.Now;
            await c.Db.Jobs.Where(j => j.ScriptId == id && j.Cron != null).ExecuteUpdateAsync(s => s.SetProperty(j => j.Enabled, false), ct);
            await c.Db.SaveChangesAsync(ct);
            await c.Audit("script.delete", organizationId: script.OrganizationId, targetType: "script", targetId: id, detail: new { script.Name }, ct: ct);
            return Results.NoContent();
        }).RequirePermission(Permissions.ScriptsManage);
    }
}
