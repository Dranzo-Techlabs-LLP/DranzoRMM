using System.Text;
using Dranzo.Api.Auth;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;

namespace Dranzo.Api;

public static class Api
{
    public static IResult Error(int status, string error, string message) => Results.Json(new { error, message }, statusCode: status);

    public static IResult BadRequest(string message) => Error(400, "bad_request", message);

    public static IResult NotFound() => Error(404, "not_found", "Not found.");

    public static IResult Conflict(string message) => Error(409, "conflict", message);

    /// <summary>Trimmed name of 1..max characters without control characters, or null if invalid.</summary>
    public static string? CleanName(string? value, int max = 120)
    {
        var v = value?.Trim();
        return string.IsNullOrEmpty(v) || v.Length > max || v.Any(char.IsControl) ? null : v;
    }

    /// <summary>Escapes LIKE wildcards in user input. Use with <c>EF.Functions.ILike(column, pattern, Api.LikeEscape)</c>.</summary>
    public static string LikeLiteral(string value) => value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");

    public const string LikeEscape = "\\";

    public static (int Skip, int Take, int Page) Paging(int? page, int? pageSize)
    {
        var p = Math.Max(1, page ?? 1);
        var size = Math.Clamp(pageSize ?? 50, 1, 500);
        return ((p - 1) * size, size, p);
    }

    public static string CsvCell(object? value)
    {
        var s = value switch
        {
            null => "",
            DateTimeOffset d => d.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss"),
            IEnumerable<string> list => string.Join("; ", list),
            _ => value.ToString() ?? "",
        };
        // Neutralise spreadsheet formula injection, then quote.
        if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
        {
            s = "'" + s;
        }
        return "\"" + s.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    public static string Csv(IEnumerable<string> header, IEnumerable<IEnumerable<object?>> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", header.Select(h => CsvCell(h))));
        foreach (var row in rows)
        {
            sb.AppendLine(string.Join(",", row.Select(CsvCell)));
        }
        return sb.ToString();
    }
}

/// <summary>Request-scoped helper bundle most endpoints need.</summary>
public sealed class Ctx(DranzoDbContext db, TenantContext tenant, CurrentPrincipal who, IAuditLog audit, TimeProvider clock)
{
    public DranzoDbContext Db => db;
    public TenantContext Tenant => tenant;
    public CurrentPrincipal Who => who;
    public DateTimeOffset Now => clock.GetUtcNow();

    public Task Audit(string action, string result = "success", Guid? organizationId = null, Guid? deviceId = null,
        string? targetType = null, object? targetId = null, object? detail = null, string? contentSha256 = null, CancellationToken ct = default) =>
        audit.WriteAsync(who.PartnerId, new AuditEntry(action, result, organizationId, deviceId, targetType, targetId?.ToString(), detail, contentSha256), ct);
}
