using System.Text;
using Dranzo.Api.Auth;
using Dranzo.Domain;
using Microsoft.EntityFrameworkCore;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;
using PdfSharp.Fonts;
using PdfSharp.Snippets.Font;

namespace Dranzo.Api.Features;

public sealed record ReportData(string Title, string[] Headers, List<object?[]> Rows);

public static class ReportEndpoints
{
    private static readonly Lock FontLock = new();

    private static string Text(object? value) => value switch
    {
        null => "",
        bool b => b ? "yes" : "no",
        DateTimeOffset d => d.UtcDateTime.ToString("yyyy-MM-dd HH:mm"),
        IEnumerable<string> list => string.Join(", ", list),
        double d => d.ToString("0.#"),
        _ => value.ToString() ?? "",
    };

    /// <summary>Renders a simple landscape table report. Uses PDFsharp's bundled fallback font so it works without OS fonts.</summary>
    public static byte[] Pdf(ReportData report, string subtitle)
    {
        lock (FontLock)
        {
            GlobalFontSettings.FontResolver ??= new FailsafeFontResolver();
        }
        var doc = new Document();
        doc.Info.Title = report.Title;
        doc.Styles[StyleNames.Normal]!.Font.Size = 7.5;
        var section = doc.AddSection();
        section.PageSetup.Orientation = Orientation.Landscape;
        section.PageSetup.LeftMargin = section.PageSetup.RightMargin = Unit.FromCentimeter(1.2);
        section.PageSetup.TopMargin = section.PageSetup.BottomMargin = Unit.FromCentimeter(1.5);
        var title = section.AddParagraph(report.Title);
        title.Format.Font.Size = 15;
        title.Format.Font.Bold = true;
        var sub = section.AddParagraph(subtitle);
        sub.Format.SpaceAfter = Unit.FromPoint(8);
        sub.Format.Font.Color = Colors.Gray;
        var footer = section.Footers.Primary.AddParagraph();
        footer.AddText("DranzoRMM · page ");
        footer.AddPageField();
        footer.Format.Alignment = ParagraphAlignment.Right;

        var table = section.AddTable();
        table.Borders.Width = 0.25;
        table.Borders.Color = Colors.LightGray;
        var width = (29.7 - 2.4) / report.Headers.Length;
        foreach (var _ in report.Headers)
        {
            table.AddColumn(Unit.FromCentimeter(width));
        }
        var head = table.AddRow();
        head.HeadingFormat = true;
        head.Format.Font.Bold = true;
        head.Shading.Color = Colors.WhiteSmoke;
        for (var i = 0; i < report.Headers.Length; i++)
        {
            head.Cells[i].AddParagraph(report.Headers[i]);
        }
        foreach (var row in report.Rows.Take(5000))
        {
            var r = table.AddRow();
            for (var i = 0; i < report.Headers.Length; i++)
            {
                var text = Text(row[i]);
                // Break very long tokens so a cell cannot overflow its column.
                r.Cells[i].AddParagraph(text.Length > 160 ? text[..160] + "…" : text);
            }
        }
        if (report.Rows.Count > 5000)
        {
            section.AddParagraph($"Showing the first 5,000 of {report.Rows.Count} rows. Use the CSV export for the full data.");
        }
        var renderer = new PdfDocumentRenderer { Document = doc };
        renderer.RenderDocument();
        using var ms = new MemoryStream();
        renderer.PdfDocument.Save(ms, false);
        return ms.ToArray();
    }

    public static async Task<IResult> RenderAsync(string format, string slug, ReportData report, Ctx c, Guid? organizationId, CancellationToken ct)
    {
        if (format is not ("csv" or "pdf"))
        {
            return Api.NotFound();
        }
        await c.Audit("report.generate", organizationId: organizationId, targetType: "report", targetId: slug, detail: new { format, rows = report.Rows.Count }, ct: ct);
        var stamp = c.Now.UtcDateTime.ToString("yyyyMMdd-HHmm");
        if (format == "csv")
        {
            return Results.File(Encoding.UTF8.GetBytes(Api.Csv(report.Headers, report.Rows.Select(r => r.AsEnumerable()))), "text/csv", $"{slug}-{stamp}.csv");
        }
        var subtitle = $"Generated {c.Now.UtcDateTime:yyyy-MM-dd HH:mm} UTC by {c.Who.Name} · {report.Rows.Count} rows";
        return Results.File(Pdf(report, subtitle), "application/pdf", $"{slug}-{stamp}.pdf");
    }

    public static void Map(RouteGroupBuilder api)
    {
        api.MapGet("/reports", () => Results.Ok(new[]
        {
            new { id = "device-inventory", name = "Device inventory", permission = Permissions.ReportsRead },
            new { id = "patch-compliance", name = "Patch compliance", permission = Permissions.ReportsRead },
            new { id = "security-posture", name = "Security posture", permission = Permissions.ReportsRead },
            new { id = "software", name = "Installed software", permission = Permissions.ReportsRead },
            new { id = "audit-log", name = "Audit log", permission = Permissions.AuditRead },
            new { id = "access-review", name = "Access review (users, API keys, rights)", permission = Permissions.UsersRead },
        })).RequirePermission(Permissions.ReportsRead);

        api.MapGet("/reports/device-inventory.{format}", async (string format, Guid? organizationId, Ctx c, CancellationToken ct) =>
        {
            var orgs = await c.Db.Organizations.AsNoTracking().ToDictionaryAsync(o => o.Id, o => o.Name, ct);
            var rows = await c.Db.Devices.AsNoTracking().Where(d => organizationId == null || d.OrganizationId == organizationId).OrderBy(d => d.Hostname).ToListAsync(ct);
            return await RenderAsync(format, "device-inventory", new ReportData("Device inventory",
                ["Organization", "Hostname", "OS", "OS version", "Arch", "Model", "Serial", "Agent", "Status", "Online", "Last seen", "User", "Enrolled"],
                [.. rows.Select(d => new object?[] { orgs.GetValueOrDefault(d.OrganizationId), d.Hostname, d.OsName.Length > 0 ? d.OsName : d.Os, d.OsVersion, d.Arch, d.Model, d.Serial, d.AgentVersion, d.Status.ToString(), d.IsOnline, d.LastSeenAt, d.ConsoleUser, d.EnrolledAt })]), c, organizationId, ct);
        }).RequirePermission(Permissions.ReportsRead);

        api.MapGet("/reports/patch-compliance.{format}", async (string format, Guid? organizationId, Ctx c, CancellationToken ct) =>
        {
            var orgs = await c.Db.Organizations.AsNoTracking().ToDictionaryAsync(o => o.Id, o => o.Name, ct);
            var devices = await c.Db.Devices.AsNoTracking().Where(d => d.Status == DeviceStatus.Active && (organizationId == null || d.OrganizationId == organizationId)).OrderBy(d => d.Hostname).ToListAsync(ct);
            var counts = await c.Db.DevicePatchStates.AsNoTracking().Where(s => (organizationId == null || s.OrganizationId == organizationId) && s.Status != PatchStatus.Installed && s.Status != PatchStatus.Rejected)
                .GroupBy(s => s.DeviceId).Select(g => new { g.Key, Missing = g.Count(), Critical = g.Count(x => x.CatalogEntry.Severity == "critical" || x.CatalogEntry.Severity == "important"), Failed = g.Count(x => x.Status == PatchStatus.Failed) })
                .ToDictionaryAsync(x => x.Key, ct);
            return await RenderAsync(format, "patch-compliance", new ReportData("Patch compliance",
                ["Organization", "Hostname", "OS", "State", "Missing updates", "Critical / important", "Failed", "Pending reboot", "Last scan", "Last install"],
                [.. devices.Select(d =>
                {
                    var n = counts.GetValueOrDefault(d.Id);
                    return new object?[] { orgs.GetValueOrDefault(d.OrganizationId), d.Hostname, d.Os, d.LastPatchScanAt is null ? "unknown" : (n?.Missing ?? 0) == 0 ? "patched" : "unpatched", n?.Missing ?? 0, n?.Critical ?? 0, n?.Failed ?? 0, d.PendingReboot, d.LastPatchScanAt, d.LastPatchInstallAt };
                })]), c, organizationId, ct);
        }).RequirePermission(Permissions.ReportsRead);

        api.MapGet("/reports/security-posture.{format}", async (string format, Guid? organizationId, Ctx c, CancellationToken ct) =>
        {
            var orgs = await c.Db.Organizations.AsNoTracking().ToDictionaryAsync(o => o.Id, o => o.Name, ct);
            var devices = await c.Db.Devices.AsNoTracking().Where(d => d.Status == DeviceStatus.Active && (organizationId == null || d.OrganizationId == organizationId)).OrderBy(d => d.Hostname).ToListAsync(ct);
            var posture = await c.Db.PostureSnapshots.AsNoTracking().Where(p => p.IsLatest && (organizationId == null || p.OrganizationId == organizationId)).ToDictionaryAsync(p => p.DeviceId, ct);
            var vulns = await c.Db.DeviceVulnerabilities.AsNoTracking().Where(v => organizationId == null || v.OrganizationId == organizationId)
                .GroupBy(v => v.DeviceId).Select(g => new { g.Key, Total = g.Count(), Kev = g.Count(x => x.KnownExploited) }).ToDictionaryAsync(x => x.Key, ct);
            static string Tri(bool? v) => v switch { true => "ok", false => "ISSUE", _ => "unknown" };
            return await RenderAsync(format, "security-posture", new ReportData("Security posture",
                ["Organization", "Hostname", "OS", "Antivirus", "Firewall", "Disk encryption", "Local admins", "Vulnerabilities", "Known exploited", "Pending reboot", "Collected"],
                [.. devices.Select(d =>
                {
                    var p = posture.GetValueOrDefault(d.Id);
                    var v = vulns.GetValueOrDefault(d.Id);
                    return new object?[] { orgs.GetValueOrDefault(d.OrganizationId), d.Hostname, d.Os, Tri(p?.AntivirusOk), Tri(p?.FirewallOk), Tri(p?.EncryptionOk), p?.LocalAdmins ?? [], v?.Total ?? 0, v?.Kev ?? 0, d.PendingReboot, p?.CollectedAt };
                })]), c, organizationId, ct);
        }).RequirePermission(Permissions.ReportsRead);

        api.MapGet("/reports/software.{format}", async (string format, Guid? organizationId, Ctx c, CancellationToken ct) =>
        {
            var orgs = await c.Db.Organizations.AsNoTracking().ToDictionaryAsync(o => o.Id, o => o.Name, ct);
            var rows = await c.Db.InstalledSoftware.AsNoTracking().Where(s => organizationId == null || s.OrganizationId == organizationId)
                .OrderBy(s => s.Name).ThenBy(s => s.Device.Hostname).Take(200_000)
                .Select(s => new { s.OrganizationId, hostname = s.Device.Hostname, s.Name, s.Version, s.Publisher, s.Source }).ToListAsync(ct);
            return await RenderAsync(format, "software", new ReportData("Installed software", ["Organization", "Hostname", "Software", "Version", "Publisher", "Source"],
                [.. rows.Select(s => new object?[] { orgs.GetValueOrDefault(s.OrganizationId), s.hostname, s.Name, s.Version, s.Publisher, s.Source })]), c, organizationId, ct);
        }).RequirePermission(Permissions.ReportsRead);

        api.MapGet("/reports/audit-log.{format}", async (string format, [AsParameters] AuditEndpoints.AuditQuery query, Ctx c, CancellationToken ct) =>
        {
            var rows = await AuditEndpoints.Filter(c.Db.AuditEvents.AsNoTracking(), query).OrderByDescending(a => a.Sequence).Take(100_000).ToListAsync(ct);
            return await RenderAsync(format, "audit-log", new ReportData("Audit log", ["Seq", "Time (UTC)", "Actor", "Action", "Target", "Device", "IP", "Result", "Content hash", "Chain hash"],
                [.. rows.Select(a => new object?[] { a.Sequence, a.OccurredAt, a.ActorName, a.Action, $"{a.TargetType} {a.TargetId}".Trim(), a.DeviceId, a.Ip, a.Result, a.ContentSha256, a.Hash })]), c, query.OrganizationId, ct);
        }).RequirePermission(Permissions.AuditRead);

        // One-screen summary used by the dashboard home page and the read-only client portal.
        api.MapGet("/overview", async (Guid? organizationId, Ctx c, CancellationToken ct) =>
        {
            var devices = c.Db.Devices.AsNoTracking().Where(d => d.Status == DeviceStatus.Active && (organizationId == null || d.OrganizationId == organizationId));
            var total = await devices.CountAsync(ct);
            return Results.Ok(new
            {
                devices = new
                {
                    total, online = await devices.CountAsync(d => d.IsOnline, ct), pendingReboot = await devices.CountAsync(d => d.PendingReboot, ct),
                    byOs = await devices.GroupBy(d => d.Os).Select(g => new { os = g.Key, count = g.Count() }).ToListAsync(ct),
                },
                organizations = await c.Db.Organizations.AsNoTracking().Where(o => organizationId == null || o.Id == organizationId).OrderBy(o => o.Name).Select(o => new { o.Id, o.Name }).ToListAsync(ct),
            });
        }).RequirePermission(Permissions.DevicesRead);
    }
}
