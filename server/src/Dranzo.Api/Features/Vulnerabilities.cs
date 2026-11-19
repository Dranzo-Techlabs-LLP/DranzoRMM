using System.Text.Json;
using System.Text.RegularExpressions;
using Dranzo.Api.Agents;
using Dranzo.Api.Services;
using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Dranzo.Api.Features;

public sealed record CpeRange(string Vendor, string Product, string? StartIncl, string? StartExcl, string? EndIncl, string? EndExcl, string? Exact);

/// <summary>Tolerant dotted-version comparison ("1.2.10" &gt; "1.2.9"; non-numeric suffixes are ignored).</summary>
public static partial class VersionCompare
{
    [GeneratedRegex(@"\d+")]
    private static partial Regex Digits();

    public static long[] Parse(string v) => [.. Digits().Matches(v.Split([' ', '-', '+', '~'], 2)[0]).Take(6).Select(m => long.TryParse(m.Value, out var n) ? n : 0)];

    public static int Compare(string a, string b)
    {
        var x = Parse(a);
        var y = Parse(b);
        for (var i = 0; i < Math.Max(x.Length, y.Length); i++)
        {
            var l = i < x.Length ? x[i] : 0;
            var r = i < y.Length ? y[i] : 0;
            if (l != r)
            {
                return l < r ? -1 : 1;
            }
        }
        return 0;
    }

    public static bool InRange(string version, CpeRange r)
    {
        if (Parse(version).Length == 0)
        {
            return false;
        }
        if (r.Exact is not null)
        {
            return Compare(version, r.Exact) == 0;
        }
        if (r.StartIncl is null && r.StartExcl is null && r.EndIncl is null && r.EndExcl is null)
        {
            return false; // "all versions" entries are too noisy to be useful without a version bound
        }
        return (r.StartIncl is null || Compare(version, r.StartIncl) >= 0) && (r.StartExcl is null || Compare(version, r.StartExcl) > 0)
            && (r.EndIncl is null || Compare(version, r.EndIncl) <= 0) && (r.EndExcl is null || Compare(version, r.EndExcl) < 0);
    }
}

/// <summary>Imports NVD CVE API 2.0 and CISA KEV JSON documents.</summary>
public static class VulnerabilityFeed
{
    public static async Task<int> ImportNvdAsync(DranzoDbContext db, JsonElement root, DateTimeOffset now, CancellationToken ct)
    {
        var count = 0;
        foreach (var item in root.Arr("vulnerabilities", 5000))
        {
            var cve = item.Obj("cve");
            var id = cve.Str("id", 32);
            if (!id.StartsWith("CVE-", StringComparison.Ordinal))
            {
                continue;
            }
            var ranges = new List<CpeRange>();
            foreach (var config in cve.Arr("configurations", 64))
            {
                foreach (var node in config.Arr("nodes", 256))
                {
                    foreach (var match in node.Arr("cpeMatch", 2000))
                    {
                        if (!match.Bool("vulnerable"))
                        {
                            continue;
                        }
                        // cpe:2.3:a:vendor:product:version:update:...
                        var parts = match.Str("criteria", 512).Split(':');
                        if (parts.Length < 6 || parts[2] != "a")
                        {
                            continue; // applications only; OS and hardware matching is out of scope (see docs)
                        }
                        var exact = parts[5] is "*" or "-" ? null : parts[5];
                        ranges.Add(new CpeRange(parts[3], parts[4], match.StrOrNull("versionStartIncluding", 64), match.StrOrNull("versionStartExcluding", 64),
                            match.StrOrNull("versionEndIncluding", 64), match.StrOrNull("versionEndExcluding", 64), exact));
                    }
                }
            }
            if (ranges.Count == 0)
            {
                continue;
            }
            double? score = null;
            var severity = "";
            foreach (var key in new[] { "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" })
            {
                var metric = cve.Obj("metrics").Arr(key, 4).FirstOrDefault();
                if (metric.ValueKind == JsonValueKind.Object)
                {
                    var data = metric.Obj("cvssData");
                    score = data.Num("baseScore");
                    severity = (data.StrOrNull("baseSeverity", 16) ?? metric.Str("baseSeverity", 16)).ToLowerInvariant();
                    break;
                }
            }
            var summary = cve.Arr("descriptions", 8).Where(d => d.Str("lang", 8) == "en").Select(d => d.Str("value", 1000)).FirstOrDefault() ?? "";
            var entry = await db.CveEntries.FirstOrDefaultAsync(e => e.Id == id, ct);
            if (entry is null)
            {
                entry = new CveEntry { Id = id };
                db.CveEntries.Add(entry);
            }
            entry.Summary = summary;
            entry.CvssScore = score;
            entry.Severity = severity;
            entry.Published = cve.Time("published");
            entry.UpdatedAt = now;
            entry.MatchJson = JsonSerializer.Serialize(ranges.Take(500), JsonSerializerOptions.Web);
            entry.Products = [.. ranges.Select(r => r.Product.ToLowerInvariant()).Distinct().Take(64)];
            count++;
        }
        await db.SaveChangesAsync(ct);
        return count;
    }

    public static async Task<int> ImportKevAsync(DranzoDbContext db, JsonElement root, DateTimeOffset now, CancellationToken ct)
    {
        var ids = root.Arr("vulnerabilities", 20_000).Select(v => v.Str("cveID", 32)).Where(i => i.StartsWith("CVE-", StringComparison.Ordinal)).Distinct().ToList();
        if (ids.Count == 0)
        {
            return 0;
        }
        await db.CveEntries.Where(e => e.KnownExploited && !ids.Contains(e.Id)).ExecuteUpdateAsync(s => s.SetProperty(e => e.KnownExploited, false), ct);
        await db.CveEntries.Where(e => !e.KnownExploited && ids.Contains(e.Id)).ExecuteUpdateAsync(s => s.SetProperty(e => e.KnownExploited, true), ct);
        await db.DeviceVulnerabilities.IgnoreQueryFilters().Where(v => !v.KnownExploited && ids.Contains(v.CveId)).ExecuteUpdateAsync(s => s.SetProperty(v => v.KnownExploited, true), ct);
        return ids.Count;
    }
}

/// <summary>
/// Matches installed software against imported CVE data. Name matching against CPE products is heuristic:
/// results are indicative. Distribution packages (dpkg/rpm/snap/flatpak) are skipped because distributions
/// backport fixes without changing the upstream version, which makes NVD version ranges unreliable for them.
/// </summary>
public sealed partial class VulnerabilityMatcher(DranzoDbContext db, TimeProvider clock)
{
    private static readonly HashSet<string> SkippedSources = ["dpkg", "rpm", "snap", "flatpak"];
    private static readonly HashSet<string> Noise = ["x64", "x86", "64-bit", "32-bit", "amd64", "arm64", "en-us", "the", "for", "and", "update", "edition"];

    [GeneratedRegex(@"[^a-z0-9.+#]+")]
    private static partial Regex Separator();

    /// <summary>CPE-style product candidates for a display name, each with whether it is the full name.</summary>
    public static List<(string Product, bool Full)> Candidates(string name, string? packageId)
    {
        var cleaned = Regex.Replace(name.ToLowerInvariant(), @"\(.*?\)", " ");
        var tokens = Separator().Split(cleaned).Where(t => t.Length > 0 && !Noise.Contains(t) && !Regex.IsMatch(t, @"^v?\d+(\.\d+)*$")).ToList();
        var result = new List<(string, bool)>();
        for (var i = 0; i < tokens.Count && i < 3; i++)
        {
            var rest = tokens.Skip(i).ToList();
            result.Add((string.Join('_', rest), i == 0));
            if (rest.Count > 1)
            {
                result.Add((string.Concat(rest), i == 0));
            }
        }
        if (!string.IsNullOrEmpty(packageId))
        {
            var last = packageId.ToLowerInvariant().Split('.', '/', ':').Last();
            if (last.Length > 1)
            {
                result.Add((last, true));
            }
        }
        return [.. result.Where(c => c.Item1.Length >= 2).Distinct()];
    }

    /// <summary>
    /// macOS lists an application twice: once as the app bundle ("Xcode" 26.6, source <c>app</c>) and once as the
    /// installer receipt ("com.apple.pkg.Xcode" 26.6.0.0.1..., source <c>pkgutil</c>). Matching both reports every CVE
    /// twice. A receipt candidate is dropped only when an <c>app</c> entry has the same product AND the same
    /// major.minor version, i.e. it is the same installation. A receipt whose version differs (an older framework or
    /// command-line tool that shares a product name with a newer app) is still matched, so a real finding is not hidden.
    /// </summary>
    public static List<(InstalledSoftware Software, List<(string Product, bool Full)> Candidates)> WithoutReceiptDuplicates(
        List<(InstalledSoftware Software, List<(string Product, bool Full)> Candidates)> items)
    {
        var apps = new Dictionary<string, List<long[]>>();
        foreach (var (s, candidates) in items.Where(x => x.Software.Source == "app"))
        {
            var v = VersionCompare.Parse(s.Version);
            foreach (var (product, _) in candidates)
            {
                if (!apps.TryGetValue(product, out var list))
                {
                    apps[product] = list = [];
                }
                list.Add(v);
            }
        }
        static bool SameRelease(long[] a, long[] b) => a.Length >= 2 && b.Length >= 2 && a[0] == b[0] && a[1] == b[1];
        var result = new List<(InstalledSoftware, List<(string, bool)>)>(items.Count);
        foreach (var (s, candidates) in items)
        {
            if (s.Source != "pkgutil")
            {
                result.Add((s, candidates));
                continue;
            }
            var receipt = VersionCompare.Parse(s.Version);
            var remaining = candidates.Where(c => !(apps.TryGetValue(c.Product, out var versions) && versions.Any(v => SameRelease(v, receipt)))).ToList();
            if (remaining.Count > 0)
            {
                result.Add((s, remaining));
            }
        }
        return result;
    }

    public async Task<int> MatchDeviceAsync(Guid deviceId, CancellationToken ct)
    {
        var device = await db.Devices.AsNoTracking().FirstOrDefaultAsync(d => d.Id == deviceId, ct);
        if (device is null)
        {
            return 0;
        }
        var software = await db.InstalledSoftware.AsNoTracking().Where(s => s.DeviceId == deviceId).ToListAsync(ct);
        var now = clock.GetUtcNow();
        var found = new Dictionary<(string, string), DeviceVulnerability>();
        var bySoftware = software.Where(s => !SkippedSources.Contains(s.Source) && s.Version.Length > 0)
            .Select(s => (Software: s, Candidates: Candidates(s.Name, s.PackageId))).Where(x => x.Candidates.Count > 0).ToList();
        bySoftware = WithoutReceiptDuplicates(bySoftware);
        var allProducts = bySoftware.SelectMany(x => x.Candidates.Select(c => c.Product)).Distinct().ToArray();
        if (allProducts.Length > 0)
        {
            var entries = await db.CveEntries.AsNoTracking().Where(e => e.Products.Any(p => allProducts.Contains(p))).Take(20_000).ToListAsync(ct);
            // Index ranges by product so the work is (software x its own candidates), not (software x all entries).
            var byProduct = new Dictionary<string, List<(CveEntry Entry, CpeRange Range)>>();
            foreach (var entry in entries)
            {
                foreach (var range in (JsonSerializer.Deserialize<List<CpeRange>>(entry.MatchJson, JsonSerializerOptions.Web) ?? []).Take(500))
                {
                    var key = range.Product.ToLowerInvariant();
                    if (!byProduct.TryGetValue(key, out var list))
                    {
                        byProduct[key] = list = [];
                    }
                    list.Add((entry, range));
                }
            }
            var budget = 200_000; // hard cap on range comparisons per device
            foreach (var (s, candidates) in bySoftware)
            {
                var hay = (s.Publisher + " " + s.Name + " " + s.PackageId).ToLowerInvariant();
                foreach (var (product, full) in candidates)
                {
                    if (!byProduct.TryGetValue(product, out var ranges))
                    {
                        continue;
                    }
                    foreach (var (entry, r) in ranges)
                    {
                        if (--budget < 0)
                        {
                            break;
                        }
                        // A partial-name match needs the CPE vendor to appear in the publisher/name to count.
                        var vendorOk = full || hay.Contains(r.Vendor.Replace('_', ' ').ToLowerInvariant()) || hay.Contains(r.Vendor.ToLowerInvariant());
                        if (vendorOk && !found.ContainsKey((entry.Id, s.Name)) && VersionCompare.InRange(s.Version, r))
                        {
                            found[(entry.Id, s.Name)] = new DeviceVulnerability
                            {
                                Id = Guid.NewGuid(), PartnerId = device.PartnerId, OrganizationId = device.OrganizationId, DeviceId = device.Id, CveId = entry.Id,
                                SoftwareName = s.Name, SoftwareVersion = s.Version, Severity = entry.Severity, CvssScore = entry.CvssScore, KnownExploited = entry.KnownExploited, DetectedAt = now,
                            };
                        }
                    }
                }
            }
        }
        var existing = await db.DeviceVulnerabilities.Where(v => v.DeviceId == deviceId).ToListAsync(ct);
        foreach (var gone in existing.Where(e => !found.ContainsKey((e.CveId, e.SoftwareName))))
        {
            db.DeviceVulnerabilities.Remove(gone);
        }
        foreach (var (key, v) in found)
        {
            var old = existing.FirstOrDefault(e => e.CveId == key.Item1 && e.SoftwareName == key.Item2);
            if (old is null)
            {
                db.DeviceVulnerabilities.Add(v);
            }
            else
            {
                old.SoftwareVersion = v.SoftwareVersion;
                old.Severity = v.Severity;
                old.CvssScore = v.CvssScore;
                old.KnownExploited = v.KnownExploited;
            }
        }
        await db.SaveChangesAsync(ct);
        return found.Count;
    }
}

/// <summary>Downloads CISA KEV and NVD (incrementally) when <c>Dranzo:Feeds:Enabled</c> is true.</summary>
public sealed class VulnerabilityFeedService(IServiceScopeFactory scopes, ILogger<VulnerabilityFeedService> log, IOptions<DranzoOptions> options, IHttpClientFactory httpFactory)
    : PeriodicService(scopes, log, TimeSpan.FromMinutes(30))
{
    protected override async Task TickAsync(IServiceProvider sp, CancellationToken ct)
    {
        var feeds = options.Value.Feeds;
        if (!feeds.Enabled)
        {
            return;
        }
        var db = sp.GetRequiredService<DranzoDbContext>();
        var now = sp.GetRequiredService<TimeProvider>().GetUtcNow();
        var state = await db.FeedStates.FirstOrDefaultAsync(f => f.Name == "nvd", ct);
        if (state is null)
        {
            state = new FeedState { Name = "nvd" };
            db.FeedStates.Add(state);
        }
        if (state.LastSyncedAt is { } last && now - last < TimeSpan.FromHours(feeds.SyncHours))
        {
            return;
        }
        var http = httpFactory.CreateClient();
        http.Timeout = TimeSpan.FromMinutes(2);
        try
        {
            // NVD allows at most 120 days per modified-date window; walk forward from the cursor (first run: last 120 days).
            var from = state.LastModifiedCursor ?? now.AddDays(-119);
            while (from < now)
            {
                var to = from.AddDays(119) < now ? from.AddDays(119) : now;
                for (var start = 0; ;)
                {
                    var url = $"{feeds.NvdUrl}?lastModStartDate={Uri.EscapeDataString(from.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.000Z"))}&lastModEndDate={Uri.EscapeDataString(to.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.000Z"))}&resultsPerPage=2000&startIndex={start}";
                    using var request = new HttpRequestMessage(HttpMethod.Get, url);
                    if (!string.IsNullOrEmpty(feeds.NvdApiKey))
                    {
                        request.Headers.Add("apiKey", feeds.NvdApiKey);
                    }
                    using var response = await http.SendAsync(request, ct);
                    response.EnsureSuccessStatusCode();
                    using var doc = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
                    state.Items += await VulnerabilityFeed.ImportNvdAsync(db, doc.RootElement, now, ct);
                    var total = doc.RootElement.Long("totalResults") ?? 0;
                    start += 2000;
                    if (start >= total)
                    {
                        break;
                    }
                    await Task.Delay(string.IsNullOrEmpty(feeds.NvdApiKey) ? 6500 : 800, ct); // NVD rate limits
                }
                state.LastModifiedCursor = to;
                await db.SaveChangesAsync(ct);
                from = to;
            }
            using (var kev = await http.GetAsync(feeds.KevUrl, ct))
            {
                kev.EnsureSuccessStatusCode();
                using var doc = await JsonDocument.ParseAsync(await kev.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
                await VulnerabilityFeed.ImportKevAsync(db, doc.RootElement, now, ct);
            }
            state.LastSyncedAt = now;
            state.LastError = null;
            await db.SaveChangesAsync(ct);

            var matcher = sp.GetRequiredService<VulnerabilityMatcher>();
            var engine = sp.GetRequiredService<AlertEngine>();
            foreach (var id in await db.Devices.Where(d => d.Status == DeviceStatus.Active).Select(d => d.Id).ToListAsync(ct))
            {
                await matcher.MatchDeviceAsync(id, ct);
                await engine.EvaluateDeviceAsync(id, ct);
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException)
        {
            state.LastError = ex.Message.Length > 500 ? ex.Message[..500] : ex.Message;
            await db.SaveChangesAsync(CancellationToken.None);
            log.LogWarning("Vulnerability feed sync failed: {Error}", state.LastError);
        }
    }
}
