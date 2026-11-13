using Dranzo.Domain;
using Dranzo.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Dranzo.Api.Features;

/// <summary>What the security score of one device is computed from.</summary>
public sealed record ScoreInputs(
    bool? Antivirus,
    bool? Firewall,
    bool? Encryption,
    DateTimeOffset? LastPatchScan,
    int MissingCritical,
    int FailedPatches,
    int PoliciesTotal,
    int PoliciesCompliant,
    bool VulnDataAvailable,
    int VulnHigh,
    int VulnKev,
    bool Isolated);

/// <summary>One part of the score. <c>Earned</c> is null when the part is unknown (not counted).</summary>
public sealed record ScoreComponent(string Key, string Label, int Weight, double? Earned, string Status, string Reason);

public sealed record ScoreResult(int? Score, string Grade, ScoreComponent[] Components, bool Isolated);

/// <summary>
/// Security score 0-100 per device. Unknown parts (not reported, not applicable) are left out and the rest is scaled
/// up, so a device is not punished for data it cannot report; with less than 40 points of known data there is no score.
/// Pure function: the weights and thresholds are unit-tested.
/// </summary>
public static class SecurityScore
{
    public static readonly TimeSpan PatchScanStale = TimeSpan.FromDays(14);
    private const int MinimumKnownWeight = 40;

    public static string Grade(int? score) => score switch
    {
        null => "?",
        >= 90 => "A",
        >= 75 => "B",
        >= 60 => "C",
        >= 40 => "D",
        _ => "F",
    };

    private static ScoreComponent Flag(string key, string label, int weight, bool? ok, string bad) => ok switch
    {
        true => new(key, label, weight, weight, "ok", "On"),
        false => new(key, label, weight, 0, "bad", bad),
        null => new(key, label, weight, null, "unknown", "Not reported"),
    };

    public static ScoreResult Compute(ScoreInputs i, DateTimeOffset now)
    {
        var parts = new List<ScoreComponent>
        {
            Flag("antivirus", "Antivirus", 20, i.Antivirus, "Antivirus off, outdated or missing"),
            Flag("firewall", "Firewall", 15, i.Firewall, "Firewall off"),
            Flag("encryption", "Disk encryption", 15, i.Encryption, "System disk not encrypted"),
        };

        if (i.LastPatchScan is not { } scanned)
        {
            parts.Add(new("patches", "Updates", 20, null, "unknown", "No update scan yet"));
        }
        else
        {
            double earned = i.MissingCritical switch { 0 => 20, <= 2 => 10, _ => 0 };
            var reasons = new List<string>();
            if (i.MissingCritical > 0)
            {
                reasons.Add($"{i.MissingCritical} critical or important update{(i.MissingCritical == 1 ? "" : "s")} missing");
            }
            if (i.FailedPatches > 0)
            {
                earned -= 5;
                reasons.Add($"{i.FailedPatches} failed");
            }
            if (now - scanned > PatchScanStale)
            {
                earned -= 5;
                reasons.Add("last scan over 14 days ago");
            }
            earned = Math.Max(0, earned);
            parts.Add(new("patches", "Updates", 20, earned, earned >= 20 ? "ok" : earned > 0 ? "warn" : "bad",
                reasons.Count == 0 ? "Up to date" : string.Join(", ", reasons)));
        }

        if (i.PoliciesTotal == 0)
        {
            parts.Add(new("policies", "Policy compliance", 15, null, "unknown", "No policies apply"));
        }
        else
        {
            var earned = 15.0 * i.PoliciesCompliant / i.PoliciesTotal;
            var failing = i.PoliciesTotal - i.PoliciesCompliant;
            parts.Add(new("policies", "Policy compliance", 15, earned, failing == 0 ? "ok" : earned > 0 ? "warn" : "bad",
                failing == 0 ? $"All {i.PoliciesTotal} compliant" : $"{failing} of {i.PoliciesTotal} not compliant"));
        }

        if (!i.VulnDataAvailable)
        {
            parts.Add(new("vulnerabilities", "Vulnerabilities", 15, null, "unknown", "Vulnerability feed not loaded"));
        }
        else if (i.VulnKev > 0)
        {
            parts.Add(new("vulnerabilities", "Vulnerabilities", 15, 0, "bad", $"{i.VulnKev} known exploited"));
        }
        else
        {
            double earned = i.VulnHigh switch { 0 => 15, <= 4 => 8, _ => 3 };
            parts.Add(new("vulnerabilities", "Vulnerabilities", 15, earned, i.VulnHigh == 0 ? "ok" : "warn",
                i.VulnHigh == 0 ? "No high or critical" : $"{i.VulnHigh} high or critical"));
        }

        var known = parts.Where(p => p.Earned is not null).ToList();
        var knownWeight = known.Sum(p => p.Weight);
        int? score = knownWeight < MinimumKnownWeight ? null : (int)Math.Round(100.0 * known.Sum(p => p.Earned!.Value) / knownWeight, MidpointRounding.AwayFromZero);
        return new(score, Grade(score), [.. parts], i.Isolated);
    }

    /// <summary>Loads score inputs for the devices visible through <paramref name="db"/>'s tenant filter.</summary>
    public static async Task<Dictionary<Guid, ScoreInputs>> LoadAsync(DranzoDbContext db, Guid? organizationId, Guid? deviceId, CancellationToken ct)
    {
        var devices = await db.Devices.AsNoTracking()
            .Where(d => d.Status == DeviceStatus.Active && (organizationId == null || d.OrganizationId == organizationId) && (deviceId == null || d.Id == deviceId))
            .Select(d => new { d.Id, d.LastPatchScanAt }).ToListAsync(ct);
        var ids = devices.Select(d => d.Id).ToList();
        var posture = await db.PostureSnapshots.AsNoTracking().Where(p => p.IsLatest && ids.Contains(p.DeviceId))
            .Select(p => new { p.DeviceId, p.AntivirusOk, p.FirewallOk, p.EncryptionOk }).ToDictionaryAsync(p => p.DeviceId, ct);
        var patches = await db.DevicePatchStates.AsNoTracking()
            .Where(s => ids.Contains(s.DeviceId) && s.Status != PatchStatus.Installed && s.Status != PatchStatus.Rejected)
            .GroupBy(s => s.DeviceId)
            .Select(g => new
            {
                g.Key,
                Critical = g.Count(x => x.CatalogEntry.Severity == "critical" || x.CatalogEntry.Severity == "important"),
                Failed = g.Count(x => x.Status == PatchStatus.Failed),
            }).ToDictionaryAsync(x => x.Key, ct);
        var enabledPolicies = db.Policies.Where(p => p.Enabled).Select(p => p.Id);
        var compliance = await db.ComplianceResults.AsNoTracking()
            .Where(r => ids.Contains(r.DeviceId) && r.Supported != false && enabledPolicies.Contains(r.PolicyId))
            .GroupBy(r => r.DeviceId)
            .Select(g => new { g.Key, Total = g.Count(), Ok = g.Count(x => x.Compliant) }).ToDictionaryAsync(x => x.Key, ct);
        var vulnData = await db.CveEntries.AnyAsync(ct);
        var vulns = await db.DeviceVulnerabilities.AsNoTracking().Where(v => ids.Contains(v.DeviceId))
            .GroupBy(v => v.DeviceId)
            .Select(g => new { g.Key, High = g.Count(x => x.CvssScore >= 7 || x.Severity == "critical" || x.Severity == "high"), Kev = g.Count(x => x.KnownExploited) })
            .ToDictionaryAsync(x => x.Key, ct);

        return devices.ToDictionary(d => d.Id, d =>
        {
            var p = posture.GetValueOrDefault(d.Id);
            var pa = patches.GetValueOrDefault(d.Id);
            var co = compliance.GetValueOrDefault(d.Id);
            var v = vulns.GetValueOrDefault(d.Id);
            return new ScoreInputs(p?.AntivirusOk, p?.FirewallOk, p?.EncryptionOk, d.LastPatchScanAt, pa?.Critical ?? 0, pa?.Failed ?? 0,
                co?.Total ?? 0, co?.Ok ?? 0, vulnData, v?.High ?? 0, v?.Kev ?? 0, Isolated: false);
        });
    }
}
