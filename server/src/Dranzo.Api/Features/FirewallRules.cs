using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Dranzo.Api.Features;

/// <summary>
/// Server-side validation of the <c>firewall.rules</c> policy check (the agent validates again). Mirrors
/// <c>agent/internal/firewall/rules.go</c>.
/// </summary>
public static partial class FirewallRules
{
    public const string Check = "firewall.rules";
    public const int MaxRules = 100, MaxPorts = 32, MaxAddresses = 64, MaxProgram = 260;

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}$")]
    private static partial Regex NameRegex();

    [GeneratedRegex(@"^[A-Za-z]:\\[^<>""|?*\x00-\x1f]+$")]
    private static partial Regex ProgramRegex();

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static List<string>? StrList(JsonElement e, string name, int max, out string? error)
    {
        error = null;
        if (!e.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null)
        {
            return [];
        }
        if (v.ValueKind != JsonValueKind.Array || v.GetArrayLength() > max || v.EnumerateArray().Any(x => x.ValueKind != JsonValueKind.String))
        {
            error = $"{name} must be a list of at most {max} strings";
            return null;
        }
        return [.. v.EnumerateArray().Select(x => x.GetString()!.Trim())];
    }

    public static bool ValidPort(string p)
    {
        var parts = p.Split('-', 2);
        if (!int.TryParse(parts[0].Trim(), out var a))
        {
            return false;
        }
        var b = a;
        if (parts.Length == 2 && !int.TryParse(parts[1].Trim(), out b))
        {
            return false;
        }
        return a >= 1 && b <= 65535 && a <= b;
    }

    public static bool ValidAddress(string s)
    {
        if (s.Contains('/', StringComparison.Ordinal))
        {
            return IPNetwork.TryParse(s, out _);
        }
        return IPAddress.TryParse(s, out var a) && !s.Contains('%', StringComparison.Ordinal) && a.ToString().Length > 0;
    }

    /// <summary>Null when <paramref name="p"/> holds a valid <c>rules</c> list; otherwise the problem.</summary>
    public static string? Validate(JsonElement p)
    {
        if (!p.TryGetProperty("rules", out var rules) || rules.ValueKind != JsonValueKind.Array)
        {
            return "params.rules must be a list of rules.";
        }
        if (rules.GetArrayLength() is 0 or > MaxRules)
        {
            return $"Give between 1 and {MaxRules} rules.";
        }
        var i = 0;
        foreach (var r in rules.EnumerateArray())
        {
            i++;
            if (r.ValueKind != JsonValueKind.Object)
            {
                return $"Rule {i} must be an object.";
            }
            var name = Str(r, "name").Trim();
            var label = $"Rule {i} ({name})";
            if (!NameRegex().IsMatch(name))
            {
                return $"Rule {i}: the name must be 1-64 letters, digits, spaces or ._()-.";
            }
            var direction = Str(r, "direction").ToLowerInvariant();
            var action = Str(r, "action").ToLowerInvariant();
            var protocol = Str(r, "protocol").ToLowerInvariant();
            if (direction is not ("in" or "out"))
            {
                return $"{label}: direction must be in or out.";
            }
            if (action is not ("allow" or "block"))
            {
                return $"{label}: action must be allow or block.";
            }
            if (protocol is not ("tcp" or "udp" or "any" or ""))
            {
                return $"{label}: protocol must be tcp, udp or any.";
            }
            var ports = StrList(r, "ports", MaxPorts, out var err);
            if (ports is null)
            {
                return $"{label}: {err}.";
            }
            if (ports.Count > 0 && protocol is "any" or "")
            {
                return $"{label}: ports need protocol tcp or udp.";
            }
            if (ports.FirstOrDefault(x => !ValidPort(x)) is { } badPort)
            {
                return $"{label}: invalid port \"{badPort}\" (use 443 or 8000-8100).";
            }
            var addresses = StrList(r, "remoteAddresses", MaxAddresses, out err);
            if (addresses is null)
            {
                return $"{label}: {err}.";
            }
            if (addresses.FirstOrDefault(x => !ValidAddress(x)) is { } badAddress)
            {
                return $"{label}: invalid address \"{badAddress}\".";
            }
            var program = Str(r, "program").Trim();
            if (program.Length > 0 && (program.Length > MaxProgram || !ProgramRegex().IsMatch(program)))
            {
                return $@"{label}: program must be a full Windows path such as C:\Program Files\App\app.exe.";
            }
            if (direction == "out" && action == "block" && ports.Count == 0 && addresses.Count == 0 && program.Length == 0)
            {
                return $"{label}: blocking all outgoing traffic would cut the device off. Use device isolation instead.";
            }
        }
        return null;
    }
}
