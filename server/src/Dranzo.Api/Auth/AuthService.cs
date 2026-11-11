using System.Security.Cryptography;
using Dranzo.Domain;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OtpNet;

namespace Dranzo.Api.Auth;

public enum LoginStatus { Invalid, Locked, MfaRequired, MfaEnrollmentRequired }

public sealed record LoginResult(LoginStatus Status, string? ChallengeToken = null);

public sealed record SessionIssued(string Token, string CsrfToken, User User, string[]? RecoveryCodes = null);

public static class PasswordPolicy
{
    private static readonly HashSet<string> Common = new(StringComparer.OrdinalIgnoreCase)
    {
        "password1234", "123456789012", "qwertyuiop12", "passwordpassword", "letmeinletmein", "administrator", "changeme1234",
        "welcome12345", "iloveyou1234", "1234567890ab", "qwerty123456", "password12345", "adminadmin12",
    };

    public static string? Validate(string password, string email, int minLength)
    {
        if (password.Length < minLength)
        {
            return $"Password must be at least {minLength} characters.";
        }
        if (password.Length > 128)
        {
            return "Password must be at most 128 characters.";
        }
        if (password.Distinct().Count() < 5)
        {
            return "Password is too repetitive.";
        }
        var local = email.Split('@')[0];
        if (local.Length >= 4 && password.Contains(local, StringComparison.OrdinalIgnoreCase))
        {
            return "Password must not contain your email name.";
        }
        if (Common.Contains(password))
        {
            return "Password is too common.";
        }
        return null;
    }
}

/// <summary>Password + mandatory TOTP login, sessions, step-up. No MFA exemptions exist anywhere in this class.</summary>
public sealed class AuthService(
    DranzoDbContext db,
    SecretProtector secrets,
    IOptions<DranzoOptions> options,
    IAuditLog audit,
    TimeProvider clock)
{
    private static readonly PasswordHasher<User> Hasher = new();
    private static readonly string DummyHash = Hasher.HashPassword(null!, "dummy-password-for-timing");
    private readonly AuthOptions _opt = options.Value.Auth;
    private const string ChallengePurpose = "login-challenge";
    private const string TotpPurpose = "totp-secret";

    /// <summary>80 random bits, shown as four groups of five hex digits. Stored as SHA-256 (enough for a random value this long).</summary>
    private static string NewRecoveryCode()
    {
        var hex = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(10));
        return $"{hex[..5]}-{hex[5..10]}-{hex[10..15]}-{hex[15..]}";
    }

    public static string HashPassword(string password) => Hasher.HashPassword(null!, password);

    public async Task<LoginResult> LoginAsync(string email, string password, string? ip, CancellationToken ct)
    {
        email = email.Trim().ToLowerInvariant();
        var user = await db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Email == email, ct);
        var now = clock.GetUtcNow();
        if (user is null || user.Disabled)
        {
            Hasher.VerifyHashedPassword(null!, DummyHash, password); // equalise timing
            return new LoginResult(LoginStatus.Invalid);
        }
        if (user.LockoutEnd is { } until && until > now)
        {
            await audit.WriteAsync(user.PartnerId, new AuditEntry("auth.login", "denied", Detail: new { reason = "locked" }, ActorType: "user", ActorId: user.Id, ActorName: user.Email, Ip: ip), ct);
            return new LoginResult(LoginStatus.Locked);
        }
        var verify = Hasher.VerifyHashedPassword(user, user.PasswordHash, password);
        if (verify == PasswordVerificationResult.Failed)
        {
            await RegisterFailureAsync(user, "bad_password", ip, ct);
            return new LoginResult(LoginStatus.Invalid);
        }
        if (verify == PasswordVerificationResult.SuccessRehashNeeded)
        {
            user.PasswordHash = Hasher.HashPassword(user, password);
            await db.SaveChangesAsync(ct);
        }
        var token = secrets.ProtectTimed(ChallengePurpose, $"{user.Id:D}|{user.PasswordChangedAt.ToUnixTimeSeconds()}", now.AddMinutes(5));
        return new LoginResult(user.TotpEnabled ? LoginStatus.MfaRequired : LoginStatus.MfaEnrollmentRequired, token);
    }

    private async Task<User?> UserFromChallengeAsync(string challengeToken, CancellationToken ct)
    {
        var plain = secrets.UnprotectTimed(ChallengePurpose, challengeToken, clock.GetUtcNow());
        if (plain is null)
        {
            return null;
        }
        var parts = plain.Split('|');
        if (parts.Length != 2 || !Guid.TryParse(parts[0], out var id))
        {
            return null;
        }
        var user = await db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null || user.Disabled || user.PasswordChangedAt.ToUnixTimeSeconds().ToString() != parts[1])
        {
            return null;
        }
        return user.LockoutEnd is { } until && until > clock.GetUtcNow() ? null : user;
    }

    public async Task<(string Secret, string Uri)?> StartTotpEnrollmentAsync(string challengeToken, CancellationToken ct)
    {
        var user = await UserFromChallengeAsync(challengeToken, ct);
        if (user is null || user.TotpEnabled)
        {
            return null;
        }
        var secret = KeyGeneration.GenerateRandomKey(20);
        user.TotpSecretProtected = secrets.Protect(TotpPurpose, Convert.ToBase64String(secret));
        await db.SaveChangesAsync(ct);
        var b32 = Base32Encoding.ToString(secret);
        var uri = new OtpUri(OtpType.Totp, b32, user.Email, _opt.Issuer).ToString();
        return (b32, uri);
    }

    public async Task<SessionIssued?> CompleteTotpEnrollmentAsync(string challengeToken, string code, string? ip, string? userAgent, CancellationToken ct)
    {
        var user = await UserFromChallengeAsync(challengeToken, ct);
        if (user is null || user.TotpEnabled || user.TotpSecretProtected is null)
        {
            return null;
        }
        if (!VerifyTotp(user, code))
        {
            await RegisterFailureAsync(user, "bad_totp_enrollment", ip, ct);
            return null;
        }
        user.TotpEnabled = true;
        var codes = Enumerable.Range(0, 10).Select(_ => NewRecoveryCode()).ToArray();
        user.RecoveryCodeHashes = [.. codes.Select(Hashing.Sha256Hex)];
        await audit.WriteAsync(user.PartnerId, new AuditEntry("auth.mfa.enrolled", TargetType: "user", TargetId: user.Id.ToString(), ActorType: "user", ActorId: user.Id, ActorName: user.Email, Ip: ip), ct);
        var session = await CreateSessionAsync(user, ip, userAgent, ct);
        return session with { RecoveryCodes = codes };
    }

    public async Task<SessionIssued?> VerifyMfaAsync(string challengeToken, string? code, string? recoveryCode, string? ip, string? userAgent, CancellationToken ct)
    {
        var user = await UserFromChallengeAsync(challengeToken, ct);
        if (user is null || !user.TotpEnabled)
        {
            return null;
        }
        var ok = false;
        if (!string.IsNullOrWhiteSpace(code))
        {
            ok = VerifyTotp(user, code);
        }
        else if (!string.IsNullOrWhiteSpace(recoveryCode))
        {
            var hash = Hashing.Sha256Hex(recoveryCode.Trim().ToLowerInvariant());
            if (user.RecoveryCodeHashes.Contains(hash))
            {
                user.RecoveryCodeHashes = [.. user.RecoveryCodeHashes.Where(h => h != hash)];
                ok = true;
                await audit.WriteAsync(user.PartnerId, new AuditEntry("auth.mfa.recovery_code_used", TargetType: "user", TargetId: user.Id.ToString(), ActorType: "user", ActorId: user.Id, ActorName: user.Email, Ip: ip), ct);
            }
        }
        if (!ok)
        {
            await RegisterFailureAsync(user, "bad_mfa", ip, ct);
            return null;
        }
        return await CreateSessionAsync(user, ip, userAgent, ct);
    }

    /// <summary>Verifies a TOTP code and burns its time step so it cannot be replayed.</summary>
    public bool VerifyTotp(User user, string code)
    {
        code = code.Replace(" ", "", StringComparison.Ordinal).Trim();
        if (user.TotpSecretProtected is null || code.Length != 6 || !code.All(char.IsAsciiDigit))
        {
            return false;
        }
        if (secrets.Unprotect(TotpPurpose, user.TotpSecretProtected) is not { } seed)
        {
            return false;
        }
        var secret = Convert.FromBase64String(seed);
        var totp = new Totp(secret);
        if (!totp.VerifyTotp(clock.GetUtcNow().UtcDateTime, code, out var step, new VerificationWindow(1, 1)) || step <= user.LastTotpStep)
        {
            return false;
        }
        user.LastTotpStep = step;
        return true;
    }

    private async Task<SessionIssued> CreateSessionAsync(User user, string? ip, string? userAgent, CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var token = Hashing.NewToken("dz_sess_");
        var session = new UserSession
        {
            Id = Guid.NewGuid(),
            PartnerId = user.PartnerId,
            UserId = user.Id,
            TokenHash = Hashing.Sha256Hex(token),
            CsrfToken = Hashing.NewToken("", 24),
            CreatedAt = now,
            LastSeenAt = now,
            ExpiresAt = now.AddHours(_opt.SessionAbsoluteHours),
            Ip = ip,
            UserAgent = userAgent is { Length: > 256 } ? userAgent[..256] : userAgent,
        };
        db.UserSessions.Add(session);
        user.FailedLogins = 0;
        user.LockoutEnd = null;
        user.LastLoginAt = now;
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(user.PartnerId, new AuditEntry("auth.login", TargetType: "user", TargetId: user.Id.ToString(), ActorType: "user", ActorId: user.Id, ActorName: user.Email, Ip: ip), ct);
        return new SessionIssued(token, session.CsrfToken, user);
    }

    private async Task RegisterFailureAsync(User user, string reason, string? ip, CancellationToken ct)
    {
        user.FailedLogins++;
        var locked = user.FailedLogins >= _opt.LockoutThreshold;
        if (locked)
        {
            user.LockoutEnd = clock.GetUtcNow().AddMinutes(_opt.LockoutMinutes);
            user.FailedLogins = 0;
        }
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(user.PartnerId, new AuditEntry("auth.login", "failure", Detail: new { reason, locked }, ActorType: "user", ActorId: user.Id, ActorName: user.Email, Ip: ip), ct);
    }

    public async Task<bool> StepUpAsync(Guid sessionId, string code, CancellationToken ct)
    {
        var session = await db.UserSessions.IgnoreQueryFilters().FirstOrDefaultAsync(s => s.Id == sessionId, ct);
        if (session is null)
        {
            return false;
        }
        var user = await db.Users.IgnoreQueryFilters().FirstAsync(u => u.Id == session.UserId, ct);
        if (user.LockoutEnd is { } until && until > clock.GetUtcNow())
        {
            return false;
        }
        if (!VerifyTotp(user, code))
        {
            await RegisterFailureAsync(user, "bad_step_up", session.Ip, ct);
            return false;
        }
        session.StepUpAt = clock.GetUtcNow();
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(user.PartnerId, new AuditEntry("auth.step_up", ActorType: "user", ActorId: user.Id, ActorName: user.Email, Ip: session.Ip), ct);
        return true;
    }

    public async Task<string[]> RegenerateRecoveryCodesAsync(Guid userId, CancellationToken ct)
    {
        var user = await db.Users.IgnoreQueryFilters().FirstAsync(u => u.Id == userId, ct);
        var codes = Enumerable.Range(0, 10).Select(_ => NewRecoveryCode()).ToArray();
        user.RecoveryCodeHashes = [.. codes.Select(Hashing.Sha256Hex)];
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(user.PartnerId, new AuditEntry("auth.recovery_codes_regenerated", TargetType: "user", TargetId: user.Id.ToString()), ct);
        return codes;
    }

    public async Task LogoutAsync(Guid sessionId, CancellationToken ct)
    {
        var session = await db.UserSessions.IgnoreQueryFilters().FirstOrDefaultAsync(s => s.Id == sessionId, ct);
        if (session is not null && session.RevokedAt is null)
        {
            session.RevokedAt = clock.GetUtcNow();
            await db.SaveChangesAsync(ct);
        }
    }

    /// <summary>Changes the password and revokes every other session of the user.</summary>
    public async Task<string?> ChangePasswordAsync(Guid userId, Guid keepSessionId, string current, string next, CancellationToken ct)
    {
        var user = await db.Users.IgnoreQueryFilters().FirstAsync(u => u.Id == userId, ct);
        if (Hasher.VerifyHashedPassword(user, user.PasswordHash, current) == PasswordVerificationResult.Failed)
        {
            await RegisterFailureAsync(user, "bad_password_change", null, ct);
            return "Current password is incorrect.";
        }
        var problem = PasswordPolicy.Validate(next, user.Email, _opt.PasswordMinLength);
        if (problem is not null)
        {
            return problem;
        }
        user.PasswordHash = Hasher.HashPassword(user, next);
        user.PasswordChangedAt = clock.GetUtcNow();
        user.MustChangePassword = false;
        var now = clock.GetUtcNow();
        await db.UserSessions.IgnoreQueryFilters().Where(s => s.UserId == userId && s.Id != keepSessionId && s.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedAt, now), ct);
        await db.SaveChangesAsync(ct);
        await audit.WriteAsync(user.PartnerId, new AuditEntry("auth.password_changed", TargetType: "user", TargetId: user.Id.ToString()), ct);
        return null;
    }
}
