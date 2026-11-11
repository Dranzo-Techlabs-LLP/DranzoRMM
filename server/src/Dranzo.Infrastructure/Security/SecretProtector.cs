using System.Security.Cryptography;
using System.Text;

namespace Dranzo.Infrastructure.Security;

/// <summary>
/// Encrypts small secrets that must be stored in the database (TOTP seeds, notification channel settings) and
/// short-lived tokens (login challenge). AES-256-GCM with a key that lives only in the key store, so a copy of
/// the database alone cannot decrypt them. The purpose string is bound as associated data.
/// </summary>
public sealed class SecretProtector
{
    private const string KeyName = "data-encryption-key";
    private readonly byte[] _key;

    public SecretProtector(IKeyStore keys, bool allowCreate)
    {
        var key = keys.Get(KeyName);
        if (key is null)
        {
            KeyStoreGuard.RequireCreateAllowed(allowCreate, KeyName);
            key = RandomNumberGenerator.GetBytes(32);
            keys.Put(KeyName, key);
        }
        if (key.Length != 32)
        {
            throw new CryptographicException("data-encryption-key must be 32 bytes.");
        }
        _key = key;
    }

    public string Protect(string purpose, string plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plain = Encoding.UTF8.GetBytes(plaintext);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(purpose));
        return "v1." + Convert.ToBase64String([.. nonce, .. tag, .. cipher]);
    }

    /// <summary>Returns null when the value was not produced by <see cref="Protect"/> for the same purpose and key.</summary>
    public string? Unprotect(string purpose, string? protectedText)
    {
        if (protectedText is null || !protectedText.StartsWith("v1.", StringComparison.Ordinal) || protectedText.Length > 2_000_000)
        {
            return null;
        }
        try
        {
            var raw = Convert.FromBase64String(protectedText[3..]);
            if (raw.Length < 28)
            {
                return null;
            }
            var plain = new byte[raw.Length - 28];
            using var aes = new AesGcm(_key, 16);
            aes.Decrypt(raw.AsSpan(0, 12), raw.AsSpan(28), raw.AsSpan(12, 16), plain, Encoding.UTF8.GetBytes(purpose));
            return Encoding.UTF8.GetString(plain);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            return null;
        }
    }

    public string ProtectTimed(string purpose, string plaintext, DateTimeOffset expiresAt) => Protect(purpose, expiresAt.ToUnixTimeSeconds() + "|" + plaintext);

    public string? UnprotectTimed(string purpose, string? protectedText, DateTimeOffset now)
    {
        var plain = Unprotect(purpose, protectedText);
        var split = plain?.IndexOf('|') ?? -1;
        if (plain is null || split <= 0 || !long.TryParse(plain[..split], out var expires) || expires < now.ToUnixTimeSeconds())
        {
            return null;
        }
        return plain[(split + 1)..];
    }
}

public static class KeyStoreGuard
{
    /// <summary>
    /// Creating a missing long-lived key is only right on first start. In production an empty or wrong key store
    /// must stop the server, not silently mint new keys that orphan every enrolled agent.
    /// </summary>
    public static void RequireCreateAllowed(bool allowCreate, string keyName)
    {
        if (!allowCreate)
        {
            throw new InvalidOperationException(
                $"Key '{keyName}' was not found in the key store and Dranzo:KeyStore:AllowCreate is false. " +
                "If this is the very first start of a new installation, set it to true once; otherwise check the key store configuration (see docs/RUNBOOK.md).");
        }
    }
}
