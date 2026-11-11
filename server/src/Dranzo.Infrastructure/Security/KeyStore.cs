using System.Security.Cryptography;
using System.Text;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;

namespace Dranzo.Infrastructure.Security;

/// <summary>Holds long-lived private key material. Never backed by the repository or the database.</summary>
public interface IKeyStore
{
    byte[]? Get(string name);
    void Put(string name, byte[] value);
}

/// <summary>Development / single-node keystore: one file per key, directory 0700, files 0600.</summary>
public sealed class FileKeyStore : IKeyStore
{
    private readonly string _dir;

    public FileKeyStore(string directory)
    {
        _dir = Path.GetFullPath(directory);
        Directory.CreateDirectory(_dir);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(_dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
    }

    private string PathFor(string name)
    {
        if (name.Length is 0 or > 64 || name.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-')))
        {
            throw new ArgumentException("Invalid key name.", nameof(name));
        }
        return Path.Combine(_dir, name + ".key");
    }

    public byte[]? Get(string name)
    {
        var path = PathFor(name);
        return File.Exists(path) ? Convert.FromBase64String(File.ReadAllText(path)) : null;
    }

    public void Put(string name, byte[] value)
    {
        var path = PathFor(name);
        var tmp = path + ".tmp";
        var options = new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        using (var fs = new FileStream(tmp, options))
        {
            fs.Write(Encoding.ASCII.GetBytes(Convert.ToBase64String(value)));
        }
        File.Move(tmp, path, overwrite: true);
    }
}

/// <summary>
/// Production keystore: Azure Key Vault secrets via managed identity.
/// Key Vault <i>keys</i> cannot hold Ed25519, so key material is stored as secrets and loaded into memory.
/// </summary>
public sealed class KeyVaultKeyStore(Uri vaultUri) : IKeyStore
{
    private readonly SecretClient _client = new(vaultUri, new DefaultAzureCredential());

    public byte[]? Get(string name)
    {
        try
        {
            return Convert.FromBase64String(_client.GetSecret(name).Value.Value);
        }
        catch (Azure.RequestFailedException ex) when (ex.Status == 404)
        {
            return null;
        }
    }

    public void Put(string name, byte[] value) => _client.SetSecret(name, Convert.ToBase64String(value));
}

public static class Hashing
{
    public static string Sha256Hex(ReadOnlySpan<byte> data) => Convert.ToHexStringLower(SHA256.HashData(data));

    public static string Sha256Hex(string text) => Sha256Hex(Encoding.UTF8.GetBytes(text));

    /// <summary>Random URL-safe secret with a readable prefix, e.g. <c>dz_enroll_...</c>.</summary>
    public static string NewToken(string prefix, int bytes = 32) =>
        prefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
