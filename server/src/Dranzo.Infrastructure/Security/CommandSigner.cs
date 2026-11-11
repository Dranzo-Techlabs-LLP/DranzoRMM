using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Dranzo.Infrastructure.Security;

/// <summary>Signs agent commands with Ed25519 (docs/PROTOCOL.md section 4.1).</summary>
public interface ICommandSigner
{
    string KeyId { get; }
    byte[] PublicKey { get; }
    byte[] Sign(string type, ReadOnlySpan<byte> payload);
    byte[] SignRaw(ReadOnlySpan<byte> data);
}

public sealed class Ed25519CommandSigner : ICommandSigner
{
    public const string Prefix = "DRANZO-CMD-V1\n";
    private readonly Ed25519PrivateKeyParameters _key;

    public Ed25519CommandSigner(IKeyStore keys, string keyName = "command-signing-key", bool allowCreate = true)
    {
        var seed = keys.Get(keyName);
        if (seed is null)
        {
            KeyStoreGuard.RequireCreateAllowed(allowCreate, keyName);
            seed = RandomNumberGenerator.GetBytes(32);
            keys.Put(keyName, seed);
        }
        if (seed.Length != 32)
        {
            throw new CryptographicException("Command signing key must be a 32-byte Ed25519 seed.");
        }
        _key = new Ed25519PrivateKeyParameters(seed, 0);
        PublicKey = _key.GeneratePublicKey().GetEncoded();
        KeyId = "cmd-" + Convert.ToHexStringLower(SHA256.HashData(PublicKey))[..16];
    }

    public string KeyId { get; }

    public byte[] PublicKey { get; }

    public byte[] Sign(string type, ReadOnlySpan<byte> payload) => SignRaw(SignatureInput(type, payload));

    public byte[] SignRaw(ReadOnlySpan<byte> data)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, _key);
        signer.BlockUpdate(data);
        return signer.GenerateSignature();
    }

    public static byte[] SignatureInput(string type, ReadOnlySpan<byte> payload)
    {
        var head = Encoding.UTF8.GetBytes(Prefix + type + "\n");
        var buffer = new byte[head.Length + payload.Length];
        head.CopyTo(buffer, 0);
        payload.CopyTo(buffer.AsSpan(head.Length));
        return buffer;
    }

    public static bool Verify(byte[] publicKey, string type, ReadOnlySpan<byte> payload, byte[] signature)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        verifier.BlockUpdate(SignatureInput(type, payload));
        return verifier.VerifySignature(signature);
    }
}

public static class AgentJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };
}

/// <summary>Builds protocol envelopes.</summary>
public sealed class EnvelopeFactory(ICommandSigner signer, TimeProvider clock)
{
    public static readonly TimeSpan DefaultValidity = TimeSpan.FromMinutes(5);

    public string Plain(string type, object payload, Guid? id = null) =>
        JsonSerializer.Serialize(new { type, id = (id ?? Guid.NewGuid()).ToString("D"), version = 1, payload }, AgentJson.Options);

    /// <summary>
    /// Signs a command for one device. <paramref name="fields"/> are merged with the common
    /// <c>deviceId</c>, <c>nonce</c>, <c>issuedAt</c>, <c>expiresAt</c> fields.
    /// </summary>
    public string Signed(string type, Guid deviceId, IDictionary<string, object?> fields, bool withNonce = true, TimeSpan? validity = null)
    {
        var now = clock.GetUtcNow();
        var payload = new Dictionary<string, object?>(fields)
        {
            ["deviceId"] = deviceId.ToString("D"),
            ["issuedAt"] = now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["expiresAt"] = now.Add(validity ?? DefaultValidity).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        };
        if (withNonce)
        {
            payload["nonce"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        }
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, AgentJson.Options);
        return JsonSerializer.Serialize(new
        {
            type,
            id = Guid.NewGuid().ToString("D"),
            version = 1,
            signedPayload = Convert.ToBase64String(bytes),
            signature = Convert.ToBase64String(signer.Sign(type, bytes)),
            keyId = signer.KeyId,
        }, AgentJson.Options);
    }
}
