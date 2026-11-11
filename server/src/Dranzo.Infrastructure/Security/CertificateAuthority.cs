using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dranzo.Infrastructure.Security;

public sealed record IssuedCertificate(string CertificatePem, string Thumbprint, DateTimeOffset NotAfter);

/// <summary>
/// Private CA for device client certificates and the agent listener's server certificate.
/// Built only on <see cref="CertificateRequest"/> / <see cref="X509Chain"/> from the BCL.
/// </summary>
public sealed class CertificateAuthority : IDisposable
{
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    private const string EcPublicKeyOid = "1.2.840.10045.2.1";
    private const string P256Oid = "1.2.840.10045.3.1.7";

    private readonly X509Certificate2 _ca;
    private readonly Lock _lock = new();
    private readonly string[] _serverNames;
    private X509Certificate2? _serverCert;

    public CertificateAuthority(IKeyStore keys, IEnumerable<string> serverNames, bool allowCreate = true)
    {
        _serverNames = [.. serverNames.Where(n => !string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.OrdinalIgnoreCase)];
        var keyBytes = keys.Get("device-ca-key");
        var certBytes = keys.Get("device-ca-cert");
        if (keyBytes is null || certBytes is null)
        {
            KeyStoreGuard.RequireCreateAllowed(allowCreate, "device-ca-key");
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var req = new CertificateRequest("CN=DranzoRMM Device CA, O=DranzoRMM", key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(10));
            keyBytes = key.ExportPkcs8PrivateKey();
            certBytes = cert.Export(X509ContentType.Cert);
            keys.Put("device-ca-key", keyBytes);
            keys.Put("device-ca-cert", certBytes);
        }
        using var pub = X509CertificateLoader.LoadCertificate(certBytes);
        using var caKey = ECDsa.Create();
        caKey.ImportPkcs8PrivateKey(keyBytes, out _);
        _ca = pub.CopyWithPrivateKey(caKey);
    }

    public string CaCertificatePem => _ca.ExportCertificatePem();

    public string CaThumbprint => Thumbprint(_ca);

    public static string Thumbprint(X509Certificate2 cert) => Convert.ToHexStringLower(SHA256.HashData(cert.RawData));

    /// <summary>
    /// Issues a client certificate for a device from a PEM CSR. The CSR subject and extensions are ignored;
    /// only the public key (which must be ECDSA P-256 and must have signed the CSR) is used.
    /// </summary>
    public IssuedCertificate IssueDeviceCertificate(string csrPem, Guid deviceId, TimeSpan validity)
    {
        if (csrPem.Length > 8192)
        {
            throw new CryptographicException("CSR too large.");
        }
        // LoadSigningRequestPem verifies the CSR's self-signature (proof of possession) by default.
        var csr = CertificateRequest.LoadSigningRequestPem(csrPem, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.Default);
        RequireP256(csr.PublicKey);

        var req = new CertificateRequest(new X500DistinguishedName($"CN={deviceId:D}, O=DranzoRMM Device"), csr.PublicKey, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ClientAuthOid)], true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri($"urn:dranzo:device:{deviceId:D}"));
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_ca, true, false));

        var notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
        var notAfter = Min(DateTimeOffset.UtcNow.Add(validity), _ca.NotAfter.ToUniversalTime().AddDays(-1));
        using var cert = req.Create(_ca, notBefore, notAfter, NewSerial());
        return new IssuedCertificate(cert.ExportCertificatePem(), Thumbprint(cert), notAfter);
    }

    /// <summary>Validates a presented client certificate against this CA only (never the OS trust store).</summary>
    public bool ValidateClientCertificate(X509Certificate2 cert)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // revocation is the per-device thumbprint check in the gateway
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ClientAuthOid));
        chain.ChainPolicy.DisableCertificateDownloads = true;
        return chain.Build(cert) && chain.ChainElements.Count == 2
            && chain.ChainElements[^1].Certificate.RawData.AsSpan().SequenceEqual(_ca.RawData);
    }

    /// <summary>Server certificate for the agent listener, issued by this CA, renewed in memory before expiry.</summary>
    public X509Certificate2 GetServerCertificate()
    {
        lock (_lock)
        {
            if (_serverCert is not null && _serverCert.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddDays(7))
            {
                return _serverCert;
            }
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var primary = _serverNames.Length > 0 ? _serverNames[0] : "localhost";
            var req = new CertificateRequest($"CN={primary}, O=DranzoRMM Agent Gateway", key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ServerAuthOid)], true));
            var san = new SubjectAlternativeNameBuilder();
            foreach (var name in _serverNames.DefaultIfEmpty("localhost"))
            {
                if (IPAddress.TryParse(name, out var ip))
                {
                    san.AddIpAddress(ip);
                }
                else
                {
                    san.AddDnsName(name);
                }
            }
            req.CertificateExtensions.Add(san.Build());
            req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(_ca, true, false));
            using var issued = req.Create(_ca, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(60), NewSerial());
            using var withKey = issued.CopyWithPrivateKey(key);
            // Round-trip through PKCS#12 so the key is usable by SslStream on every OS.
            _serverCert = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
            return _serverCert;
        }
    }

    private static void RequireP256(PublicKey key)
    {
        if (key.Oid.Value != EcPublicKeyOid)
        {
            throw new CryptographicException("CSR key must be ECDSA P-256.");
        }
        var reader = new AsnReader(key.EncodedParameters!.RawData, AsnEncodingRules.DER);
        if (reader.ReadObjectIdentifier() != P256Oid)
        {
            throw new CryptographicException("CSR key must be ECDSA P-256.");
        }
    }

    private static byte[] NewSerial()
    {
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F; // positive
        if (serial[0] == 0)
        {
            serial[0] = 1;
        }
        return serial;
    }

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a < b ? a : b;

    public void Dispose()
    {
        _ca.Dispose();
        _serverCert?.Dispose();
    }
}
