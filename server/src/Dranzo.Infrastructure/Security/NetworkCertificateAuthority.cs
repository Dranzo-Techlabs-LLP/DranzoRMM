using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dranzo.Infrastructure.Security;

/// <summary>
/// Per-organization CA for 802.1X (EAP-TLS) Wi-Fi: the RADIUS server certificate and one client certificate per
/// device. Separate from the device CA that authenticates agents. Built on <see cref="CertificateRequest"/> and
/// <see cref="CertificateRevocationListBuilder"/> from the BCL.
///
/// Windows needs this CA in the machine's trusted roots to validate the RADIUS server. So that it cannot be misused
/// to impersonate websites, the CA certificate carries critical name constraints: DNS names only under
/// <see cref="ServerDomain"/>, and no IP addresses at all.
/// </summary>
public sealed class NetworkCertificateAuthority(IKeyStore keys)
{
    public const string ServerDomain = "dranzo-radius.invalid";
    public const string RadiusServerName = "radius." + ServerDomain;
    private const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    private static readonly Lock CreateLock = new();

    private static string KeyName(Guid orgId) => $"netca-{orgId:N}-key";
    private static string CertName(Guid orgId) => $"netca-{orgId:N}-cert";

    public bool Exists(Guid orgId) => keys.Get(CertName(orgId)) is not null;

    /// <summary>Name constraints: permitted dNSName subtree <see cref="ServerDomain"/>; all IPv4 and IPv6 addresses excluded.</summary>
    public static X509Extension NameConstraints()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        {
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            using (w.PushSequence())
            {
                w.WriteCharacterString(UniversalTagNumber.IA5String, ServerDomain, new Asn1Tag(TagClass.ContextSpecific, 2));
            }
            using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            {
                foreach (var len in new[] { 8, 32 }) // address + mask, all zero: every IPv4 / IPv6 address
                {
                    using (w.PushSequence())
                    {
                        w.WriteOctetString(new byte[len], new Asn1Tag(TagClass.ContextSpecific, 7));
                    }
                }
            }
        }
        return new X509Extension("2.5.29.30", w.Encode(), critical: true);
    }

    /// <summary>The organization's CA (created on first use).</summary>
    public X509Certificate2 GetOrCreate(Guid orgId)
    {
        lock (CreateLock)
        {
            var keyBytes = keys.Get(KeyName(orgId));
            var certBytes = keys.Get(CertName(orgId));
            if (keyBytes is null || certBytes is null)
            {
                using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var req = new CertificateRequest($"CN=DranzoRMM Network CA, OU={orgId:D}, O=DranzoRMM", key, HashAlgorithmName.SHA256);
                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
                req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
                req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
                req.CertificateExtensions.Add(NameConstraints());
                using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(10));
                keyBytes = key.ExportPkcs8PrivateKey();
                certBytes = cert.Export(X509ContentType.Cert);
                keys.Put(KeyName(orgId), keyBytes);
                keys.Put(CertName(orgId), certBytes);
            }
            using var pub = X509CertificateLoader.LoadCertificate(certBytes);
            using var caKey = ECDsa.Create();
            caKey.ImportPkcs8PrivateKey(keyBytes, out _);
            return pub.CopyWithPrivateKey(caKey);
        }
    }

    public string CaPem(Guid orgId)
    {
        using var ca = GetOrCreate(orgId);
        return ca.ExportCertificatePem();
    }

    private static byte[] NewSerial()
    {
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7f;
        return serial;
    }

    /// <summary>RADIUS server certificate and its private key (for the FreeRADIUS bundle).</summary>
    public (string CertPem, string KeyPem) IssueServer(Guid orgId)
    {
        using var ca = GetOrCreate(orgId);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={RadiusServerName}, O=DranzoRMM", key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ServerAuthOid)], false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(RadiusServerName);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, false));
        using var cert = req.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddYears(2), NewSerial());
        return (cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem());
    }

    /// <summary>Client certificate for a device's Wi-Fi from its CSR (key generated on the device).</summary>
    public (string CertPem, string SerialHex, string Thumbprint, DateTimeOffset NotAfter) IssueClient(Guid orgId, string csrPem, Guid deviceId)
    {
        if (csrPem.Length > 8192)
        {
            throw new CryptographicException("CSR too large.");
        }
        var csr = CertificateRequest.LoadSigningRequestPem(csrPem, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.Default);
        var alg = csr.PublicKey.Oid.Value;
        if (alg is not ("1.2.840.10045.2.1" or "1.2.840.113549.1.1.1"))
        {
            throw new CryptographicException("Only ECDSA or RSA keys are accepted.");
        }
        if (alg == "1.2.840.113549.1.1.1" && csr.PublicKey.GetRSAPublicKey() is { KeySize: < 2048 })
        {
            throw new CryptographicException("RSA keys must be at least 2048 bits.");
        }
        using var ca = GetOrCreate(orgId);
        var req = new CertificateRequest(new X500DistinguishedName($"CN={deviceId:D}, O=DranzoRMM Wi-Fi"), csr.PublicKey, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(ClientAuthOid)], false));
        var san = new SubjectAlternativeNameBuilder();
        san.AddUri(new Uri($"urn:dranzo:device:{deviceId:D}"));
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(ca, true, false));
        var serial = NewSerial();
        var notAfter = DateTimeOffset.UtcNow.AddYears(1);
        using var cert = req.Create(ca, DateTimeOffset.UtcNow.AddMinutes(-5), notAfter, serial);
        return (cert.ExportCertificatePem(), Convert.ToHexString(serial), CertificateAuthority.Thumbprint(cert), notAfter);
    }

    /// <summary>CRL of revoked client certificates, valid for 7 days (FreeRADIUS refreshes it every few minutes).</summary>
    public string CrlPem(Guid orgId, IEnumerable<(string SerialHex, DateTimeOffset RevokedAt)> revoked, long crlNumber, DateTimeOffset now)
    {
        using var ca = GetOrCreate(orgId);
        var builder = new CertificateRevocationListBuilder();
        foreach (var (serial, at) in revoked)
        {
            builder.AddEntry(Convert.FromHexString(serial), at, X509RevocationReason.CessationOfOperation);
        }
        var der = builder.Build(ca, new BigInteger(crlNumber), now.AddDays(7), HashAlgorithmName.SHA256, null, now);
        return PemEncoding.WriteString("X509 CRL", der);
    }
}
