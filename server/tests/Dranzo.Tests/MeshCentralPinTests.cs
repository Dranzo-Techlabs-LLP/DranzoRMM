using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dranzo.Api.Features;
using Xunit;

namespace Dranzo.Tests;

public sealed class MeshCentralPinTests
{
    private static X509Certificate2 SelfSigned(string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    [Fact]
    public void Pinned_certificate_is_accepted_despite_chain_errors_and_others_are_refused()
    {
        using var pinned = SelfSigned("mesh");
        using var other = SelfSigned("attacker");
        var pin = SHA256.HashData(pinned.RawData);

        Assert.True(MeshCentral.PinAccepts(pin, pinned, SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
        Assert.False(MeshCentral.PinAccepts(pin, other, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(MeshCentral.PinAccepts(pin, null, SslPolicyErrors.RemoteCertificateNotAvailable));
        // A certificate that validates normally is still accepted (pin only widens trust to one certificate).
        Assert.True(MeshCentral.PinAccepts(pin, other, SslPolicyErrors.None));
    }

    [Fact]
    public void Handler_without_pin_keeps_default_validation()
    {
        using var handler = MeshCentral.CreateHandler(null);
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-not-hex-not-hex!")]
    public void Malformed_pin_is_rejected_at_startup(string pin) =>
        Assert.Throws<InvalidOperationException>(() => MeshCentral.CreateHandler(pin));

    [Fact]
    public void MeshAgent_settings_must_name_the_server_and_the_group()
    {
        // Shaped like MeshCentral 1.1.44's /meshsettings answer (CRLF, leading blank line, translations).
        const string real = "\r\nMeshName=World Happiness Code\r\nMeshType=2\r\nMeshID=0xF529A416D16FECCA\r\nServerID=ABCDEF\r\nMeshServer=wss://mesh.dranzo.com:443/agent.ashx\r\ntranslation={\"en\":{}}\r\n";
        Assert.True(MeshCentral.IsValidSettings(real));
        Assert.True(MeshCentral.IsValidSettings("MeshID=0x01\nMeshServer=local\n"));
        Assert.False(MeshCentral.IsValidSettings(null));
        Assert.False(MeshCentral.IsValidSettings(""));
        Assert.False(MeshCentral.IsValidSettings("<html>Login</html>"));
        Assert.False(MeshCentral.IsValidSettings("MeshID=0x01\r\n"));
        Assert.False(MeshCentral.IsValidSettings("MeshServer=wss://mesh.dranzo.com/agent.ashx\r\n"));
        Assert.False(MeshCentral.IsValidSettings("MeshID=0x\r\nMeshServer=wss://mesh.dranzo.com/agent.ashx\r\n"));
        Assert.False(MeshCentral.IsValidSettings(real + "\0"));
        Assert.False(MeshCentral.IsValidSettings(real + new string('x', MeshCentral.MaxSettingsBytes)));
    }

    [Fact]
    public void Colon_separated_pin_is_accepted()
    {
        using var cert = SelfSigned("mesh");
        var hex = string.Join(':', SHA256.HashData(cert.RawData).Select(b => b.ToString("X2")));
        using var handler = MeshCentral.CreateHandler(hex);
        Assert.NotNull(handler.SslOptions.RemoteCertificateValidationCallback);
    }
}
