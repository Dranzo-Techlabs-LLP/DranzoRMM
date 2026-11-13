using System.Net.Http.Json;
using System.Net.Security;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Dranzo.Infrastructure.Security;

namespace Dranzo.Tests.Infra;

public sealed record AgentMessage(string Type, string Id, JsonElement Payload, bool Signed, bool SignatureValid, string Raw);

/// <summary>
/// A protocol-level stand-in for the Go agent: real mTLS, real WebSocket, verifies server signatures.
/// Used to test the server side of docs/PROTOCOL.md.
/// </summary>
public sealed class TestAgent : IAsyncDisposable
{
    private readonly ServerFixture _fx;
    private readonly X509Certificate2 _ca;
    private Channel<AgentMessage> _incoming = Channel.CreateUnbounded<AgentMessage>();
    private readonly List<AgentMessage> _backlog = [];
    private ClientWebSocket? _ws;
    private Task? _receive;
    private CancellationTokenSource _cts = new();

    private TestAgent(ServerFixture fx, X509Certificate2 ca)
    {
        _fx = fx;
        _ca = ca;
    }

    public Guid DeviceId { get; private set; }
    public X509Certificate2 Certificate { get; private set; } = null!;
    public ECDsa Key { get; private set; } = null!;
    public string Hostname { get; private set; } = "";
    public string Os { get; private set; } = "linux";
    public WebSocketState? State => _ws?.State;
    public string? HandshakeStatusCode { get; private set; }

    public static (ECDsa Key, string CsrPem) NewCsr(string cn = "ignored")
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256);
        return (key, req.CreateSigningRequestPem());
    }

    public bool ValidateServer(X509Certificate? cert, SslPolicyErrors errors)
    {
        if (cert is null || errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            return false;
        }
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(_ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(new X509Certificate2(cert));
    }

    public HttpClient NewHttp(bool withClientCert = true)
    {
        var handler = new SocketsHttpHandler
        {
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, cert, _, errors) => ValidateServer(cert, errors),
                ClientCertificates = withClientCert && Certificate is not null ? [Certificate] : null,
            },
        };
        return new HttpClient(handler) { BaseAddress = new Uri(_fx.AgentUrl) };
    }

    public static X509Certificate2 WithKey(string certPem, ECDsa key)
    {
        using var pub = X509Certificate2.CreateFromPem(certPem);
        using var withKey = pub.CopyWithPrivateKey(key);
        return X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
    }

    public static async Task<(HttpResponseMessage Response, TestAgent Agent)> TryEnrollAsync(ServerFixture fx, string token, string hostname, string os = "linux", string arch = "amd64", string? csrOverride = null, string machineId = "")
    {
        var ca = X509Certificate2.CreateFromPem(fx.Service<CertificateAuthority>().CaCertificatePem);
        var agent = new TestAgent(fx, ca) { Hostname = hostname, Os = os };
        var (key, csr) = NewCsr();
        agent.Key = key;
        using var http = agent.NewHttp(withClientCert: false);
        var response = await http.PostAsJsonAsync("/agent/v1/enroll", new { token, csr = csrOverride ?? csr, hostname, os, arch, agentVersion = "0.1.0-test", machineId });
        if (response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadFromJsonAsync<JsonElement>();
            agent.DeviceId = Guid.Parse(body.GetProperty("deviceId").GetString()!);
            agent.Certificate = WithKey(body.GetProperty("certificate").GetString()!, key);
        }
        return (response, agent);
    }

    public static async Task<TestAgent> EnrollAsync(ServerFixture fx, string token, string hostname, string os = "linux", string arch = "amd64", bool connect = true)
    {
        var (response, agent) = await TryEnrollAsync(fx, token, hostname, os, arch);
        Assert.True(response.IsSuccessStatusCode, $"enroll → {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        if (connect)
        {
            await agent.ConnectAsync();
        }
        return agent;
    }

    public async Task<bool> RenewAsync()
    {
        var (key, csr) = NewCsr();
        using var http = NewHttp();
        var response = await http.PostAsJsonAsync("/agent/v1/renew", new { csr });
        if (!response.IsSuccessStatusCode)
        {
            return false;
        }
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Certificate = WithKey(body.GetProperty("certificate").GetString()!, key);
        Key = key;
        return true;
    }

    /// <summary>Opens the WebSocket with the device certificate and completes hello/hello.ack.</summary>
    public async Task ConnectAsync(bool sendHello = true, X509Certificate2? certOverride = null, string[]? capabilities = null)
    {
        await CloseAsync();
        _incoming = Channel.CreateUnbounded<AgentMessage>();
        lock (_backlog)
        {
            _backlog.Clear();
        }
        _cts = new CancellationTokenSource();
        _ws = new ClientWebSocket();
        _ws.Options.AddSubProtocol("dranzo.agent.v1");
        _ws.Options.ClientCertificates.Add(certOverride ?? Certificate);
        _ws.Options.RemoteCertificateValidationCallback = (_, cert, _, errors) => ValidateServer(cert, errors);
        await _ws.ConnectAsync(new Uri(_fx.AgentUrl.Replace("https://", "wss://", StringComparison.Ordinal) + "/agent/v1/ws"), _cts.Token);
        _receive = Task.Run(ReceiveLoopAsync);
        if (sendHello)
        {
            await SendAsync("hello", new
            {
                agentVersion = "0.1.0-test", protocolVersion = 1, os = Os, arch = "amd64", hostname = Hostname,
                capabilities = capabilities ?? new[] { "script", "inventory.refresh", "software.scan", "software.install", "software.uninstall", "package.install", "package.uninstall", "patch.scan", "patch.install", "posture.scan", "policy.evaluate", "reboot", "file.list", "file.read", "file.write", "mesh.install", "agent.configure", "agent.uninstall", "network.scan", "session.terminal", "session.files", "session.desktop" },
                trustKeyIds = new[] { _fx.Service<ICommandSigner>().KeyId },
            });
            await WaitForAsync("hello.ack");
        }
    }

    private async Task ReceiveLoopAsync()
    {
        var buffer = new byte[64 * 1024];
        var signer = _fx.Service<ICommandSigner>();
        try
        {
            while (_ws!.State == WebSocketState.Open)
            {
                using var ms = new MemoryStream();
                WebSocketReceiveResult result;
                do
                {
                    result = await _ws.ReceiveAsync(buffer, _cts.Token);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        _incoming.Writer.TryComplete();
                        return;
                    }
                    ms.Write(buffer, 0, result.Count);
                }
                while (!result.EndOfMessage);
                var raw = Encoding.UTF8.GetString(ms.ToArray());
                using var doc = JsonDocument.Parse(raw);
                var root = doc.RootElement;
                var type = root.GetProperty("type").GetString()!;
                var id = root.GetProperty("id").GetString()!;
                if (root.TryGetProperty("signedPayload", out var sp))
                {
                    var bytes = Convert.FromBase64String(sp.GetString()!);
                    var sig = Convert.FromBase64String(root.GetProperty("signature").GetString()!);
                    var ok = root.GetProperty("keyId").GetString() == signer.KeyId && Ed25519CommandSigner.Verify(signer.PublicKey, type, bytes, sig);
                    _incoming.Writer.TryWrite(new AgentMessage(type, id, JsonDocument.Parse(bytes).RootElement.Clone(), true, ok, raw));
                }
                else
                {
                    _incoming.Writer.TryWrite(new AgentMessage(type, id, root.GetProperty("payload").Clone(), false, false, raw));
                }
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or WebSocketException or ObjectDisposedException)
        {
        }
        _incoming.Writer.TryComplete();
    }

    public Task SendAsync(string type, object payload) => SendRawAsync(JsonSerializer.Serialize(new { type, id = Guid.NewGuid().ToString("D"), version = 1, payload }, AgentJson.Options));

    public Task SendRawAsync(string json) => _ws!.SendAsync(Encoding.UTF8.GetBytes(json), WebSocketMessageType.Text, true, _cts.Token);

    /// <summary>Waits for the next message of <paramref name="type"/> (optionally matching a predicate); other messages stay queued.</summary>
    public async Task<AgentMessage> WaitForAsync(string type, Func<AgentMessage, bool>? match = null, int timeoutMs = 10_000)
    {
        bool Matches(AgentMessage m) => m.Type == type && (match is null || match(m));
        lock (_backlog)
        {
            var hit = _backlog.FirstOrDefault(Matches);
            if (hit is not null)
            {
                _backlog.Remove(hit);
                return hit;
            }
        }
        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            await foreach (var m in _incoming.Reader.ReadAllAsync(cts.Token))
            {
                if (Matches(m))
                {
                    return m;
                }
                lock (_backlog)
                {
                    _backlog.Add(m);
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
        throw new TimeoutException($"No '{type}' message within {timeoutMs} ms (socket {_ws?.State}).");
    }

    /// <summary>True if no message of the type arrives within the window.</summary>
    public async Task<bool> NoneAsync(string type, int windowMs = 600)
    {
        try
        {
            await WaitForAsync(type, null, windowMs);
            return false;
        }
        catch (TimeoutException)
        {
            return true;
        }
    }

    public async Task<bool> WaitClosedAsync(int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (_ws is null || _ws.State != WebSocketState.Open || _incoming.Reader.Completion.IsCompleted)
            {
                return true;
            }
            await Task.Delay(50);
        }
        return false;
    }

    public async Task CloseAsync()
    {
        if (_ws is null)
        {
            return;
        }
        try
        {
            await _cts.CancelAsync();
            _ws.Abort();
            if (_receive is not null)
            {
                await _receive;
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or WebSocketException)
        {
        }
        _ws.Dispose();
        _ws = null;
    }

    public async ValueTask DisposeAsync() => await CloseAsync();
}

public static class TestAgentJobExtensions
{
    /// <summary>Waits for a signed job.dispatch, checks what a real agent would check, and returns it.</summary>
    public static async Task<AgentMessage> NextJobAsync(this TestAgent agent, string? kind = null, int timeoutMs = 10_000)
    {
        var m = await agent.WaitForAsync("job.dispatch", x => kind is null || x.Payload.GetProperty("kind").GetString() == kind, timeoutMs);
        Assert.True(m.Signed && m.SignatureValid, "job.dispatch must carry a valid signature");
        Assert.Equal(agent.DeviceId.ToString("D"), m.Payload.GetProperty("deviceId").GetString());
        Assert.Equal(16, Convert.FromBase64String(m.Payload.GetProperty("nonce").GetString()!).Length);
        var issued = m.Payload.GetProperty("issuedAt").GetDateTimeOffset();
        var expires = m.Payload.GetProperty("expiresAt").GetDateTimeOffset();
        Assert.True(expires - issued <= TimeSpan.FromMinutes(15));
        return m;
    }

    public static Guid RunId(this AgentMessage m) => Guid.Parse(m.Payload.GetProperty("jobRunId").GetString()!);

    public static async Task CompleteAsync(this TestAgent agent, AgentMessage job, string status = "succeeded", int? exitCode = 0, string[]? output = null, object? result = null, string? message = null)
    {
        var runId = job.RunId().ToString("D");
        await agent.SendAsync("job.ack", new { jobRunId = runId, accepted = true });
        var seq = 0;
        var all = new System.Text.StringBuilder();
        foreach (var line in output ?? [])
        {
            await agent.SendAsync("job.output", new { jobRunId = runId, seq = ++seq, stream = "stdout", data = line });
            all.Append(line);
        }
        await agent.SendAsync("job.result", new
        {
            jobRunId = runId, status, exitCode, message, truncated = false, outputBytes = all.Length,
            outputSha256 = Dranzo.Infrastructure.Security.Hashing.Sha256Hex(all.ToString()), startedAt = DateTimeOffset.UtcNow, finishedAt = DateTimeOffset.UtcNow, result,
        });
    }
}
