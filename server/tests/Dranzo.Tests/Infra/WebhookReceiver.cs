using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Dranzo.Tests.Infra;

public sealed record ReceivedWebhook(string Path, string Body, Dictionary<string, string> Headers);

/// <summary>Tiny local HTTP endpoint that records what the server posts to it.</summary>
public sealed class WebhookReceiver : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _cts = new();

    public WebhookReceiver()
    {
        using (var probe = new TcpListener(IPAddress.Loopback, 0))
        {
            probe.Start();
            Port = ((IPEndPoint)probe.LocalEndpoint).Port;
        }
        _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
        _listener.Start();
        _ = Task.Run(LoopAsync);
    }

    public int Port { get; }
    public string Url(string path = "/hook") => $"http://127.0.0.1:{Port}{path}";
    public ConcurrentQueue<ReceivedWebhook> Received { get; } = new();
    public int StatusCode { get; set; } = 200;

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync();
            }
            catch (Exception ex) when (ex is HttpListenerException or ObjectDisposedException)
            {
                return;
            }
            using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
            var body = await reader.ReadToEndAsync();
            Received.Enqueue(new ReceivedWebhook(ctx.Request.Url!.AbsolutePath, body, ctx.Request.Headers.AllKeys.ToDictionary(k => k!, k => ctx.Request.Headers[k]!, StringComparer.OrdinalIgnoreCase)));
            ctx.Response.StatusCode = StatusCode;
            ctx.Response.Close();
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Close();
    }
}
