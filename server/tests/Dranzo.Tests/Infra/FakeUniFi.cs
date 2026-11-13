using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Dranzo.Api.Features;
using Dranzo.Domain;

namespace Dranzo.Tests.Infra;

/// <summary>
/// In-memory UniFi Network controllers for tests, keyed by host. Implements the classic endpoints the server uses
/// (shapes taken from UniFi Network 8/9); requests are recorded for assertions.
/// </summary>
public sealed class FakeUniFi : IUniFiTransport
{
    public const string ApiKey = "test-unifi-key";
    public ConcurrentDictionary<string, Controller> Controllers { get; } = new(StringComparer.OrdinalIgnoreCase);

    public Controller Add(string host)
    {
        var c = new Controller();
        Controllers[host] = c;
        return c;
    }

    public HttpMessageHandler CreateHandler(NetworkController controller) => new Handler(this);

    public sealed class Controller
    {
        public List<JsonObject> Devices { get; } = [];
        public List<JsonObject> Clients { get; } = [];
        public List<JsonObject> Wlans { get; } = [];
        public List<JsonObject> Networks { get; } = [];
        public List<JsonObject> RadiusProfiles { get; } = [];
        public ConcurrentQueue<string> Requests { get; } = new();
        public ConcurrentQueue<JsonObject> Commands { get; } = new();
    }

    private sealed class Handler(FakeUniFi fake) : HttpMessageHandler
    {
        private static HttpResponseMessage Json(HttpStatusCode code, object body) => new(code)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"),
        };

        private static HttpResponseMessage Ok(IEnumerable<JsonNode?> data) => Json(HttpStatusCode.OK, new { meta = new { rc = "ok" }, data = new JsonArray([.. data.Select(d => d?.DeepClone())]) });

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            if (!fake.Controllers.TryGetValue(uri.Host, out var c))
            {
                throw new HttpRequestException("No such host (fake UniFi).");
            }
            var path = uri.AbsolutePath;
            c.Requests.Enqueue($"{request.Method} {path}");
            if (!request.Headers.TryGetValues("X-API-KEY", out var key) || key.First() != ApiKey)
            {
                return Json(HttpStatusCode.Unauthorized, new { meta = new { rc = "error", msg = "api.err.LoginRequired" }, data = Array.Empty<object>() });
            }
            var body = request.Content is null ? null : JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken))?.AsObject();
            const string prefix = "/proxy/network/api/s/default/";
            if (path == "/proxy/network/v2/api/site/default/apgroups")
            {
                return Json(HttpStatusCode.OK, new[] { new { _id = "apg-all", name = "All APs", attr_no_delete = true } });
            }
            if (!path.StartsWith(prefix, StringComparison.Ordinal))
            {
                return Json(HttpStatusCode.NotFound, new { meta = new { rc = "error", msg = "api.err.NotFound" } });
            }
            var rest = path[prefix.Length..];
            lock (c)
            {
                switch (request.Method.Method, rest)
                {
                    case ("GET", "stat/device"):
                        return Ok(c.Devices);
                    case ("GET", "stat/sta"):
                        return Ok(c.Clients);
                    case ("GET", "rest/wlanconf"):
                        return Ok(c.Wlans);
                    case ("GET", "rest/networkconf"):
                        return Ok(c.Networks);
                    case ("GET", "rest/usergroup"):
                        return Ok([new JsonObject { ["_id"] = "ug-default", ["name"] = "Default" }]);
                    case ("GET", "rest/radiusprofile"):
                        return Ok(c.RadiusProfiles);
                    case ("POST", "rest/networkconf"):
                        body!["_id"] = "net-" + Guid.NewGuid().ToString("N")[..8];
                        c.Networks.Add(body);
                        return Ok([body]);
                    case ("POST", "rest/wlanconf"):
                        body!["_id"] = "wlan-" + Guid.NewGuid().ToString("N")[..8];
                        c.Wlans.Add(body);
                        return Ok([body]);
                    case ("POST", "rest/radiusprofile"):
                        body!["_id"] = "rp-" + Guid.NewGuid().ToString("N")[..8];
                        c.RadiusProfiles.Add(body);
                        return Ok([body]);
                    case ("POST", "cmd/stamgr"):
                    case ("POST", "cmd/devmgr"):
                        c.Commands.Enqueue(body!);
                        return Ok([]);
                }
                if (request.Method == HttpMethod.Put && rest.StartsWith("rest/wlanconf/", StringComparison.Ordinal))
                {
                    var id = rest["rest/wlanconf/".Length..];
                    var w = c.Wlans.FirstOrDefault(x => x["_id"]?.GetValue<string>() == id);
                    if (w is null)
                    {
                        return Json(HttpStatusCode.BadRequest, new { meta = new { rc = "error", msg = "api.err.IdInvalid" } });
                    }
                    foreach (var (k, v) in body!)
                    {
                        w[k] = v?.DeepClone();
                    }
                    return Ok([w]);
                }
            }
            return Json(HttpStatusCode.BadRequest, new { meta = new { rc = "error", msg = "api.err.Invalid" } });
        }
    }
}
