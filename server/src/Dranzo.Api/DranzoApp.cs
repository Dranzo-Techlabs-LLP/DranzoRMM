using System.Security.Authentication;
using System.Threading.RateLimiting;
using Amazon.S3;
using Dranzo.Api.Agents;
using Dranzo.Api.Auth;
using Dranzo.Api.Features;
using Dranzo.Api.Live;
using Dranzo.Api.Services;
using Dranzo.Infrastructure.Audit;
using Dranzo.Infrastructure.Data;
using Dranzo.Infrastructure.Security;
using Dranzo.Infrastructure.Storage;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Dranzo.Api;

public static class DranzoApp
{
    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null, string? environment = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, EnvironmentName = environment });
        configure?.Invoke(builder);

        var options = builder.Configuration.GetSection("Dranzo").Get<DranzoOptions>() ?? new DranzoOptions();
        var devHome = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".dranzormm-dev");
        if (string.IsNullOrEmpty(options.KeyStore.Directory))
        {
            options.KeyStore.Directory = Path.Combine(devHome, "keys");
        }
        if (string.IsNullOrEmpty(options.Storage.Directory))
        {
            options.Storage.Directory = Path.Combine(devHome, "storage");
        }
        builder.Services.Configure<DranzoOptions>(o =>
        {
            builder.Configuration.GetSection("Dranzo").Bind(o);
            o.KeyStore.Directory = options.KeyStore.Directory;
            o.Storage.Directory = options.Storage.Directory;
        });

        if (!builder.Environment.IsDevelopment())
        {
            builder.Logging.ClearProviders();
            builder.Logging.AddJsonConsole(o => o.IncludeScopes = true);
        }

        // ----- Keys, PKI, signing (created before Kestrel so the agent listener can use them) -----
        IKeyStore keyStore = options.KeyStore.Type.ToLowerInvariant() switch
        {
            "keyvault" => new KeyVaultKeyStore(new Uri(options.KeyStore.VaultUri ?? throw new InvalidOperationException("Dranzo:KeyStore:VaultUri is required."))),
            "file" => new FileKeyStore(options.KeyStore.Directory),
            var other => throw new InvalidOperationException($"Unknown key store type '{other}'."),
        };
        var allowCreate = options.KeyStore.AllowCreate ?? options.KeyStore.Type.Equals("file", StringComparison.OrdinalIgnoreCase);
        var ca = new CertificateAuthority(keyStore, options.AgentHostnames, allowCreate);
        builder.Services.AddSingleton(keyStore);
        builder.Services.AddSingleton(ca);
        builder.Services.AddSingleton<ICommandSigner>(new Ed25519CommandSigner(keyStore, allowCreate: allowCreate));
        builder.Services.AddSingleton(new SecretProtector(keyStore, allowCreate));
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<EnvelopeFactory>();

        // ----- Storage -----
        builder.Services.AddSingleton<IObjectStore>(_ => options.Storage.Type.ToLowerInvariant() switch
        {
            "s3" => new S3ObjectStore(new AmazonS3Client(options.Storage.S3AccessKey, options.Storage.S3SecretKey,
                new AmazonS3Config { ServiceURL = options.Storage.S3ServiceUrl, ForcePathStyle = true }), options.Storage.Bucket),
            "azure" => new AzureObjectStore(options.Storage.AzureConnectionString,
                options.Storage.AzureAccountUri is null ? null : new Uri(options.Storage.AzureAccountUri.TrimEnd('/') + "/"), options.Storage.Bucket),
            "file" => new FileObjectStore(options.Storage.Directory),
            var other => throw new InvalidOperationException($"Unknown storage type '{other}'."),
        });

        // ----- Data -----
        var connectionString = builder.Configuration.GetConnectionString("Default")
            ?? throw new InvalidOperationException("ConnectionStrings:Default is required.");
        builder.Services.AddScoped<TenantContext>();
        builder.Services.AddDbContext<DranzoDbContext>(o => o.UseNpgsql(connectionString));

        // ----- Identity and access -----
        builder.Services.AddScoped<CurrentPrincipal>();
        builder.Services.AddScoped<ScopeResolver>();
        builder.Services.AddScoped<AuthService>();
        builder.Services.AddScoped<IAuditLog, AuditLog>();
        builder.Services.AddScoped<Ctx>();
        builder.Services.AddAuthentication(AuthSchemes.Selector)
            .AddPolicyScheme(AuthSchemes.Selector, null, o => o.ForwardDefaultSelector = ctx =>
                ctx.Request.Headers.Authorization.ToString().StartsWith("Bearer " + ApiKeyAuthHandler.Prefix, StringComparison.Ordinal) ? AuthSchemes.ApiKey : AuthSchemes.Session)
            .AddScheme<AuthenticationSchemeOptions, SessionAuthHandler>(AuthSchemes.Session, null)
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthHandler>(AuthSchemes.ApiKey, null);

        builder.Services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.OnRejected = (context, ct) => new ValueTask(context.HttpContext.Response.WriteAsJsonAsync(new { error = "rate_limited", message = "Too many requests. Try again shortly." }, ct));
            static string Ip(HttpContext c) => c.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            o.AddPolicy("auth", c => RateLimitPartition.GetFixedWindowLimiter(Ip(c), _ => new FixedWindowRateLimiterOptions { PermitLimit = options.RateLimits.AuthPerMinute, Window = TimeSpan.FromMinutes(1) }));
            o.AddPolicy("enroll", c => RateLimitPartition.GetFixedWindowLimiter(Ip(c), _ => new FixedWindowRateLimiterOptions { PermitLimit = options.RateLimits.EnrollPerMinute, Window = TimeSpan.FromMinutes(1) }));
            o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(c =>
            {
                if (c.Features.Get<ITlsHandshakeFeature>() is not null)
                {
                    return RateLimitPartition.GetNoLimiter("agent");
                }
                var auth = c.Request.Headers.Authorization.ToString();
                return auth.StartsWith("Bearer " + ApiKeyAuthHandler.Prefix, StringComparison.Ordinal) && auth.Length > 46
                    ? RateLimitPartition.GetFixedWindowLimiter("key:" + auth[..46], _ => new FixedWindowRateLimiterOptions { PermitLimit = options.RateLimits.ApiKeyPerMinute, Window = TimeSpan.FromMinutes(1) })
                    : RateLimitPartition.GetFixedWindowLimiter("ip:" + Ip(c), _ => new FixedWindowRateLimiterOptions { PermitLimit = options.RateLimits.ApiPerMinute, Window = TimeSpan.FromMinutes(1) });
            });
        });

        // ----- Agents and live updates -----
        builder.Services.AddSingleton<AgentRegistry>();
        builder.Services.AddSingleton<LiveNotifier>();
        builder.Services.AddScoped<IAgentMessageProcessor, HelloProcessor>();
        builder.Services.AddScoped<IAgentMessageProcessor, HeartbeatProcessor>();
        builder.Services.AddScoped<IAgentMessageProcessor, InventoryProcessor>();
        builder.Services.AddScoped<IAgentMessageProcessor, AgentErrorProcessor>();
        builder.Services.AddSignalR(o => o.MaximumReceiveMessageSize = 64 * 1024);
        builder.Services.AddHttpClient();
        FeatureRegistration.AddServices(builder.Services);

        if (options.RunBackgroundServices)
        {
            builder.Services.AddHostedService<OfflineMonitor>();
        }
        FeatureRegistration.AddHostedServices(builder.Services, options);

        if (builder.Configuration.GetValue<bool>("Dranzo:TrustForwardedHeaders"))
        {
            builder.Services.Configure<ForwardedHeadersOptions>(o =>
            {
                // Only the ingress may set the client address and scheme. Never trust arbitrary senders.
                o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
                o.ForwardLimit = 1;
                o.KnownIPNetworks.Clear();
                o.KnownProxies.Clear();
                var networks = options.TrustedProxyNetworks.Length > 0 ? options.TrustedProxyNetworks : ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"];
                foreach (var network in networks)
                {
                    o.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network));
                }
            });
        }

        // ----- Listeners: plain HTTP for the dashboard (TLS at the ingress), mTLS for agents -----
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.AddServerHeader = false;
            k.Limits.MaxRequestBodySize = 10 * 1024 * 1024;
            k.ListenAnyIP(options.DashboardPort);
            k.ListenAnyIP(options.AgentPort, listen => listen.UseHttps(https =>
            {
                https.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                https.ServerCertificateSelector = (_, _) => ca.GetServerCertificate();
                // A certificate is optional at the TLS layer (enrollment has none yet); if one is presented it must
                // chain to the private CA. Per-device revocation is checked by the gateway.
                https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
                https.ClientCertificateValidation = (cert, _, _) => ca.ValidateClientCertificate(cert);
            }));
        });

        var app = builder.Build();

        if (builder.Configuration.GetValue<bool>("Dranzo:TrustForwardedHeaders"))
        {
            // Agents connect directly (mTLS end to end); never let them claim another address.
            app.UseWhen(ctx => ctx.Features.Get<ITlsHandshakeFeature>() is null, b => b.UseForwardedHeaders());
        }
        app.Use(async (ctx, next) =>
        {
            var h = ctx.Response.Headers;
            h.XContentTypeOptions = "nosniff";
            h["Referrer-Policy"] = "no-referrer";
            h["X-Frame-Options"] = "DENY";
            h["Cross-Origin-Opener-Policy"] = "same-origin";
            h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
            h.ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'";
            if (!app.Environment.IsDevelopment())
            {
                h.StrictTransportSecurity = "max-age=31536000; includeSubDomains";
            }
            if (ctx.Request.Path.StartsWithSegments("/api"))
            {
                h.CacheControl = "no-store";
            }
            await next();
        });
        // Cross-site WebSocket hijacking: the hub's upgrade is a GET without a CSRF header, so require a same-host Origin.
        app.Use(async (ctx, next) =>
        {
            if (ctx.Request.Path.StartsWithSegments("/hubs") && ctx.Request.Headers.Origin.ToString() is { Length: > 0 } origin
                && (!Uri.TryCreate(origin, UriKind.Absolute, out var o) || !string.Equals(o.Host, ctx.Request.Host.Host, StringComparison.OrdinalIgnoreCase)))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            await next();
        });
        app.UseWebSockets();
        app.UseRouting();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseMiddleware<AccessMiddleware>();
        app.UseWhen(ctx => ctx.Features.Get<ITlsHandshakeFeature>() is null && ctx.GetEndpoint() is null, b => b.UseStaticFiles());

        app.MapGet("/healthz", () => Results.Ok(new { status = "ok" })).Anonymous();
        app.MapGet("/agent/v1/healthz", () => Results.Ok(new { status = "ok" })).AgentListener();
        AgentGateway.Map(app);
        app.MapHub<LiveHub>("/hubs/live", o => o.CloseOnAuthenticationExpiration = true).AuthenticatedOnly();

        var api = app.MapGroup("/api/v1");
        AuthEndpoints.Map(api);
        TenantEndpoints.Map(api);
        UserEndpoints.Map(api);
        DeviceEndpoints.Map(api);
        AuditEndpoints.Map(api);
        FeatureRegistration.MapEndpoints(api, app);

        if (File.Exists(Path.Combine(app.Environment.WebRootPath ?? "wwwroot", "index.html")))
        {
            app.MapFallbackToFile("index.html").Anonymous();
        }
        return app;
    }

    /// <summary>Applies migrations, syncs built-in roles, creates the first partner/admin if configured.</summary>
    public static async Task InitializeAsync(WebApplication app)
    {
        await using var scope = app.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<TenantContext>().SetSystem();
        var db = scope.ServiceProvider.GetRequiredService<DranzoDbContext>();
        await db.Database.MigrateAsync();
        await Bootstrap.RunAsync(scope.ServiceProvider);
        var options = scope.ServiceProvider.GetRequiredService<Microsoft.Extensions.Options.IOptions<DranzoOptions>>().Value;
        if (!string.IsNullOrEmpty(options.ExportTrustDirectory))
        {
            // Public material only: the CA certificate and the command-signing public key.
            var signer = scope.ServiceProvider.GetRequiredService<ICommandSigner>();
            Directory.CreateDirectory(options.ExportTrustDirectory);
            await File.WriteAllTextAsync(Path.Combine(options.ExportTrustDirectory, "ca.pem"), scope.ServiceProvider.GetRequiredService<CertificateAuthority>().CaCertificatePem);
            await File.WriteAllTextAsync(Path.Combine(options.ExportTrustDirectory, "trust.json"), System.Text.Json.JsonSerializer.Serialize(new
            {
                commandKeys = new[] { new { kid = signer.KeyId, alg = "ed25519", publicKey = Convert.ToBase64String(signer.PublicKey) } },
            }));
        }
    }
}
