using Microsoft.Extensions.DependencyInjection.Extensions;
using Dranzo.Api.Agents;
using Dranzo.Api.Features;
using Dranzo.Api.Jobs;
using Dranzo.Api.Notifications;

namespace Dranzo.Api;

/// <summary>Registration point for feature modules added phase by phase.</summary>
public static class FeatureRegistration
{
    public static void AddServices(IServiceCollection services)
    {
        // Phase 2: scripts and jobs
        services.AddSingleton<JobDispatcher>();
        services.AddScoped<JobService>();
        services.AddScoped<IAgentMessageProcessor, JobAckProcessor>();
        services.AddScoped<IAgentMessageProcessor, JobOutputProcessor>();
        services.AddScoped<IAgentMessageProcessor, JobResultProcessor>();

        // Phase 3: software and packages
        services.AddScoped<BlobService>();
        services.AddScoped<IAgentMessageProcessor, SoftwareInventoryProcessor>();
        services.AddScoped<IJobResultHandler, SoftwareResultHandler>();

        // Phase 4: patch management
        services.AddScoped<IAgentMessageProcessor, PatchStateProcessor>();
        services.AddScoped<IJobResultHandler, PatchResultHandler>();

        // Phase 5: security posture, vulnerabilities, alerts, notifications
        services.AddOptions<NotificationOptions>().BindConfiguration("Dranzo:Notifications");
        services.AddScoped<NotificationService>();
        services.AddScoped<AlertEngine>();
        services.AddScoped<VulnerabilityMatcher>();
        services.AddScoped<IAgentMessageProcessor, PostureProcessor>();

        // Phase 6: remote support
        services.AddSingleton<SessionRegistry>();
        services.AddSingleton<MeshCentral>();
        services.AddScoped<RemoteSessionService>();
        services.AddScoped<IAgentMessageProcessor, SessionStatusProcessor>();
        services.AddScoped<IAgentMessageProcessor, SessionOutputProcessor>();
        services.AddScoped<IJobResultHandler, MeshResultHandler>();

        // Phase 7: policies and compliance
        services.AddScoped<IJobResultHandler, PolicyResultHandler>();

        // Phase 8: agent releases, reports, API keys
        services.AddScoped<UpdateRollout>();
        services.AddScoped<IAgentMessageProcessor, UpdateStatusProcessor>();
        services.AddScoped<IJobResultHandler, AgentUninstallResultHandler>();

        // Phase 10: network and firewall
        services.AddScoped<IJobResultHandler, NetworkScanResultHandler>();
        services.AddScoped<IJobResultHandler, IsolationResultHandler>();
        services.TryAddSingleton<IUniFiTransport, UniFiTransport>();
        services.AddSingleton<UniFiFactory>();
        services.AddScoped<NetworkEnforcer>();
        services.AddSingleton<Dranzo.Infrastructure.Security.NetworkCertificateAuthority>();
        services.AddScoped<IJobResultHandler, CertRequestResultHandler>();
    }

    /// <summary>The dispatcher is required for jobs to flow at all; periodic monitors can be switched off in tests.</summary>
    public static void AddHostedServices(IServiceCollection services, DranzoOptions options)
    {
        if (options.RunDispatcher)
        {
            services.AddHostedService(sp => sp.GetRequiredService<JobDispatcher>());
        }
        // Always on: it ends sessions when a device disconnects (fail closed).
        services.AddHostedService<SessionMonitor>();
        if (!options.RunBackgroundServices)
        {
            return;
        }
        services.AddHostedService<Scheduler>();
        services.AddHostedService<PatchWindowService>();
        services.AddHostedService<AlertMonitor>();
        services.AddHostedService<NotificationSender>();
        services.AddHostedService<VulnerabilityFeedService>();
        services.AddHostedService<PolicyEvaluator>();
        services.AddHostedService<UpdateRolloutService>();
        services.AddHostedService<NetworkControllerSync>();
        services.AddHostedService<Services.AuditVerifier>();
    }

    public static void MapEndpoints(RouteGroupBuilder api, WebApplication app)
    {
        ScriptEndpoints.Map(api);
        JobEndpoints.Map(api);
        SoftwareEndpoints.Map(api);
        BlobEndpoints.Map(app);
        PatchEndpoints.Map(api);
        SecurityEndpoints.Map(api);
        AlertEndpoints.Map(api);
        RemoteEndpoints.Map(api);
        PolicyEndpoints.Map(api);
        ReleaseEndpoints.Map(api);
        ApiKeyEndpoints.Map(api);
        ReportEndpoints.Map(api);
        AccessReviewEndpoints.Map(api);
        NetworkEndpoints.Map(api);
        IsolationEndpoints.Map(api);
        NetworkControllerEndpoints.Map(api);
        RadiusEndpoints.Map(api);
    }
}
