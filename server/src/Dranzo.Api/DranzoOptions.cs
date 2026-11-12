namespace Dranzo.Api;

public sealed class DranzoOptions
{
    public int DashboardPort { get; set; } = 8080;
    public int AgentPort { get; set; } = 8443;
    /// <summary>DNS names / IPs placed in the agent listener's server certificate.</summary>
    public string[] AgentHostnames { get; set; } = ["localhost", "127.0.0.1"];
    /// <summary>URL agents are told to connect to (shown in install commands).</summary>
    public string PublicAgentUrl { get; set; } = "https://localhost:8443";
    public string PublicDashboardUrl { get; set; } = "http://localhost:5173";
    public KeyStoreOptions KeyStore { get; set; } = new();
    public StorageOptions Storage { get; set; } = new();
    public AuthOptions Auth { get; set; } = new();
    public AgentOptions Agents { get; set; } = new();
    public BootstrapOptions Bootstrap { get; set; } = new();
    public SmtpOptions Smtp { get; set; } = new();
    public MeshOptions Mesh { get; set; } = new();
    public FeedOptions Feeds { get; set; } = new();
    public RateLimitOptions RateLimits { get; set; } = new();
    /// <summary>Set false in tests that drive background work by hand.</summary>
    /// <summary>Networks (CIDR) whose X-Forwarded-* headers are trusted when Dranzo:TrustForwardedHeaders is true. Default: loopback and private ranges.</summary>
    public string[] TrustedProxyNetworks { get; set; } = [];
    /// <summary>If set, the public trust anchors agents need (ca.pem, trust.json) are written here at start (dev/compose, packaging).</summary>
    public string? ExportTrustDirectory { get; set; }
    public bool RunBackgroundServices { get; set; } = true;
    public bool RunDispatcher { get; set; } = true;
}

public sealed class KeyStoreOptions
{
    /// <summary>file or keyvault.</summary>
    public string Type { get; set; } = "file";
    public string Directory { get; set; } = "";
    public string? VaultUri { get; set; }
    /// <summary>Create missing keys at start. Default: true for the file store, false for Key Vault (set true for the first start only).</summary>
    public bool? AllowCreate { get; set; }
}

public sealed class StorageOptions
{
    /// <summary>file, s3 or azure.</summary>
    public string Type { get; set; } = "file";
    public string Directory { get; set; } = "";
    public string? S3ServiceUrl { get; set; }
    public string? S3AccessKey { get; set; }
    public string? S3SecretKey { get; set; }
    public string Bucket { get; set; } = "dranzo";
    public string? AzureConnectionString { get; set; }
    public string? AzureAccountUri { get; set; }
    public long MaxPackageBytes { get; set; } = 2L * 1024 * 1024 * 1024;
    public long MaxFileTransferBytes { get; set; } = 100L * 1024 * 1024;
}

public sealed class AuthOptions
{
    public int SessionIdleMinutes { get; set; } = 30;
    public int SessionAbsoluteHours { get; set; } = 12;
    public int StepUpMinutes { get; set; } = 5;
    public int LockoutThreshold { get; set; } = 5;
    public int LockoutMinutes { get; set; } = 15;
    public int PasswordMinLength { get; set; } = 12;
    /// <summary>Device count above which running a script needs step-up re-authentication.</summary>
    public int BulkStepUpThreshold { get; set; } = 10;
    public string Issuer { get; set; } = "DranzoRMM";
}

public sealed class AgentOptions
{
    public int HeartbeatSeconds { get; set; } = 60;
    public int MissedHeartbeats { get; set; } = 3;
    public int CertValidityDays { get; set; } = 90;
    public int MaxMessageBytes { get; set; } = 2 * 1024 * 1024;
    public int MessagesPerSecond { get; set; } = 50;
    public int MessageBurst { get; set; } = 200;
    public int InventoryIntervalSeconds { get; set; } = 6 * 3600;
    public int SoftwareIntervalSeconds { get; set; } = 12 * 3600;
    public int PostureIntervalSeconds { get; set; } = 3600;
    public int PatchScanIntervalSeconds { get; set; } = 12 * 3600;
    public int MaxConcurrentRunsPerDevice { get; set; } = 4;
    public int PendingRunExpiryHours { get; set; } = 24;
    public int CommandValiditySeconds { get; set; } = 300;
}

public sealed class BootstrapOptions
{
    public string? PartnerName { get; set; }
    public string? AdminEmail { get; set; }
    public string? AdminPassword { get; set; }
}

public sealed class SmtpOptions
{
    public string? Host { get; set; }
    public int Port { get; set; } = 587;
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string From { get; set; } = "dranzormm@localhost";
    public bool UseStartTls { get; set; } = true;
}

public sealed class MeshOptions
{
    public string? Url { get; set; }
    /// <summary>MeshCentral login token key (hex, 80 bytes) from <c>meshcentral --logintokenkey</c>.</summary>
    public string? LoginTokenKey { get; set; }
    public string User { get; set; } = "admin";
    public string Domain { get; set; } = "";
    public string? MeshId { get; set; }
    /// <summary>
    /// Allow remote desktop for organizations without their own MeshCentral user/group. Only safe when the partner
    /// has a single organization: a shared MeshCentral login can see every device in MeshCentral.
    /// </summary>
    public bool AllowSharedUser { get; set; }
    public int LoginTokenMinutes { get; set; } = 2;
    /// <summary>
    /// SHA-256 (hex) of MeshCentral's HTTPS certificate, for a MeshCentral with a self-signed certificate. The server
    /// then accepts exactly that certificate when it downloads MeshAgent installers. Leave empty for a publicly trusted one.
    /// </summary>
    public string? CertificateSha256 { get; set; }
    /// <summary>MeshCentral agent architecture ids per "os-arch". Check them against your MeshCentral version.</summary>
    public Dictionary<string, int> AgentIds { get; set; } = new()
    {
        ["windows-amd64"] = 4, ["windows-arm64"] = 43, ["linux-amd64"] = 6, ["linux-arm64"] = 26, ["macos-amd64"] = 16, ["macos-arm64"] = 29,
    };
}

public sealed class FeedOptions
{
    public bool Enabled { get; set; }
    public string KevUrl { get; set; } = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    public string NvdUrl { get; set; } = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    public string? NvdApiKey { get; set; }
    public int SyncHours { get; set; } = 24;
}

public sealed class RateLimitOptions
{
    public int AuthPerMinute { get; set; } = 10;
    public int EnrollPerMinute { get; set; } = 30;
    public int ApiPerMinute { get; set; } = 600;
    public int ApiKeyPerMinute { get; set; } = 120;
}
