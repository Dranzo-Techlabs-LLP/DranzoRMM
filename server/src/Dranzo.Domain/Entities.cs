namespace Dranzo.Domain;

// ---------- Tenancy ----------

public class Partner
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string? SupportContact { get; set; }
}

public enum ConsentMode { None, Notify, Require }

public class Organization : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public required string Name { get; set; }
    public string TimeZone { get; set; } = "UTC";
    public ConsentMode ConsentMode { get; set; } = ConsentMode.Require;
    public bool RequireSignedPowerShell { get; set; }
    /// <summary>MeshCentral user (e.g. "user//acme-tech") that can see only this organization's device group.</summary>
    public string? MeshUser { get; set; }
    /// <summary>MeshCentral device group id that this organization's devices join.</summary>
    public string? MeshGroupId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
}

public class Site : IOrgOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public required string Name { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public class DeviceGroup : IOrgOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid SiteId { get; set; }
    public required string Name { get; set; }
    /// <summary>Agent update ring for devices in this group: test, pilot or all.</summary>
    public string UpdateRing { get; set; } = "all";
    public DateTimeOffset CreatedAt { get; set; }
}

// ---------- Identity ----------

public class User : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public required string Email { get; set; }
    public required string DisplayName { get; set; }
    public string PasswordHash { get; set; } = "";
    public string? TotpSecretProtected { get; set; }
    public bool TotpEnabled { get; set; }
    public long LastTotpStep { get; set; }
    public string[] RecoveryCodeHashes { get; set; } = [];
    public int FailedLogins { get; set; }
    public DateTimeOffset? LockoutEnd { get; set; }
    public bool Disabled { get; set; }
    public bool MustChangePassword { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastLoginAt { get; set; }
    public DateTimeOffset PasswordChangedAt { get; set; }
}

public class UserSession : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid UserId { get; set; }
    public required string TokenHash { get; set; }
    public required string CsrfToken { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? StepUpAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? Ip { get; set; }
    public string? UserAgent { get; set; }
}

public class Role : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public required string Name { get; set; }
    public bool IsBuiltIn { get; set; }
    public string[] Permissions { get; set; } = [];
}

public class RoleAssignment : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid? UserId { get; set; }
    public Guid? ApiKeyId { get; set; }
    public Guid RoleId { get; set; }
    public Role Role { get; set; } = null!;
    public ScopeType ScopeType { get; set; }
    /// <summary>Organization, site or group id; null for partner scope.</summary>
    public Guid? ScopeId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public class ApiKey : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public required string Name { get; set; }
    public required string SecretHash { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
    public Guid CreatedByUserId { get; set; }
}

// ---------- Enrollment and devices ----------

public class EnrollmentToken : IOrgOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid SiteId { get; set; }
    public Guid? GroupId { get; set; }
    public required string Name { get; set; }
    public required string TokenHash { get; set; }
    public required string TokenPrefix { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public int MaxUses { get; set; }
    public int Uses { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public Guid CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public enum DeviceStatus { Active, Revoked }

public class Device : IOrgOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid SiteId { get; set; }
    public Guid? GroupId { get; set; }
    public required string Hostname { get; set; }
    /// <summary>windows, macos or linux.</summary>
    public required string Os { get; set; }
    public string OsName { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public required string Arch { get; set; }
    public string Serial { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string Model { get; set; } = "";
    public string AgentVersion { get; set; } = "";
    public string MachineId { get; set; } = "";
    public DeviceStatus Status { get; set; } = DeviceStatus.Active;
    public DateTimeOffset EnrolledAt { get; set; }
    public DateTimeOffset? LastSeenAt { get; set; }
    public bool IsOnline { get; set; }
    public string[] Tags { get; set; } = [];
    public string? CertThumbprint { get; set; }
    public DateTimeOffset? CertNotAfter { get; set; }
    public string? PrevCertThumbprint { get; set; }
    public DateTimeOffset? PrevCertNotAfter { get; set; }
    public string? ConsoleUser { get; set; }
    public bool PendingReboot { get; set; }
    public double? CpuPercent { get; set; }
    public double? MemUsedPercent { get; set; }
    public long? AgentRssBytes { get; set; }
    public Guid? PossibleDuplicateOfDeviceId { get; set; }
    public string[] Capabilities { get; set; } = [];
    public string? LastIp { get; set; }
    public string? MeshNodeId { get; set; }
    public bool UninstallCodeSet { get; set; }
    /// <summary>Version that failed to install and must not be offered again.</summary>
    public string? FailedUpdateVersion { get; set; }
    public DateTimeOffset? LastPatchScanAt { get; set; }
    public DateTimeOffset? LastPatchInstallAt { get; set; }
    /// <summary>MAC addresses from the latest inventory (lowercase, colon-separated), to match discovered network devices.</summary>
    public string[] MacAddresses { get; set; } = [];
    public string? DefaultGateway { get; set; }
    /// <summary>SSID of the Wi-Fi the device is on; "" when the OS hides it, null when not on Wi-Fi.</summary>
    public string? WifiSsid { get; set; }
    /// <summary>Set when a network.isolate job succeeded; cleared by network.release.</summary>
    public DateTimeOffset? IsolatedAt { get; set; }
    public string? IsolatedBy { get; set; }
    public string? IsolationReason { get; set; }
}

// ---------- Network ----------

public enum NetworkDeviceStatus { Unknown, Approved, Blocked }

/// <summary>A device seen on a site's local network by a network.scan (or a network controller).</summary>
public class NetworkDevice : IOrgOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid SiteId { get; set; }
    /// <summary>Lowercase, colon-separated.</summary>
    public required string Mac { get; set; }
    public string Ip { get; set; } = "";
    public string? Hostname { get; set; }
    public string? Vendor { get; set; }
    /// <summary>Locally administered (private Wi-Fi) MAC: the same phone may appear under several.</summary>
    public bool Randomized { get; set; }
    public bool IsGateway { get; set; }
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public Guid? SeenByDeviceId { get; set; }
    /// <summary>The enrolled device with this MAC, if any.</summary>
    public Guid? ManagedDeviceId { get; set; }
    public NetworkDeviceStatus Status { get; set; }
    public string? Note { get; set; }
    public DateTimeOffset? StatusChangedAt { get; set; }
    public string? StatusChangedBy { get; set; }
}

public class InventorySnapshot : IDeviceOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public DateTimeOffset CollectedAt { get; set; }
    public bool IsLatest { get; set; }
    public string DataJson { get; set; } = "{}";
}

public class InstalledSoftware : IDeviceOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public required string Name { get; set; }
    public string Version { get; set; } = "";
    public string? Publisher { get; set; }
    public required string Source { get; set; }
    public string? PackageId { get; set; }
    public DateTimeOffset? InstallDate { get; set; }
    public DateTimeOffset SeenAt { get; set; }
}

public class SavedFilter : IOrgOptionalShared
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid? OrganizationId { get; set; }
    public required string Name { get; set; }
    public string FilterJson { get; set; } = "{}";
    public Guid CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

// ---------- Scripts and jobs ----------

public class Script : IOrgOptionalShared
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid? OrganizationId { get; set; }
    public required string Name { get; set; }
    public string Description { get; set; } = "";
    public required string Language { get; set; }
    public string[] OsTargets { get; set; } = [];
    public int CurrentVersion { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
    public List<ScriptVersion> Versions { get; set; } = [];
}

public class ScriptVersion : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid ScriptId { get; set; }
    public int Version { get; set; }
    public required string Body { get; set; }
    public required string BodySha256 { get; set; }
    /// <summary>JSON array of {name, type, required, default}.</summary>
    public string ParametersJson { get; set; } = "[]";
    public Guid CreatedByUserId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string? ChangeNote { get; set; }
}

public class Job : IOrgOptionalRestricted
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid? OrganizationId { get; set; }
    public required string Name { get; set; }
    public required string Kind { get; set; }
    public string SpecJson { get; set; } = "{}";
    public string TargetJson { get; set; } = "{}";
    public string? Cron { get; set; }
    public string? TimeZone { get; set; }
    public DateTimeOffset? NextRunAt { get; set; }
    public bool Enabled { get; set; } = true;
    public Guid? RequestedByUserId { get; set; }
    public string RequestedByName { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public int TimeoutSeconds { get; set; } = 300;
    public int MaxOutputBytes { get; set; } = 1_048_576;
    public int MaxAttempts { get; set; } = 1;
    /// <summary>Maximum devices running this job at once; 0 = no job-level limit.</summary>
    public int MaxParallel { get; set; }
    public Guid? ScriptId { get; set; }
    public int? ScriptVersion { get; set; }
    public string ContentSha256 { get; set; } = "";
    /// <summary>System-created (policies, patch windows, updates) rather than requested by a person.</summary>
    public bool IsSystem { get; set; }
}

public enum JobRunStatus { Pending, Dispatched, Running, Succeeded, Failed, TimedOut, Cancelled, Rejected, Unsupported, Expired }

public class JobRun : IDeviceOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public Guid JobId { get; set; }
    public Job Job { get; set; } = null!;
    public Guid BatchId { get; set; }
    public required string Kind { get; set; }
    public string SpecJson { get; set; } = "{}";
    public JobRunStatus Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? DispatchedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? FinishedAt { get; set; }
    public int? ExitCode { get; set; }
    public string? Message { get; set; }
    public bool Truncated { get; set; }
    public long OutputBytes { get; set; }
    public string? OutputSha256 { get; set; }
    public string? ResultJson { get; set; }
    public int Attempt { get; set; } = 1;
    public int MaxAttempts { get; set; } = 1;
    public int TimeoutSeconds { get; set; }
    public int MaxOutputBytes { get; set; }
    public Guid? SessionId { get; set; }
    public bool CancelRequested { get; set; }
}

public class JobOutputChunk : IPartnerOwned
{
    public long Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid JobRunId { get; set; }
    public int Seq { get; set; }
    public required string Stream { get; set; }
    public required string Data { get; set; }
}

// ---------- Blobs and packages ----------

public class Blob : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public required string StorageKey { get; set; }
    public required string FileName { get; set; }
    public long SizeBytes { get; set; }
    public required string Sha256 { get; set; }
    public required string Purpose { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
}

/// <summary>Allows one device to download one blob for a limited time.</summary>
public class BlobGrant : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid BlobId { get; set; }
    public Guid DeviceId { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

public class UploadTicket : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid DeviceId { get; set; }
    public Guid JobRunId { get; set; }
    public long MaxBytes { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public Guid? BlobId { get; set; }
    public DateTimeOffset? UsedAt { get; set; }
}

public class Package : IOrgOptionalShared
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid? OrganizationId { get; set; }
    public required string Name { get; set; }
    public string Version { get; set; } = "";
    public required string Os { get; set; }
    /// <summary>msi, exe, pkg, dmg, deb or rpm.</summary>
    public required string Type { get; set; }
    public Guid BlobId { get; set; }
    public string InstallArgsJson { get; set; } = "[]";
    public string UninstallCommandJson { get; set; } = "[]";
    public string? DetectionJson { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public Guid CreatedByUserId { get; set; }
    public DateTimeOffset? DeletedAt { get; set; }
}

// ---------- Patching ----------

/// <summary>
/// One update as reported by the devices of one organization. Kept per organization (not per partner) because the
/// title/severity/category come from agents: a device of one client must never define what another client approves.
/// </summary>
public class PatchCatalogEntry : IOrgOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public required string Source { get; set; }
    public required string UpdateId { get; set; }
    public required string Title { get; set; }
    public string? Kb { get; set; }
    public string Category { get; set; } = "";
    public string Severity { get; set; } = "";
    public DateTimeOffset FirstSeenAt { get; set; }
}

public enum PatchStatus { Pending, Approved, Rejected, Deferred, Installed, Failed }

public class DevicePatchState : IDeviceOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public Guid CatalogEntryId { get; set; }
    public PatchCatalogEntry CatalogEntry { get; set; } = null!;
    public PatchStatus Status { get; set; }
    public string? CurrentVersion { get; set; }
    public string? NewVersion { get; set; }
    public bool RequiresReboot { get; set; }
    public DateTimeOffset FirstSeenAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? InstalledAt { get; set; }
    public string? Error { get; set; }
}

public class PatchPolicy : IOrgOptionalShared
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid? OrganizationId { get; set; }
    public required string Name { get; set; }
    public bool Enabled { get; set; } = true;
    /// <summary>Severities approved automatically (critical, important, moderate, low, unspecified).</summary>
    public string[] AutoApproveSeverities { get; set; } = [];
    public string[] AutoApproveCategories { get; set; } = [];
    public string[] Sources { get; set; } = [];
    public int DeferDays { get; set; }
    /// <summary>Cron expression (organization time zone) for the start of the maintenance window.</summary>
    public string? WindowCron { get; set; }
    public int WindowMinutes { get; set; } = 120;
    public string RebootMode { get; set; } = "if_required";
    public bool RebootNotifyUser { get; set; } = true;
    public int RebootDeferrals { get; set; } = 3;
    public int RebootDeadlineMinutes { get; set; } = 240;
    public DateTimeOffset? NextWindowAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

// ---------- Security posture, vulnerabilities, alerts ----------

public class PostureSnapshot : IDeviceOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public DateTimeOffset CollectedAt { get; set; }
    public bool IsLatest { get; set; }
    public string DataJson { get; set; } = "{}";
    public bool? AntivirusOk { get; set; }
    public bool? FirewallOk { get; set; }
    public bool? EncryptionOk { get; set; }
    public string[] LocalAdmins { get; set; } = [];
}

/// <summary>Global vulnerability record (NVD + CISA KEV). Not tenant data.</summary>
public class CveEntry
{
    public required string Id { get; set; }
    public string Summary { get; set; } = "";
    public double? CvssScore { get; set; }
    public string Severity { get; set; } = "";
    public bool KnownExploited { get; set; }
    public DateTimeOffset? Published { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    /// <summary>JSON array of {vendor, product, versionStart, versionStartExcl, versionEnd, versionEndExcl, exact}.</summary>
    public string MatchJson { get; set; } = "[]";
    /// <summary>Lower-cased product names for fast lookup.</summary>
    public string[] Products { get; set; } = [];
}

/// <summary>Global sync watermark for an external feed (nvd, kev).</summary>
public class FeedState
{
    public required string Name { get; set; }
    public DateTimeOffset? LastSyncedAt { get; set; }
    public DateTimeOffset? LastModifiedCursor { get; set; }
    public string? LastError { get; set; }
    public long Items { get; set; }
}

public class DeviceVulnerability : IDeviceOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public required string CveId { get; set; }
    public required string SoftwareName { get; set; }
    public string SoftwareVersion { get; set; } = "";
    public string Severity { get; set; } = "";
    public double? CvssScore { get; set; }
    public bool KnownExploited { get; set; }
    public DateTimeOffset DetectedAt { get; set; }
}

public class NotificationChannel : IOrgOptionalShared
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid? OrganizationId { get; set; }
    public required string Name { get; set; }
    /// <summary>email, webhook, teams or slack.</summary>
    public required string Type { get; set; }
    /// <summary>Data-protected JSON configuration (addresses, URLs, secrets).</summary>
    public required string ConfigProtected { get; set; }
    public bool Enabled { get; set; } = true;
    /// <summary>Event names delivered as outbound webhooks; empty for alert-only channels.</summary>
    public string[] EventTypes { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
}

public class AlertRule : IOrgOptionalShared
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid? OrganizationId { get; set; }
    public required string Name { get; set; }
    /// <summary>device.offline, disk.usage, antivirus.off, encryption.off, patch.failed, localadmin.new, agent.tamper, compliance.drift.</summary>
    public required string Type { get; set; }
    public string Severity { get; set; } = "warning";
    public string ParamsJson { get; set; } = "{}";
    public bool Enabled { get; set; } = true;
    public Guid[] ChannelIds { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
}

public enum AlertState { Open, Acknowledged, Resolved }

public class Alert : IDeviceOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public Guid? RuleId { get; set; }
    public required string Type { get; set; }
    public string Severity { get; set; } = "warning";
    public required string Title { get; set; }
    public string Detail { get; set; } = "";
    /// <summary>Stable key so the same condition does not open a second alert.</summary>
    public required string DedupKey { get; set; }
    public AlertState State { get; set; }
    public DateTimeOffset OpenedAt { get; set; }
    public DateTimeOffset? AcknowledgedAt { get; set; }
    public Guid? AcknowledgedByUserId { get; set; }
    public DateTimeOffset? ResolvedAt { get; set; }
    public DateTimeOffset? NotifiedAt { get; set; }
}

// ---------- Policies ----------

public class Policy : IOrgOptionalShared
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid? OrganizationId { get; set; }
    public required string Name { get; set; }
    public string Description { get; set; } = "";
    /// <summary>Built-in check id (firewall.enabled, ...) or "script".</summary>
    public required string Check { get; set; }
    public string ParamsJson { get; set; } = "{}";
    public string[] OsTargets { get; set; } = [];
    public bool Remediate { get; set; }
    public bool Enabled { get; set; } = true;
    public int IntervalMinutes { get; set; } = 240;
    public DateTimeOffset CreatedAt { get; set; }
}

public class PolicyAssignment : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid PolicyId { get; set; }
    public Policy Policy { get; set; } = null!;
    public ScopeType ScopeType { get; set; }
    public Guid? ScopeId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}

public class ComplianceResult : IDeviceOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public Guid PolicyId { get; set; }
    public bool Compliant { get; set; }
    public bool Remediated { get; set; }
    public string Detail { get; set; } = "";
    public bool? Supported { get; set; }
    public DateTimeOffset EvaluatedAt { get; set; }
    public DateTimeOffset? NonCompliantSince { get; set; }
}

// ---------- Remote sessions ----------

public enum RemoteSessionState { Requested, PendingConsent, Active, Denied, Ended, Failed }

public class RemoteSession : IDeviceOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid DeviceId { get; set; }
    public Device Device { get; set; } = null!;
    public Guid UserId { get; set; }
    public required string UserName { get; set; }
    /// <summary>terminal, files or desktop.</summary>
    public required string Kind { get; set; }
    public ConsentMode ConsentMode { get; set; }
    public RemoteSessionState State { get; set; }
    public string? ConsentResult { get; set; }
    public string? EndReason { get; set; }
    public DateTimeOffset RequestedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? EndedAt { get; set; }
    public string? Ip { get; set; }
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    /// <summary>SHA-256 over everything the technician typed (terminal sessions).</summary>
    public string? InputSha256 { get; set; }
}

// ---------- Agent releases ----------

public class AgentRelease : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public required string Version { get; set; }
    public string Notes { get; set; } = "";
    /// <summary>none, test, pilot or all: how far the rollout has progressed.</summary>
    public string Ring { get; set; } = "none";
    public bool Paused { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public Guid CreatedByUserId { get; set; }
    public List<AgentReleaseBinary> Binaries { get; set; } = [];
}

public class AgentReleaseBinary : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid ReleaseId { get; set; }
    public required string Os { get; set; }
    public required string Arch { get; set; }
    /// <summary>"binary" (used for self-update) or an installer type: msi, pkg, deb, rpm.</summary>
    public string Kind { get; set; } = "binary";
    public Guid BlobId { get; set; }
    public required string Sha256 { get; set; }
    public long SizeBytes { get; set; }
    /// <summary>Base64 Ed25519 signature over "DRANZO-RELEASE-V1\n{version}\n{os}\n{arch}\n{sha256}".</summary>
    public required string Signature { get; set; }
    public required string KeyId { get; set; }
}

public class DeviceUpdateState : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid DeviceId { get; set; }
    public Guid ReleaseId { get; set; }
    public required string Version { get; set; }
    public required string State { get; set; }
    public string? Error { get; set; }
    public DateTimeOffset OfferedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

// ---------- Audit ----------

public class AuditEvent : IOrgOptionalRestricted
{
    public long Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid? OrganizationId { get; set; }
    public long Sequence { get; set; }
    public DateTimeOffset OccurredAt { get; set; }
    /// <summary>user, apikey, agent or system.</summary>
    public required string ActorType { get; set; }
    public Guid? ActorId { get; set; }
    public string ActorName { get; set; } = "";
    public required string Action { get; set; }
    public string? TargetType { get; set; }
    public string? TargetId { get; set; }
    public Guid? DeviceId { get; set; }
    public string? Ip { get; set; }
    /// <summary>success, failure or denied.</summary>
    public required string Result { get; set; }
    /// <summary>JSON text. Stored as plain text (not jsonb) so the hash chain sees exactly what was written.</summary>
    public string Detail { get; set; } = "{}";
    /// <summary>SHA-256 of the script body / command / output this event refers to.</summary>
    public string? ContentSha256 { get; set; }
    public required string PrevHash { get; set; }
    public required string Hash { get; set; }
}

// ---------- Outbound webhooks ----------

public class WebhookDelivery : IPartnerOwned
{
    public Guid Id { get; set; }
    public Guid PartnerId { get; set; }
    public Guid ChannelId { get; set; }
    public required string EventType { get; set; }
    public required string PayloadJson { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset NextAttemptAt { get; set; }
    public DateTimeOffset? DeliveredAt { get; set; }
    public string? LastError { get; set; }
}

public static class JobKinds
{
    public const string Script = "script";
    public const string InventoryRefresh = "inventory.refresh";
    public const string SoftwareScan = "software.scan";
    public const string SoftwareInstall = "software.install";
    public const string SoftwareUninstall = "software.uninstall";
    public const string PackageInstall = "package.install";
    public const string PackageUninstall = "package.uninstall";
    public const string PatchScan = "patch.scan";
    public const string PatchInstall = "patch.install";
    public const string PostureScan = "posture.scan";
    public const string PolicyEvaluate = "policy.evaluate";
    public const string Reboot = "reboot";
    public const string FileList = "file.list";
    public const string FileRead = "file.read";
    public const string FileWrite = "file.write";
    public const string MeshInstall = "mesh.install";
    public const string MeshUninstall = "mesh.uninstall";
    public const string AgentConfigure = "agent.configure";
    public const string AgentUninstall = "agent.uninstall";
    public const string NetworkScan = "network.scan";
    public const string NetworkIsolate = "network.isolate";
    public const string NetworkRelease = "network.release";
}
