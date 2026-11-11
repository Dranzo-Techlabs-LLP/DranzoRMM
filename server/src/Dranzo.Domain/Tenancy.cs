namespace Dranzo.Domain;

/// <summary>Row belongs to one partner (the IT company).</summary>
public interface IPartnerOwned
{
    Guid PartnerId { get; }
}

/// <summary>Row belongs to one organization (a client business).</summary>
public interface IOrgOwned : IPartnerOwned
{
    Guid OrganizationId { get; }
}

/// <summary>
/// Partner library item. <c>OrganizationId == null</c> means shared with every organization of the partner
/// and readable by any principal that holds the endpoint's permission anywhere in the partner.
/// </summary>
public interface IOrgOptionalShared : IPartnerOwned
{
    Guid? OrganizationId { get; }
}

/// <summary>
/// Partner-level record. <c>OrganizationId == null</c> rows are only visible with partner-wide scope.
/// </summary>
public interface IOrgOptionalRestricted : IPartnerOwned
{
    Guid? OrganizationId { get; }
}

/// <summary>Row hangs off a device. Visibility follows the device (organization, site or group scope).</summary>
public interface IDeviceOwned : IOrgOwned
{
    Guid DeviceId { get; }
    Device Device { get; }
}

public enum ScopeType
{
    Partner,
    Organization,
    Site,
    Group,
}

public static class Permissions
{
    public const string TenantsRead = "tenants.read";
    public const string TenantsManage = "tenants.manage";
    public const string UsersRead = "users.read";
    public const string UsersManage = "users.manage";
    public const string RolesManage = "roles.manage";
    public const string EnrollmentManage = "enrollment.manage";
    public const string DevicesRead = "devices.read";
    public const string DevicesManage = "devices.manage";
    public const string DevicesRevoke = "devices.revoke";
    public const string AuditRead = "audit.read";
    public const string ScriptsRead = "scripts.read";
    public const string ScriptsManage = "scripts.manage";
    public const string ScriptsRun = "scripts.run";
    public const string JobsRead = "jobs.read";
    public const string JobsCancel = "jobs.cancel";
    public const string SoftwareRead = "software.read";
    public const string SoftwareDeploy = "software.deploy";
    public const string PackagesManage = "packages.manage";
    public const string PatchesRead = "patches.read";
    public const string PatchesApprove = "patches.approve";
    public const string PatchesInstall = "patches.install";
    public const string SecurityRead = "security.read";
    public const string AlertsRead = "alerts.read";
    public const string AlertsManage = "alerts.manage";
    public const string NotificationsManage = "notifications.manage";
    public const string RemoteTerminal = "remote.terminal";
    public const string RemoteFiles = "remote.files";
    public const string RemoteDesktop = "remote.desktop";
    public const string SessionsRead = "sessions.read";
    public const string PoliciesRead = "policies.read";
    public const string PoliciesManage = "policies.manage";
    public const string ReleasesManage = "releases.manage";
    public const string ReportsRead = "reports.read";
    public const string ApiKeysManage = "apikeys.manage";
    public const string WebhooksManage = "webhooks.manage";
    public const string SettingsManage = "settings.manage";

    public static readonly IReadOnlyList<string> All =
    [
        TenantsRead, TenantsManage, UsersRead, UsersManage, RolesManage, EnrollmentManage,
        DevicesRead, DevicesManage, DevicesRevoke, AuditRead,
        ScriptsRead, ScriptsManage, ScriptsRun, JobsRead, JobsCancel,
        SoftwareRead, SoftwareDeploy, PackagesManage,
        PatchesRead, PatchesApprove, PatchesInstall,
        SecurityRead, AlertsRead, AlertsManage, NotificationsManage,
        RemoteTerminal, RemoteFiles, RemoteDesktop, SessionsRead,
        PoliciesRead, PoliciesManage,
        ReleasesManage, ReportsRead, ApiKeysManage, WebhooksManage, SettingsManage,
    ];

    /// <summary>Permissions an API key may never hold or exercise (interactive, step-up protected).</summary>
    public static readonly IReadOnlySet<string> InteractiveOnly = new HashSet<string>
    {
        UsersManage, RolesManage, ApiKeysManage, ReleasesManage, SettingsManage, DevicesRevoke,
        RemoteTerminal, RemoteFiles, RemoteDesktop,
    };
}

public static class BuiltInRoles
{
    public const string PartnerAdmin = "Partner Admin";
    public const string Technician = "Technician";
    public const string ReadOnly = "Read-only";
    public const string OrganizationViewer = "Organization Viewer";

    public static readonly IReadOnlyDictionary<string, string[]> Definitions = new Dictionary<string, string[]>
    {
        [PartnerAdmin] = [.. Permissions.All],
        [Technician] =
        [
            Permissions.TenantsRead, Permissions.EnrollmentManage,
            Permissions.DevicesRead, Permissions.DevicesManage,
            Permissions.ScriptsRead, Permissions.ScriptsManage, Permissions.ScriptsRun,
            Permissions.JobsRead, Permissions.JobsCancel,
            Permissions.SoftwareRead, Permissions.SoftwareDeploy, Permissions.PackagesManage,
            Permissions.PatchesRead, Permissions.PatchesApprove, Permissions.PatchesInstall,
            Permissions.SecurityRead, Permissions.AlertsRead, Permissions.AlertsManage,
            Permissions.RemoteTerminal, Permissions.RemoteFiles, Permissions.RemoteDesktop, Permissions.SessionsRead,
            Permissions.PoliciesRead, Permissions.PoliciesManage, Permissions.ReportsRead,
        ],
        [ReadOnly] = [.. Permissions.All.Where(p => p.EndsWith(".read", StringComparison.Ordinal))],
        [OrganizationViewer] =
        [
            Permissions.TenantsRead, Permissions.DevicesRead, Permissions.SoftwareRead, Permissions.PatchesRead,
            Permissions.SecurityRead, Permissions.AlertsRead, Permissions.PoliciesRead, Permissions.ReportsRead,
        ],
    };
}
