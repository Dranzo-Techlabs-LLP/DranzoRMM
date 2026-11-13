using System.Reflection;
using Dranzo.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Dranzo.Infrastructure.Data;

public class DranzoDbContext(DbContextOptions<DranzoDbContext> options, TenantContext tenant)
    : DbContext(options)
{
    /// <summary>Referenced by the global query filters; EF evaluates it per context instance.</summary>
    public TenantContext Tenant { get; } = tenant;

    public DbSet<Partner> Partners => Set<Partner>();
    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<Site> Sites => Set<Site>();
    public DbSet<DeviceGroup> DeviceGroups => Set<DeviceGroup>();
    public DbSet<User> Users => Set<User>();
    public DbSet<UserSession> UserSessions => Set<UserSession>();
    public DbSet<Role> Roles => Set<Role>();
    public DbSet<RoleAssignment> RoleAssignments => Set<RoleAssignment>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<EnrollmentToken> EnrollmentTokens => Set<EnrollmentToken>();
    public DbSet<Device> Devices => Set<Device>();
    public DbSet<InventorySnapshot> InventorySnapshots => Set<InventorySnapshot>();
    public DbSet<InstalledSoftware> InstalledSoftware => Set<InstalledSoftware>();
    public DbSet<SavedFilter> SavedFilters => Set<SavedFilter>();
    public DbSet<Script> Scripts => Set<Script>();
    public DbSet<ScriptVersion> ScriptVersions => Set<ScriptVersion>();
    public DbSet<Job> Jobs => Set<Job>();
    public DbSet<JobRun> JobRuns => Set<JobRun>();
    public DbSet<JobOutputChunk> JobOutputChunks => Set<JobOutputChunk>();
    public DbSet<Blob> Blobs => Set<Blob>();
    public DbSet<BlobGrant> BlobGrants => Set<BlobGrant>();
    public DbSet<UploadTicket> UploadTickets => Set<UploadTicket>();
    public DbSet<Package> Packages => Set<Package>();
    public DbSet<PatchCatalogEntry> PatchCatalog => Set<PatchCatalogEntry>();
    public DbSet<DevicePatchState> DevicePatchStates => Set<DevicePatchState>();
    public DbSet<PatchPolicy> PatchPolicies => Set<PatchPolicy>();
    public DbSet<PostureSnapshot> PostureSnapshots => Set<PostureSnapshot>();
    public DbSet<CveEntry> CveEntries => Set<CveEntry>();
    public DbSet<NetworkDevice> NetworkDevices => Set<NetworkDevice>();
    public DbSet<NetworkController> NetworkControllers => Set<NetworkController>();
    public DbSet<RadiusConfig> RadiusConfigs => Set<RadiusConfig>();
    public DbSet<NetworkCertificate> NetworkCertificates => Set<NetworkCertificate>();
    public DbSet<FeedState> FeedStates => Set<FeedState>();
    public DbSet<DeviceVulnerability> DeviceVulnerabilities => Set<DeviceVulnerability>();
    public DbSet<NotificationChannel> NotificationChannels => Set<NotificationChannel>();
    public DbSet<AlertRule> AlertRules => Set<AlertRule>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<Policy> Policies => Set<Policy>();
    public DbSet<PolicyAssignment> PolicyAssignments => Set<PolicyAssignment>();
    public DbSet<ComplianceResult> ComplianceResults => Set<ComplianceResult>();
    public DbSet<RemoteSession> RemoteSessions => Set<RemoteSession>();
    public DbSet<AgentRelease> AgentReleases => Set<AgentRelease>();
    public DbSet<AgentReleaseBinary> AgentReleaseBinaries => Set<AgentReleaseBinary>();
    public DbSet<DeviceUpdateState> DeviceUpdateStates => Set<DeviceUpdateState>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<WebhookDelivery> WebhookDeliveries => Set<WebhookDelivery>();

    /// <summary>Entity types that are deliberately not tenant-filtered. Everything else must implement a tenancy interface.</summary>
    public static readonly IReadOnlySet<Type> GlobalEntities = new HashSet<Type> { typeof(CveEntry), typeof(FeedState) };

    protected override void OnModelCreating(ModelBuilder b)
    {
        // ----- Tenant query filters (central enforcement; see docs/ARCHITECTURE.md section 3) -----
        b.Entity<Partner>().HasQueryFilter(e => Tenant.IsSystem || e.Id == Tenant.PartnerId);
        b.Entity<Organization>().HasQueryFilter(e => Tenant.IsSystem ||
            (e.PartnerId == Tenant.PartnerId && e.DeletedAt == null && (Tenant.AllOrgs || Tenant.VisibleOrgIds.Contains(e.Id))));
        b.Entity<Site>().HasQueryFilter(e => Tenant.IsSystem ||
            (e.PartnerId == Tenant.PartnerId && (Tenant.AllOrgs || Tenant.OrgIds.Contains(e.OrganizationId) || Tenant.VisibleSiteIds.Contains(e.Id))));
        b.Entity<DeviceGroup>().HasQueryFilter(e => Tenant.IsSystem ||
            (e.PartnerId == Tenant.PartnerId && (Tenant.AllOrgs || Tenant.OrgIds.Contains(e.OrganizationId) || Tenant.SiteIds.Contains(e.SiteId) || Tenant.GroupIds.Contains(e.Id))));
        b.Entity<Device>().HasQueryFilter(e => Tenant.IsSystem ||
            (e.PartnerId == Tenant.PartnerId && (Tenant.AllOrgs || Tenant.OrgIds.Contains(e.OrganizationId) || Tenant.SiteIds.Contains(e.SiteId)
                || (e.GroupId != null && Tenant.GroupIds.Contains(e.GroupId.Value)))));

        var special = new HashSet<Type> { typeof(Partner), typeof(Organization), typeof(Site), typeof(DeviceGroup), typeof(Device) };
        foreach (var entityType in b.Model.GetEntityTypes().Select(t => t.ClrType).Where(t => !special.Contains(t) && !GlobalEntities.Contains(t)).ToList())
        {
            var method = entityType switch
            {
                _ when typeof(IDeviceOwned).IsAssignableFrom(entityType) => nameof(DeviceOwnedFilter),
                _ when typeof(IOrgOwned).IsAssignableFrom(entityType) => nameof(OrgOwnedFilter),
                _ when typeof(IOrgOptionalShared).IsAssignableFrom(entityType) => nameof(OrgOptionalSharedFilter),
                _ when typeof(IOrgOptionalRestricted).IsAssignableFrom(entityType) => nameof(OrgOptionalRestrictedFilter),
                _ when typeof(IPartnerOwned).IsAssignableFrom(entityType) => nameof(PartnerOwnedFilter),
                _ => throw new InvalidOperationException($"Entity {entityType.Name} has no tenancy interface and is not in GlobalEntities."),
            };
            typeof(DranzoDbContext).GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!
                .MakeGenericMethod(entityType).Invoke(this, [b]);
        }

        // ----- Shape -----
        foreach (var entity in b.Model.GetEntityTypes())
        {
            foreach (var p in entity.GetProperties())
            {
                var t = Nullable.GetUnderlyingType(p.ClrType) ?? p.ClrType;
                if (t.IsEnum)
                {
                    p.SetProviderClrType(typeof(string));
                    p.SetMaxLength(32);
                }
                if (p.Name.EndsWith("Json", StringComparison.Ordinal) && p.ClrType == typeof(string))
                {
                    p.SetColumnType("jsonb");
                }
            }
        }

        b.Entity<User>().HasIndex(e => e.Email).IsUnique();
        b.Entity<UserSession>().HasIndex(e => e.TokenHash).IsUnique();
        b.Entity<ApiKey>().HasIndex(e => e.PartnerId);
        b.Entity<Role>().HasIndex(e => new { e.PartnerId, e.Name }).IsUnique();
        b.Entity<RoleAssignment>().HasIndex(e => e.UserId);
        b.Entity<RoleAssignment>().HasIndex(e => e.ApiKeyId);
        b.Entity<RoleAssignment>().HasOne(e => e.Role).WithMany().HasForeignKey(e => e.RoleId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<Organization>().HasIndex(e => e.PartnerId);
        b.Entity<Site>().HasIndex(e => e.OrganizationId);
        b.Entity<DeviceGroup>().HasIndex(e => e.SiteId);
        b.Entity<EnrollmentToken>().HasIndex(e => e.TokenHash).IsUnique();
        b.Entity<Device>().HasIndex(e => new { e.PartnerId, e.OrganizationId });
        b.Entity<Device>().HasIndex(e => e.CertThumbprint);
        b.Entity<Device>().HasIndex(e => e.PrevCertThumbprint);
        b.Entity<Device>().HasIndex(e => e.IsOnline);
        b.Entity<InventorySnapshot>().HasIndex(e => new { e.DeviceId, e.IsLatest });
        b.Entity<InstalledSoftware>().HasIndex(e => e.DeviceId);
        b.Entity<InstalledSoftware>().HasIndex(e => e.Name);
        b.Entity<Script>().HasMany(e => e.Versions).WithOne().HasForeignKey(v => v.ScriptId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<ScriptVersion>().HasIndex(e => new { e.ScriptId, e.Version }).IsUnique();
        b.Entity<Job>().HasIndex(e => e.NextRunAt);
        b.Entity<JobRun>().HasIndex(e => new { e.DeviceId, e.Status });
        b.Entity<JobRun>().HasIndex(e => e.JobId);
        b.Entity<JobRun>().HasIndex(e => e.Status);
        b.Entity<JobRun>().HasOne(e => e.Job).WithMany().HasForeignKey(e => e.JobId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<JobOutputChunk>().HasIndex(e => new { e.JobRunId, e.Seq });
        b.Entity<BlobGrant>().HasIndex(e => new { e.DeviceId, e.BlobId });
        b.Entity<PatchCatalogEntry>().HasIndex(e => new { e.PartnerId, e.OrganizationId, e.Source, e.UpdateId }).IsUnique();
        b.Entity<DevicePatchState>().HasIndex(e => new { e.DeviceId, e.CatalogEntryId }).IsUnique();
        b.Entity<DevicePatchState>().HasOne(e => e.CatalogEntry).WithMany().HasForeignKey(e => e.CatalogEntryId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<PostureSnapshot>().HasIndex(e => new { e.DeviceId, e.IsLatest });
        b.Entity<CveEntry>().HasIndex(e => e.Products).HasMethod("gin");
        b.Entity<FeedState>().HasKey(e => e.Name);
        b.Entity<DeviceVulnerability>().HasIndex(e => new { e.DeviceId, e.CveId });
        b.Entity<Alert>().HasIndex(e => new { e.DeviceId, e.DedupKey, e.State });
        b.Entity<Alert>().HasIndex(e => new { e.PartnerId, e.State });
        b.Entity<PolicyAssignment>().HasOne(e => e.Policy).WithMany().HasForeignKey(e => e.PolicyId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<ComplianceResult>().HasIndex(e => new { e.DeviceId, e.PolicyId }).IsUnique();
        b.Entity<RemoteSession>().HasIndex(e => e.DeviceId);
        b.Entity<AgentRelease>().HasIndex(e => new { e.PartnerId, e.Version }).IsUnique();
        b.Entity<AgentRelease>().HasMany(e => e.Binaries).WithOne().HasForeignKey(x => x.ReleaseId).OnDelete(DeleteBehavior.Cascade);
        b.Entity<DeviceUpdateState>().HasIndex(e => new { e.DeviceId, e.ReleaseId }).IsUnique();
        b.Entity<AuditEvent>().HasIndex(e => new { e.PartnerId, e.Sequence }).IsUnique();
        b.Entity<AuditEvent>().HasIndex(e => e.OccurredAt);
        b.Entity<WebhookDelivery>().HasIndex(e => new { e.DeliveredAt, e.NextAttemptAt });
        b.Entity<NetworkDevice>().HasIndex(e => new { e.SiteId, e.Mac }).IsUnique();
        b.Entity<RadiusConfig>().HasIndex(e => e.OrganizationId).IsUnique();
        b.Entity<NetworkCertificate>().HasIndex(e => e.SerialHex).IsUnique();
        b.Entity<NetworkDevice>().HasIndex(e => new { e.OrganizationId, e.Status });
        b.Entity<Device>().HasIndex(e => e.MacAddresses).HasMethod("gin");

        // Device-owned rows are removed with their device, except audit events (never deleted).
        foreach (var entity in b.Model.GetEntityTypes().Where(t => typeof(IDeviceOwned).IsAssignableFrom(t.ClrType)))
        {
            b.Entity(entity.ClrType).HasOne(typeof(Device), nameof(IDeviceOwned.Device)).WithMany().HasForeignKey(nameof(IDeviceOwned.DeviceId)).OnDelete(DeleteBehavior.Cascade);
        }
    }

    private void PartnerOwnedFilter<T>(ModelBuilder b) where T : class, IPartnerOwned =>
        b.Entity<T>().HasQueryFilter(e => Tenant.IsSystem || e.PartnerId == Tenant.PartnerId);

    private void OrgOwnedFilter<T>(ModelBuilder b) where T : class, IOrgOwned =>
        b.Entity<T>().HasQueryFilter(e => Tenant.IsSystem ||
            (e.PartnerId == Tenant.PartnerId && (Tenant.AllOrgs || Tenant.OrgIds.Contains(e.OrganizationId))));

    private void OrgOptionalSharedFilter<T>(ModelBuilder b) where T : class, IOrgOptionalShared =>
        b.Entity<T>().HasQueryFilter(e => Tenant.IsSystem ||
            (e.PartnerId == Tenant.PartnerId && (e.OrganizationId == null || Tenant.AllOrgs || Tenant.OrgIds.Contains(e.OrganizationId.Value))));

    private void OrgOptionalRestrictedFilter<T>(ModelBuilder b) where T : class, IOrgOptionalRestricted =>
        b.Entity<T>().HasQueryFilter(e => Tenant.IsSystem ||
            (e.PartnerId == Tenant.PartnerId && (Tenant.AllOrgs || (e.OrganizationId != null && Tenant.OrgIds.Contains(e.OrganizationId.Value)))));

    private void DeviceOwnedFilter<T>(ModelBuilder b) where T : class, IDeviceOwned =>
        b.Entity<T>().HasQueryFilter(e => Tenant.IsSystem ||
            (e.PartnerId == Tenant.PartnerId && (Tenant.AllOrgs || Tenant.OrgIds.Contains(e.OrganizationId) || Tenant.SiteIds.Contains(e.Device.SiteId)
                || (e.Device.GroupId != null && Tenant.GroupIds.Contains(e.Device.GroupId.Value)))));
}

/// <summary>Used by <c>dotnet ef</c> only.</summary>
public class DesignTimeFactory : IDesignTimeDbContextFactory<DranzoDbContext>
{
    public DranzoDbContext CreateDbContext(string[] args)
    {
        var conn = Environment.GetEnvironmentVariable("DRANZO_DB") ?? "Host=localhost;Database=dranzo_design";
        var options = new DbContextOptionsBuilder<DranzoDbContext>().UseNpgsql(conn).Options;
        var tenant = new TenantContext();
        tenant.SetSystem();
        return new DranzoDbContext(options, tenant);
    }
}
