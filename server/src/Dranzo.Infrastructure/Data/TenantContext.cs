namespace Dranzo.Infrastructure.Data;

/// <summary>
/// The scope the current request may see. It starts <b>empty</b> (matches no rows) and is filled by the
/// permission middleware with the scopes in which the caller holds the endpoint's permission.
/// Background services and the agent gateway call <see cref="SetSystem"/> and scope queries explicitly.
/// </summary>
public sealed class TenantContext
{
    public bool IsSystem { get; private set; }
    public Guid PartnerId { get; private set; }
    public bool AllOrgs { get; private set; }
    public Guid[] OrgIds { get; private set; } = [];
    public Guid[] SiteIds { get; private set; } = [];
    public Guid[] GroupIds { get; private set; } = [];
    /// <summary>Organizations the caller may see the name of (full org scope plus parents of scoped sites/groups).</summary>
    public Guid[] VisibleOrgIds { get; private set; } = [];
    /// <summary>Sites the caller may see the name of (site scope plus parents of scoped groups).</summary>
    public Guid[] VisibleSiteIds { get; private set; } = [];

    public string ActorType { get; private set; } = "system";
    public Guid? ActorId { get; private set; }
    public string ActorName { get; private set; } = "system";
    public string? Ip { get; private set; }

    public bool IsEmpty => !IsSystem && PartnerId == Guid.Empty;

    public void SetSystem()
    {
        Clear();
        IsSystem = true;
    }

    public void SetActor(string actorType, Guid? actorId, string actorName, string? ip)
    {
        ActorType = actorType;
        ActorId = actorId;
        ActorName = actorName;
        Ip = ip;
    }

    public void SetScope(Guid partnerId, bool allOrgs, Guid[] orgIds, Guid[] siteIds, Guid[] groupIds, Guid[] visibleOrgIds, Guid[] visibleSiteIds)
    {
        IsSystem = false;
        PartnerId = partnerId;
        AllOrgs = allOrgs;
        OrgIds = orgIds;
        SiteIds = siteIds;
        GroupIds = groupIds;
        VisibleOrgIds = visibleOrgIds;
        VisibleSiteIds = visibleSiteIds;
    }

    public void Clear()
    {
        IsSystem = false;
        PartnerId = Guid.Empty;
        AllOrgs = false;
        OrgIds = [];
        SiteIds = [];
        GroupIds = [];
        VisibleOrgIds = [];
        VisibleSiteIds = [];
    }

    /// <summary>True when the scope covers the whole organization.</summary>
    public bool CoversOrganization(Guid organizationId) => IsSystem || AllOrgs || OrgIds.Contains(organizationId);

    public bool CoversSite(Guid organizationId, Guid siteId) => CoversOrganization(organizationId) || SiteIds.Contains(siteId);

    /// <summary>Same rule as the device query filter, for devices already in memory.</summary>
    public bool CoversDevice(Guid partnerId, Guid organizationId, Guid siteId, Guid? groupId) =>
        IsSystem || (partnerId == PartnerId && (CoversSite(organizationId, siteId) || (groupId is { } g && GroupIds.Contains(g))));
}
