import type { DeviceGroup, Id, Organization, ScopeType, Site } from '@/lib/api';

export interface ScopeDirectory {
  organizations: Organization[];
  sites: Site[];
  groups: DeviceGroup[];
}

/** "all organizations", "Acme", "Acme / London", "Acme / London / Finance". */
export function describeScope(scopeType: ScopeType, scopeId: Id | null, dir: ScopeDirectory): string {
  const org = (id: Id) => dir.organizations.find((o) => o.id === id)?.name ?? 'Unknown organization';
  switch (scopeType) {
    case 'Partner':
      return 'all organizations';
    case 'Organization':
      return scopeId ? org(scopeId) : 'Unknown organization';
    case 'Site': {
      const site = dir.sites.find((s) => s.id === scopeId);
      return site ? `${org(site.organizationId)} / ${site.name}` : 'Unknown site';
    }
    case 'Group': {
      const group = dir.groups.find((g) => g.id === scopeId);
      if (!group) {
        return 'Unknown group';
      }
      const site = dir.sites.find((s) => s.id === group.siteId);
      return `${org(group.organizationId)} / ${site?.name ?? 'Unknown site'} / ${group.name}`;
    }
  }
}

export const SCOPE_TYPE_LABEL: Record<ScopeType, string> = {
  Partner: 'All organizations',
  Organization: 'One organization',
  Site: 'One site',
  Group: 'One device group',
};
