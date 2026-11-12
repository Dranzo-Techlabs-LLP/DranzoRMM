import type { AuditFilter, DeviceListFilter, Id } from './types';

/** TanStack Query keys. Kept in one place so live updates and mutations invalidate the right data. */
export const qk = {
  me: ['auth', 'me'] as const,
  /** Client-only marker: the user signed out on purpose, so the sign-in page should not offer a return URL. */
  signedOut: ['auth', 'signed-out'] as const,
  permissionCatalog: ['auth', 'permissions'] as const,
  organizations: ['organizations'] as const,
  sites: (organizationId?: Id) => ['sites', organizationId ?? 'all'] as const,
  sitesAll: ['sites'] as const,
  groups: (organizationId?: Id) => ['groups', organizationId ?? 'all'] as const,
  groupsAll: ['groups'] as const,
  users: ['users'] as const,
  roles: ['roles'] as const,
  tokens: (organizationId?: Id) => ['enrollment-tokens', organizationId ?? 'all'] as const,
  tokensAll: ['enrollment-tokens'] as const,
  installInfo: ['install-info'] as const,
  enrollmentTargets: ['enrollment-tokens', 'targets'] as const,
  installers: ['agent-installers'] as const,
  timeZones: ['auth', 'time-zones'] as const,
  overview: (organizationId?: Id) => ['devices', 'overview', organizationId ?? 'all'] as const,
  devices: ['devices'] as const,
  deviceLists: ['devices', 'list'] as const,
  deviceList: (filter: DeviceListFilter) => ['devices', 'list', filter] as const,
  deviceDetail: (id: Id) => ['devices', 'detail', id] as const,
  audit: (filter: AuditFilter) => ['audit', filter] as const,
  auditAll: ['audit'] as const,
};
