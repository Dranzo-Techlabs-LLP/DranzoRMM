import type { Me } from '@/lib/api';

/** Permission strings, mirroring `Dranzo.Domain.Permissions` for the areas the dashboard implements. */
export const P = {
  tenantsRead: 'tenants.read',
  tenantsManage: 'tenants.manage',
  usersRead: 'users.read',
  usersManage: 'users.manage',
  rolesManage: 'roles.manage',
  enrollmentManage: 'enrollment.manage',
  devicesRead: 'devices.read',
  devicesManage: 'devices.manage',
  devicesRevoke: 'devices.revoke',
  auditRead: 'audit.read',
  scriptsRead: 'scripts.read',
  jobsRead: 'jobs.read',
  softwareRead: 'software.read',
  patchesRead: 'patches.read',
  securityRead: 'security.read',
  alertsRead: 'alerts.read',
  alertsManage: 'alerts.manage',
  notificationsManage: 'notifications.manage',
  remoteTerminal: 'remote.terminal',
  remoteFiles: 'remote.files',
  remoteDesktop: 'remote.desktop',
  sessionsRead: 'sessions.read',
  policiesRead: 'policies.read',
  policiesManage: 'policies.manage',
  releasesManage: 'releases.manage',
  apiKeysManage: 'apikeys.manage',
  settingsManage: 'settings.manage',
  reportsRead: 'reports.read',
} as const;

export interface Requirement {
  /** Permission the user must hold somewhere. Omit for "any signed-in user". */
  permission?: string;
  /** The server endpoint needs the permission at partner scope (`RequirePermission(..., partnerWide: true)`). */
  partnerWide?: boolean;
}

export interface Access {
  has: (permission: string) => boolean;
  /** Holds the permission and has a partner-scope assignment. */
  hasPartnerWide: (permission: string) => boolean;
  can: (requirement: Requirement) => boolean;
}

/**
 * UI-side permission checks. They only hide dead ends; the server enforces everything.
 * `partnerWide` from `/auth/me` means "has some partner-scope assignment", which is the closest the client can get
 * to the server's per-permission scope check.
 */
export function accessFor(me: Pick<Me, 'permissions' | 'partnerWide'> | null | undefined): Access {
  const set = new Set(me?.permissions ?? []);
  const has = (permission: string) => set.has(permission);
  const hasPartnerWide = (permission: string) => has(permission) && me?.partnerWide === true;
  return {
    has,
    hasPartnerWide,
    can: ({ permission, partnerWide }) => {
      if (!me) {
        return false;
      }
      if (!permission) {
        return true;
      }
      return partnerWide ? hasPartnerWide(permission) : has(permission);
    },
  };
}
