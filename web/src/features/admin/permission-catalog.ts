import { capitalize } from '@/lib/format';

/** Friendly names for permission areas (the part before the dot). Unknown areas fall back to the raw word. */
const AREA_LABELS: Record<string, string> = {
  tenants: 'Organizations, sites and groups',
  users: 'Users',
  roles: 'Roles',
  enrollment: 'Enrollment',
  devices: 'Devices',
  audit: 'Audit log',
  scripts: 'Scripts',
  jobs: 'Jobs',
  software: 'Software',
  packages: 'Packages',
  patches: 'Patches',
  security: 'Security',
  alerts: 'Alerts',
  notifications: 'Notifications',
  remote: 'Remote support',
  sessions: 'Remote sessions',
  policies: 'Policies',
  releases: 'Agent releases',
  reports: 'Reports',
  apikeys: 'API keys',
  webhooks: 'Webhooks',
  settings: 'Settings',
};

const ACTION_LABELS: Record<string, string> = {
  read: 'View',
  manage: 'Create, change and delete',
  run: 'Run',
  cancel: 'Cancel',
  deploy: 'Install and remove',
  approve: 'Approve',
  install: 'Install',
  revoke: 'Revoke and delete',
  terminal: 'Open a terminal',
  files: 'Browse and transfer files',
  desktop: 'Control the desktop',
};

export interface PermissionItem {
  /** The permission string the server understands, e.g. `devices.read`. */
  id: string;
  label: string;
}

export interface PermissionGroup {
  area: string;
  label: string;
  items: PermissionItem[];
}

export function permissionLabel(permission: string): string {
  const [, action = ''] = permission.split('.');
  return ACTION_LABELS[action] ?? capitalize(action);
}

/** Groups the server's flat permission list by area, keeping the server's order. */
export function groupPermissions(permissions: readonly string[]): PermissionGroup[] {
  const groups = new Map<string, PermissionGroup>();
  for (const id of permissions) {
    const area = id.split('.')[0] ?? id;
    let group = groups.get(area);
    if (!group) {
      group = { area, label: AREA_LABELS[area] ?? capitalize(area), items: [] };
      groups.set(area, group);
    }
    group.items.push({ id, label: permissionLabel(id) });
  }
  return [...groups.values()];
}
