import { describe, expect, it } from 'vitest';
import { DEVICE_TABS } from '@/features/devices/tabs/registry';
import { accessFor } from '@/lib/auth/permissions';
import { visibleNav } from './pages';

/** Built-in "Organization Viewer" (server `BuiltInRoles`): the read-only client portal role. */
const ORGANIZATION_VIEWER = [
  'tenants.read',
  'devices.read',
  'software.read',
  'patches.read',
  'security.read',
  'alerts.read',
  'policies.read',
  'reports.read',
];

describe('client portal (Organization Viewer)', () => {
  const viewer = accessFor({ permissions: ORGANIZATION_VIEWER, partnerWide: false });

  it('sees only pages it can read, and no admin, remote, enrollment, scripts or audit pages', () => {
    const labels = visibleNav(viewer).flatMap((a) => a.pages.map((p) => p.label));
    expect(labels).toEqual(
      expect.arrayContaining([
        'Overview',
        'Devices',
        'Security',
        'Alerts',
        'Policies',
        'Reports',
        'Patches',
        'Software',
      ]),
    );
    for (const hidden of [
      'Enrollment',
      'Remote sessions',
      'Scripts',
      'Jobs',
      'Audit log',
      'Users & roles',
      'Agent releases',
      'API keys',
    ]) {
      expect(labels).not.toContain(hidden);
    }
  });

  it('sees read tabs on a device but no remote, management or danger tabs', () => {
    const tabs = DEVICE_TABS.filter((t) => viewer.can(t)).map((t) => t.id);
    expect(tabs).toEqual(expect.arrayContaining(['overview', 'security', 'compliance']));
    for (const hidden of ['remote', 'manage', 'danger', 'scripts']) {
      expect(tabs).not.toContain(hidden);
    }
  });

  it('holds no permission behind an action button', () => {
    for (const action of [
      'devices.manage',
      'devices.revoke',
      'alerts.manage',
      'policies.manage',
      'notifications.manage',
      'remote.terminal',
      'remote.files',
      'remote.desktop',
      'enrollment.manage',
    ]) {
      expect(viewer.has(action), action).toBe(false);
    }
  });

  it('cannot open partner-wide admin pages even with their permission at organization scope', () => {
    const scoped = accessFor({ permissions: ['releases.manage', 'apikeys.manage'], partnerWide: false });
    expect(visibleNav(scoped)).toEqual([]);
  });
});
