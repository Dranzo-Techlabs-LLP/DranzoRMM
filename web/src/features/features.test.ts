import { describe, expect, it } from 'vitest';
import { groupPermissions, permissionLabel } from '@/features/admin/permission-catalog';
import { principalStatus, reviewSummary } from '@/features/admin/access/review';
import { describeScope } from '@/features/admin/scope';
import { formatAuditDetail, resultTone } from '@/features/audit/detail';
import { readDeviceFilters, toApiFilter, writeDeviceFilters } from '@/features/devices/filters';
import { installCommands, tokenState } from '@/features/enrollment/tokens';
import { timeZoneOptions } from '@/features/organizations/timezones';
import { matchesPostureFilter, scoreTone } from '@/features/security/posture-model';
import { countDevices, summarizeByOrganization } from '@/features/overview/fleet';
import { auditApi, type DeviceListItem, type EnrollmentToken, type InstallInfo, type Organization } from '@/lib/api';
import type { AccessPrincipal } from '@/lib/api/access';
import type { PostureRow } from '@/lib/api/security';
import { formatBytes, formatDuration, formatRelative, localInputToIso } from '@/lib/format';

const org = (id: string, name: string, deviceCount = 0, onlineCount = 0): Organization => ({
  id,
  name,
  timeZone: 'UTC',
  consentMode: 'require',
  requireSignedPowerShell: false,
  createdAt: '2026-01-01T00:00:00Z',
  deviceCount,
  onlineCount,
});

const dev = (organizationId: string, isOnline: boolean, pendingReboot = false) =>
  ({ id: crypto.randomUUID(), organizationId, isOnline, pendingReboot }) as DeviceListItem;

describe('overview counts', () => {
  it('counts online, offline and restart-pending devices', () => {
    expect(countDevices([dev('a', true), dev('a', false, true), dev('a', false)])).toEqual({
      total: 3,
      online: 1,
      offline: 2,
      pendingReboot: 1,
    });
  });

  it('summarizes per organization, including organizations without devices', () => {
    const rows = summarizeByOrganization(
      { devices: [dev('a', true), dev('a', false, true), dev('b', true)], total: 3, complete: true },
      [org('b', 'Beta'), org('a', 'Acme'), org('c', 'Corp')],
    );
    expect(rows.map((r) => [r.name, r.total, r.online, r.offline, r.pendingReboot])).toEqual([
      ['Acme', 2, 1, 1, 1],
      ['Beta', 1, 1, 0, 0],
      ['Corp', 0, 0, 0, 0],
    ]);
  });

  it('falls back to the organization list totals when the device list was cut off', () => {
    const rows = summarizeByOrganization({ devices: [dev('a', true)], total: 9000, complete: false }, [
      org('a', 'Acme', 9000, 8000),
    ]);
    expect(rows[0]).toMatchObject({ total: 9000, online: 8000, offline: 1000 });
  });

  it('still groups devices when the user cannot list organizations', () => {
    const rows = summarizeByOrganization(
      { devices: [dev('abcdef12-0000', true)], total: 1, complete: true },
      undefined,
    );
    expect(rows[0]).toMatchObject({ name: 'Organization abcdef12', total: 1 });
  });
});

describe('device filters', () => {
  it('round-trips through the URL', () => {
    const params = new URLSearchParams('q=web&os=linux&status=offline&tag=kiosk&page=3&site=s1');
    const filters = readDeviceFilters(params);
    expect(filters).toEqual({
      search: 'web',
      siteId: 's1',
      groupId: '',
      os: 'linux',
      status: 'offline',
      tag: 'kiosk',
      reboot: false,
      sort: 'hostname',
      page: 3,
    });
    expect(writeDeviceFilters(filters).toString()).toBe('q=web&site=s1&os=linux&status=offline&tag=kiosk&page=3');
    const reboot = readDeviceFilters(new URLSearchParams('reboot=1&sort=lastSeen'));
    expect(reboot).toMatchObject({ reboot: true, sort: 'lastSeen' });
    expect(writeDeviceFilters(reboot).toString()).toBe('reboot=1&sort=lastSeen');
    expect(toApiFilter(reboot, null)).toMatchObject({ pendingReboot: true, sort: 'lastSeen' });
    expect(readDeviceFilters(new URLSearchParams('sort=evil'))).toMatchObject({ sort: 'hostname' });
  });

  it('ignores invalid values', () => {
    expect(readDeviceFilters(new URLSearchParams('status=maybe&page=-2'))).toMatchObject({ status: '', page: 1 });
  });

  it('maps to the API query, including the global organization', () => {
    const filters = readDeviceFilters(new URLSearchParams('status=online&q=%20srv%20'));
    expect(toApiFilter(filters, 'org-9')).toMatchObject({
      organizationId: 'org-9',
      online: true,
      search: 'srv',
      page: 1,
      pageSize: 50,
    });
    expect(toApiFilter(readDeviceFilters(new URLSearchParams()), null)).toMatchObject({
      organizationId: undefined,
      online: undefined,
    });
  });
});

describe('enrollment tokens', () => {
  const token = (patch: Partial<EnrollmentToken>): EnrollmentToken => ({
    id: 't',
    organizationId: 'o',
    siteId: 's',
    groupId: null,
    name: 'n',
    tokenPrefix: 'dz_enroll_abc',
    expiresAt: '2026-12-01T00:00:00Z',
    maxUses: 5,
    uses: 0,
    revokedAt: null,
    createdAt: '2026-11-01T00:00:00Z',
    ...patch,
  });
  const now = Date.parse('2026-11-11T00:00:00Z');

  it('derives the token state', () => {
    expect(tokenState(token({}), now)).toBe('active');
    expect(tokenState(token({ revokedAt: '2026-11-02T00:00:00Z' }), now)).toBe('revoked');
    expect(tokenState(token({ expiresAt: '2026-11-10T00:00:00Z' }), now)).toBe('expired');
    expect(tokenState(token({ uses: 5 }), now)).toBe('used-up');
  });

  it('substitutes the token into every install command and lists what is left to fill in', () => {
    const info: InstallInfo = {
      serverUrl: 'https://agents.example',
      caCertificatePem: '',
      trust: { commandKeys: [] },
      commands: {
        windows:
          'dranzo-agent.exe install --server https://agents.example --token <token> --ca-file ca.pem --trust-file trust.json',
        macos:
          'sudo ./dranzo-agent install --server https://agents.example --token <token> --ca-file ca.pem --trust-file trust.json',
        linux:
          'sudo ./dranzo-agent install --server https://agents.example --token <token> --ca-file ca.pem --trust-file trust.json',
        windowsMsi: 'msiexec /i DranzoAgent-<arch>.msi /qn SERVERURL="https://agents.example" ENROLLTOKEN="<token>"',
        linuxDeb: 'sudo dpkg -i dranzo-agent_<version>_<arch>.deb && sudo dranzo-agent install --token <token>',
        linuxRpm: 'sudo rpm -i dranzo-agent-<version>.<arch>.rpm && sudo dranzo-agent install --token <token>',
        check: 'curl -k https://agents.example/agent/v1/healthz',
      },
    };
    const commands = installCommands(info, 'dz_enroll_SECRET');
    expect(commands.map((c) => c.label)).toEqual(['Windows', 'macOS', 'Linux', 'Connection test']);
    for (const c of commands.filter((x) => x.id !== 'check')) {
      expect(c.command).toContain('dz_enroll_SECRET');
      expect(c.command).not.toContain('<token>');
      expect(c.command).toContain('--ca-file ca.pem --trust-file trust.json');
      expect(c.placeholders).toEqual([]);
    }
  });
});

describe('audit helpers', () => {
  it('pretty-prints JSON detail and keeps anything else verbatim', () => {
    expect(formatAuditDetail('{"name":"Acme","n":1}')).toBe('{\n  "name": "Acme",\n  "n": 1\n}');
    expect(formatAuditDetail('{}')).toBeNull();
    expect(formatAuditDetail('')).toBeNull();
    expect(formatAuditDetail('<b>not json</b>')).toBe('<b>not json</b>');
    // Current servers send the detail as an object.
    expect(formatAuditDetail({ name: 'Acme', n: 1 })).toBe('{\n  "name": "Acme",\n  "n": 1\n}');
    expect(formatAuditDetail({})).toBeNull();
    expect(formatAuditDetail(null)).toBeNull();
  });

  it('maps results to tones', () => {
    expect(resultTone('success')).toBe('ok');
    expect(resultTone('denied')).toBe('danger');
    expect(resultTone('other')).toBe('idle');
  });

  it('builds the CSV export link from the filters without paging', () => {
    expect(auditApi.exportUrl({ action: 'device.', organizationId: 'o1', page: 4, pageSize: 50 })).toBe(
      '/api/v1/audit/export.csv?action=device.&organizationId=o1',
    );
    expect(auditApi.exportUrl({})).toBe('/api/v1/audit/export.csv');
  });
});

describe('roles and scopes', () => {
  it('groups the permission catalog by area in server order', () => {
    const groups = groupPermissions([
      'tenants.read',
      'tenants.manage',
      'devices.read',
      'remote.terminal',
      'newarea.launch',
    ]);
    expect(groups.map((g) => [g.label, g.items.map((i) => i.id)])).toEqual([
      ['Organizations, sites and groups', ['tenants.read', 'tenants.manage']],
      ['Devices', ['devices.read']],
      ['Remote support', ['remote.terminal']],
      ['Newarea', ['newarea.launch']],
    ]);
    expect(permissionLabel('devices.read')).toBe('View');
    expect(permissionLabel('newarea.launch')).toBe('Launch');
  });

  it('describes assignment scopes by name', () => {
    const dir = {
      organizations: [org('o1', 'Acme')],
      sites: [{ id: 's1', organizationId: 'o1', name: 'London' }],
      groups: [{ id: 'g1', organizationId: 'o1', siteId: 's1', name: 'Finance', updateRing: 'all' as const }],
    };
    expect(describeScope('Partner', null, dir)).toBe('all organizations');
    expect(describeScope('Organization', 'o1', dir)).toBe('Acme');
    expect(describeScope('Site', 's1', dir)).toBe('Acme / London');
    expect(describeScope('Group', 'g1', dir)).toBe('Acme / London / Finance');
    expect(describeScope('Site', 'gone', dir)).toBe('Unknown site');
  });
});

describe('formatting', () => {
  const now = Date.parse('2026-11-11T12:00:00Z');

  it('formats relative times', () => {
    expect(formatRelative('2026-11-11T11:59:55Z', now)).toBe('just now');
    expect(formatRelative('2026-11-11T11:55:00Z', now)).toBe('5 minutes ago');
    expect(formatRelative('2026-11-10T12:00:00Z', now)).toBe('yesterday');
    expect(formatRelative('2026-11-14T12:00:00Z', now)).toBe('in 3 days');
    expect(formatRelative(null, now)).toBe('never');
    expect(formatRelative('garbage', now)).toBe('never');
  });

  it('formats sizes and durations', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(17179869184)).toBe('16.0 GB');
    expect(formatBytes(536870912000)).toBe('500 GB');
    expect(formatBytes(null)).toBe('');
    expect(formatDuration(90061)).toBe('1d 1h');
    expect(formatDuration(3700)).toBe('1h 1m');
  });

  it('converts local date-time input to an ISO instant', () => {
    expect(localInputToIso('')).toBeUndefined();
    expect(localInputToIso('2026-11-11T09:30')).toBe(new Date('2026-11-11T09:30').toISOString());
  });

  it('always offers UTC and the current time zone', () => {
    const zones = timeZoneOptions('Mars/Olympus_Mons');
    expect(zones).toContain('UTC');
    expect(zones).toContain('Mars/Olympus_Mons');
  });
});

describe('access review', () => {
  const base: AccessPrincipal = {
    kind: 'user',
    id: '1',
    name: 'Ann',
    email: 'ann@example.test',
    disabled: false,
    locked: false,
    mfaEnabled: true,
    lastActiveAt: null,
    expiresAt: null,
    grants: [],
    permissions: [],
    findings: [],
  };

  it('labels status for users and API keys', () => {
    expect(principalStatus(base)).toEqual({ label: 'Active', tone: 'ok' });
    expect(principalStatus({ ...base, locked: true })).toEqual({ label: 'Locked', tone: 'warn' });
    expect(principalStatus({ ...base, disabled: true })).toEqual({ label: 'Disabled', tone: 'idle' });
    expect(principalStatus({ ...base, kind: 'apikey', disabled: true })).toEqual({ label: 'Expired', tone: 'idle' });
  });

  it('counts findings only for active principals', () => {
    const rows: AccessPrincipal[] = [
      { ...base, findings: ['Full admin rights over every organization'] },
      { ...base, id: '2', kind: 'apikey', findings: ['API key never expires'] },
      { ...base, id: '3', disabled: true, findings: ['MFA not set up'] },
    ];
    expect(reviewSummary(rows)).toEqual({ users: 2, apiKeys: 1, withFindings: 2, fullAdmins: 1 });
  });
});

describe('security score display', () => {
  it('colours scores by band and filters low scores', () => {
    expect(scoreTone(null)).toBe('idle');
    expect(scoreTone(90)).toBe('ok');
    expect(scoreTone(75)).toBe('ok');
    expect(scoreTone(74)).toBe('warn');
    expect(scoreTone(59)).toBe('danger');
    const row = { score: 40 } as PostureRow;
    expect(matchesPostureFilter(row, 'low-score')).toBe(true);
    expect(matchesPostureFilter({ ...row, score: 60 }, 'low-score')).toBe(false);
    expect(matchesPostureFilter({ ...row, score: null }, 'low-score')).toBe(false);
  });
});
