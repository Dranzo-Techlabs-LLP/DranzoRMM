import { describe, expect, it } from 'vitest';
import { describePolicy, policyDraft, toPolicyInput, validatePolicy } from '@/features/patches/patch-model';
import {
  detectionProblems,
  EMPTY_DETECTION,
  EMPTY_PACKAGE_IDS,
  managedOs,
  managerForSource,
  packageIdProblem,
  packageTypeFromFileName,
  toDetectionRule,
  uninstallProgramProblem,
  validatePackageIds,
} from './software-model';

describe('package id validation (server regex ^[A-Za-z0-9][A-Za-z0-9+._:@/-]{0,199}$)', () => {
  it('accepts real package ids', () => {
    for (const id of [
      '7zip.7zip',
      'Mozilla.Firefox',
      'firefox',
      'p7zip-full',
      'homebrew/cask/firefox',
      'gcc-c++',
      'pkg@1.2:3',
    ]) {
      expect(packageIdProblem(id), id).toBeNull();
    }
  });

  it('rejects anything a shell or the agent would treat specially', () => {
    expect(packageIdProblem('-rf')).toMatch(/Start with/);
    expect(packageIdProblem('foo bar')).toMatch(/no spaces/);
    expect(packageIdProblem('foo;rm')).toMatch(/no spaces/);
    expect(packageIdProblem('$(id)')).toMatch(/Start with/);
    expect(packageIdProblem('a'.repeat(201))).toMatch(/200/);
    expect(packageIdProblem('a'.repeat(200))).toBeNull();
  });

  it('builds the packages map and needs at least one id', () => {
    expect(validatePackageIds(EMPTY_PACKAGE_IDS).form).toMatch(/at least one/);
    const v = validatePackageIds({ winget: ' 7zip.7zip ', brew: '', apt: 'p7zip-full', dnf: 'bad id' });
    expect(v.packages).toEqual({ winget: '7zip.7zip', apt: 'p7zip-full' });
    expect(v.errors).toEqual({ dnf: expect.stringMatching(/no spaces/) });
    expect(managedOs(v.packages)).toEqual(['windows', 'linux']);
  });

  it('maps inventory sources to the manager that can remove them', () => {
    expect(managerForSource('winget')).toBe('winget');
    expect(managerForSource('dpkg')).toBe('apt');
    expect(managerForSource('rpm')).toBe('dnf');
    expect(managerForSource('registry')).toBeNull();
  });
});

describe('custom packages', () => {
  it('infers the type from the extension', () => {
    expect(packageTypeFromFileName('Setup.MSI')).toBe('msi');
    expect(packageTypeFromFileName('tool_1.0_amd64.deb')).toBe('deb');
    expect(packageTypeFromFileName('archive.tar.gz')).toBeNull();
    expect(packageTypeFromFileName('noext')).toBeNull();
  });

  it('checks detection rules the way the agent does', () => {
    const rule = (patch: Partial<typeof EMPTY_DETECTION>) =>
      detectionProblems({ ...EMPTY_DETECTION, enabled: true, ...patch });
    expect(rule({ type: 'file', key: 'relative/path' }).key).toMatch(/full path/);
    expect(rule({ type: 'file', key: 'C:\\Program Files\\Acme\\a.exe' })).toEqual({});
    expect(rule({ type: 'registry', key: 'HKCU\\Software\\Acme' }).key).toMatch(/HKLM/);
    expect(rule({ type: 'registry', key: 'HKLM\\SOFTWARE\\Acme' })).toEqual({});
    expect(rule({ type: 'dpkg', key: 'acme vpn' }).key).toMatch(/no spaces/);
    expect(rule({ type: 'app', key: 'Firefox' })).toEqual({});
    expect(rule({ type: 'app', key: '/Applications/Firefox' }).key).toMatch(/\.app/);
    expect(rule({ type: 'file', key: '/opt/a', minVersion: '1 2' }).minVersion).toBeTruthy();
    expect(detectionProblems(EMPTY_DETECTION)).toEqual({});
    expect(
      toDetectionRule({
        ...EMPTY_DETECTION,
        enabled: true,
        type: 'registry',
        key: ' HKLM\\A ',
        valueName: 'V',
        minVersion: '',
      }),
    ).toEqual({
      type: 'registry',
      key: 'HKLM\\A',
      valueName: 'V',
      minVersion: undefined,
    });
  });

  it('accepts only full paths or known tools as the uninstall program', () => {
    expect(uninstallProgramProblem([], 'linux')).toBeNull();
    expect(uninstallProgramProblem(['apt-get', 'remove', '-y', 'acme'], 'linux')).toBeNull();
    expect(uninstallProgramProblem(['/usr/local/bin/acme-uninstall'], 'macos')).toBeNull();
    expect(uninstallProgramProblem(['C:\\Acme\\uninstall.exe'], 'windows')).toBeNull();
    expect(uninstallProgramProblem(['bash', '-c', 'x'], 'linux')).toMatch(/full path/);
    expect(uninstallProgramProblem(['', 'x'], 'linux')).toMatch(/first row/);
  });
});

describe('patch policies', () => {
  const ok = () => true;

  it('validates ranges the server would otherwise clamp silently', () => {
    const d = policyDraft(null, 'o1');
    expect(validatePolicy({ ...d, name: 'Nightly' }, ok)).toEqual({});
    const bad = validatePolicy(
      { ...d, name: '', deferDays: '91', rebootDeferrals: 'x', windowEnabled: true, windowMinutes: '10' },
      ok,
    );
    expect(Object.keys(bad).sort()).toEqual(['deferDays', 'name', 'rebootDeferrals', 'windowMinutes']);
  });

  it('clears the window with an empty cron and sets organizationId only on create', () => {
    const d = { ...policyDraft(null, 'o1'), name: 'P', windowEnabled: false };
    expect(toPolicyInput(d, true)).toMatchObject({ organizationId: 'o1', windowCron: '', windowMinutes: undefined });
    expect(toPolicyInput(d, false)).not.toHaveProperty('organizationId');
    expect(toPolicyInput({ ...d, organizationId: '' }, true).organizationId).toBeNull();
  });

  it('explains a policy in plain language', () => {
    expect(
      describePolicy({
        autoApproveSeverities: ['critical'],
        autoApproveCategories: [],
        sources: ['wua'],
        deferDays: 3,
      }),
    ).toBe('Auto-approves critical updates from Windows Update; installs only after 3 days.');
    expect(describePolicy({ autoApproveSeverities: [], autoApproveCategories: [], sources: [], deferDays: 0 })).toBe(
      'Approves nothing automatically.',
    );
  });
});
