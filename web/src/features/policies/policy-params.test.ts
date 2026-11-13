import { describe, expect, it } from 'vitest';
import { buildFirewallRules, describeRule, EMPTY_RULE, rulesToForm, type FirewallRuleForm } from './firewall-rules';
import {
  availableOs,
  buildPolicyParams,
  formatInterval,
  policyToForm,
  validatePolicy,
  type PolicyForm,
} from './policy-params';

const CHECKS = {
  'firewall.enabled': ['windows', 'macos', 'linux'],
  'screenlock.timeout': ['windows', 'macos', 'linux'],
  'localadmins.allowed': ['windows', 'macos', 'linux'],
  'usb.storage.blocked': ['windows'],
  'password.policy': ['windows'],
  'diskencryption.enabled': ['windows', 'macos', 'linux'],
  script: ['windows', 'macos', 'linux'],
};

const form = (patch: Partial<PolicyForm>): PolicyForm => ({
  ...policyToForm(null, { check: 'firewall.enabled', organizationId: '' }),
  name: 'Baseline',
  ...patch,
});

describe('policy params', () => {
  it('validates the screen lock limit like the server (30..86400)', () => {
    expect(buildPolicyParams(form({ check: 'screenlock.timeout', maxSeconds: '600' }))).toEqual({
      ok: true,
      params: { maxSeconds: 600 },
    });
    expect(buildPolicyParams(form({ check: 'screenlock.timeout', maxSeconds: '29' })).ok).toBe(false);
    expect(buildPolicyParams(form({ check: 'screenlock.timeout', maxSeconds: '86401' })).ok).toBe(false);
  });

  it('parses allowed administrators one per line, at most 100', () => {
    expect(buildPolicyParams(form({ check: 'localadmins.allowed', allowed: ' admin\n\nit-support\nadmin ' }))).toEqual({
      ok: true,
      params: { allowed: ['admin', 'it-support'] },
    });
    const many = Array.from({ length: 101 }, (_, i) => `u${i}`).join('\n');
    expect(buildPolicyParams(form({ check: 'localadmins.allowed', allowed: many })).ok).toBe(false);
  });

  it('checks password policy ranges', () => {
    expect(
      buildPolicyParams(form({ check: 'password.policy', minLength: '14', maxAgeDays: '90', complexity: true })),
    ).toEqual({
      ok: true,
      params: { minLength: 14, maxAgeDays: 90, complexity: true },
    });
    expect(buildPolicyParams(form({ check: 'password.policy', minLength: '129' })).ok).toBe(false);
    expect(buildPolicyParams(form({ check: 'password.policy', maxAgeDays: '1000' })).ok).toBe(false);
  });

  it('requires a check script, and a remediation script when fixing is on', () => {
    expect(buildPolicyParams(form({ check: 'script', language: 'bash', checkScript: '' })).ok).toBe(false);
    expect(buildPolicyParams(form({ check: 'script', language: 'bash', checkScript: 'exit 0' }))).toEqual({
      ok: true,
      params: { language: 'bash', checkScript: 'exit 0', remediationScript: null },
    });
    const v = validatePolicy(
      form({ check: 'script', language: 'bash', checkScript: 'exit 0', remediate: true }),
      CHECKS,
      true,
    );
    expect(v.ok).toBe(false);
    if (!v.ok) {
      expect(v.errors.remediationScript).toMatch(/remediation script/);
    }
  });

  it('limits operating systems to the check and the script language', () => {
    expect(availableOs({ check: 'usb.storage.blocked', language: 'bash' }, CHECKS)).toEqual(['windows']);
    expect(availableOs({ check: 'script', language: 'powershell' }, CHECKS)).toEqual(['windows']);
    expect(availableOs({ check: 'script', language: 'python' }, CHECKS)).toEqual(['windows', 'macos', 'linux']);
    const v = validatePolicy(form({ check: 'usb.storage.blocked', osTargets: ['linux'] }), CHECKS, true);
    expect(v.ok).toBe(false);
  });

  it('pins a script policy to its language’s systems when “every OS” is chosen', () => {
    const v = validatePolicy(form({ check: 'script', language: 'bash', checkScript: 'true' }), CHECKS, true);
    expect(v.ok && v.input.osTargets).toEqual(['macos', 'linux']);
  });

  it('never asks to remediate a report-only check, and sends create-only fields only on create', () => {
    const create = validatePolicy(
      form({ check: 'diskencryption.enabled', remediate: true, organizationId: 'org-1' }),
      CHECKS,
      true,
    );
    expect(create.ok && create.input).toMatchObject({
      remediate: false,
      check: 'diskencryption.enabled',
      organizationId: 'org-1',
    });
    const edit = validatePolicy(form({}), CHECKS, false);
    expect(edit.ok && 'check' in edit.input).toBe(false);
  });

  it('validates name and interval', () => {
    expect(validatePolicy(form({ name: ' ' }), CHECKS, true).ok).toBe(false);
    expect(validatePolicy(form({ intervalMinutes: '14' }), CHECKS, true).ok).toBe(false);
    expect(validatePolicy(form({ intervalMinutes: '10081' }), CHECKS, true).ok).toBe(false);
    expect(formatInterval(60)).toBe('Hourly');
    expect(formatInterval(1440 * 2)).toBe('Every 2 days');
    expect(formatInterval(45)).toBe('Every 45 minutes');
  });
});

describe('firewall.rules', () => {
  const rule = { ...EMPTY_RULE, name: 'Block SMB', ports: '445, 139', remoteAddresses: '10.0.0.0/8\nfd00::/8' };

  it('builds the rules parameter', () => {
    const built = buildFirewallRules([rule]);
    expect(built).toEqual({
      ok: true,
      rules: [
        {
          name: 'Block SMB',
          direction: 'in',
          action: 'block',
          protocol: 'tcp',
          ports: ['445', '139'],
          remoteAddresses: ['10.0.0.0/8', 'fd00::/8'],
        },
      ],
    });
    expect(rulesToForm(built.ok ? built.rules : [])[0]?.ports).toBe('445, 139');
  });

  it('refuses what the server refuses', () => {
    const bad = (patch: Partial<FirewallRuleForm>) => buildFirewallRules([{ ...rule, ...patch }]).ok;
    expect(buildFirewallRules([]).ok).toBe(false);
    expect(bad({ name: '' })).toBe(false);
    expect(bad({ name: 'x"; rm' })).toBe(false);
    expect(bad({ protocol: 'any' })).toBe(false); // ports need TCP or UDP
    expect(bad({ ports: '90-80' })).toBe(false);
    expect(bad({ ports: '70000' })).toBe(false);
    expect(bad({ remoteAddresses: '10.0.0.0/33' })).toBe(false);
    expect(bad({ remoteAddresses: '300.1.1.1' })).toBe(false);
    expect(bad({ program: 'app.exe' })).toBe(false);
    expect(bad({ direction: 'out', protocol: 'any', ports: '', remoteAddresses: '' })).toBe(false);
    expect(bad({ direction: 'out', protocol: 'any', ports: '', remoteAddresses: '', program: 'C:\\Apps\\t.exe' })).toBe(
      true,
    );
  });

  it('describes rules in words', () => {
    expect(
      describeRule({
        name: 'x',
        direction: 'in',
        action: 'block',
        protocol: 'tcp',
        ports: ['445'],
        remoteAddresses: ['10.0.0.0/8'],
      }),
    ).toBe('Block incoming TCP 445 from 10.0.0.0/8');
    expect(describeRule({ name: 'x', direction: 'out', action: 'allow', protocol: 'any' })).toBe(
      'Allow outgoing all traffic',
    );
  });

  it('validates the whole policy form', () => {
    const form = {
      ...policyToForm(null, { check: 'firewall.rules', organizationId: '' }),
      name: 'Fw',
      firewallRules: [rule],
    };
    expect(validatePolicy(form, { 'firewall.rules': ['windows', 'macos', 'linux'] }, true).ok).toBe(true);
    expect(validatePolicy({ ...form, firewallRules: [] }, { 'firewall.rules': ['windows'] }, true)).toMatchObject({
      ok: false,
      errors: { firewallRules: 'Add at least one rule.' },
    });
  });
});
