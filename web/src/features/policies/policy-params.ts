import type { Id } from '@/lib/api';
import type { Policy, PolicyInput } from '@/lib/api/policies';
import {
  buildFirewallRules,
  FIREWALL_RULES_CHECK,
  rulesToForm,
  type FirewallRule,
  type FirewallRuleForm,
} from './firewall-rules';

/**
 * Policy checks and their settings. The list of checks and the operating systems each exists on come from the
 * server (`GET /policies` → `checks`); this file adds wording, the per-check form and the same validation the server
 * applies (`PolicyChecks.ValidateParams`), so mistakes are caught before the request.
 */
export const SCRIPT_CHECK = 'script';
export const MAX_SCRIPT_CHARS = 512 * 1024;
export const MIN_INTERVAL_MINUTES = 15;
export const MAX_INTERVAL_MINUTES = 7 * 24 * 60;

interface CheckInfo {
  label: string;
  description: string;
  /** What "fix automatically" does for this check, or `null` when the check can only report. */
  remediation: string | null;
}

const CHECKS: Record<string, CheckInfo> = {
  'firewall.enabled': {
    label: 'Firewall is on',
    description: 'The host firewall must be enabled.',
    remediation: 'Turns the host firewall on.',
  },
  'antivirus.enabled': {
    label: 'Antivirus is on',
    description: 'An antivirus product must be enabled.',
    remediation: 'Turns the built-in antivirus on where the operating system allows it.',
  },
  'screenlock.timeout': {
    label: 'Screen locks after inactivity',
    description: 'The screen must lock by itself within the time below.',
    remediation: 'Sets the screen lock time to the limit below.',
  },
  'localadmins.allowed': {
    label: 'Only approved local administrators',
    description: 'Only the accounts listed below may be local administrators.',
    remediation: 'Removes administrator rights from accounts that are not on the list.',
  },
  'usb.storage.blocked': {
    label: 'USB storage is blocked',
    description: 'USB mass-storage devices must be blocked.',
    remediation: 'Blocks USB mass-storage devices.',
  },
  'password.policy': {
    label: 'Local password policy',
    description: 'Local accounts must meet the password rules below.',
    remediation: 'Applies the password rules below to the local policy.',
  },
  'diskencryption.enabled': {
    label: 'Disk encryption is on',
    description: 'Every volume must be encrypted (BitLocker, FileVault or LUKS).',
    remediation: null,
  },
  [FIREWALL_RULES_CHECK]: {
    label: 'Firewall rules',
    description:
      'The firewall rules below must be in place. DranzoRMM manages only its own rules (group or table "DranzoRMM"); other rules are never touched.',
    remediation:
      'Adds, updates or removes the DranzoRMM rules. If the device cannot reach DranzoRMM afterwards, the previous rules are restored.',
  },
  [SCRIPT_CHECK]: {
    label: 'Custom script',
    description: 'Runs your check script; the device complies when the script exits with code 0.',
    remediation: 'Runs your remediation script when the check fails, then checks again.',
  },
};

export function checkLabel(check: string | null | undefined): string {
  return check ? (CHECKS[check]?.label ?? check) : 'Unknown check';
}

export function checkDescription(check: string): string {
  return CHECKS[check]?.description ?? '';
}

export function checkRemediation(check: string): string | null {
  return CHECKS[check] ? CHECKS[check].remediation : 'Applies the fix defined for this check.';
}

/** Script languages and where each runs (server `ScriptEndpoints.LanguageOs`). */
export const SCRIPT_LANGUAGES: Record<string, { label: string; os: string[] }> = {
  powershell: { label: 'PowerShell', os: ['windows'] },
  cmd: { label: 'Command Prompt (cmd)', os: ['windows'] },
  bash: { label: 'Bash', os: ['macos', 'linux'] },
  zsh: { label: 'Zsh', os: ['macos', 'linux'] },
  sh: { label: 'sh', os: ['macos', 'linux'] },
  python: { label: 'Python', os: ['windows', 'macos', 'linux'] },
};

export interface PolicyForm {
  name: string;
  description: string;
  check: string;
  /** Empty = every operating system the check (and script language) exists on. */
  osTargets: string[];
  remediate: boolean;
  enabled: boolean;
  intervalMinutes: string;
  /** Empty string = shared with all organizations. */
  organizationId: Id;
  maxSeconds: string;
  /** One account name per line. */
  allowed: string;
  minLength: string;
  maxAgeDays: string;
  complexity: boolean;
  language: string;
  checkScript: string;
  remediationScript: string;
  firewallRules: FirewallRuleForm[];
}

function text(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : fallback;
}

export function policyToForm(policy: Policy | null, defaults: { check: string; organizationId: Id }): PolicyForm {
  const p = policy?.params ?? {};
  return {
    name: policy?.name ?? '',
    description: policy?.description ?? '',
    check: policy?.check ?? defaults.check,
    osTargets: policy?.osTargets ?? [],
    remediate: policy?.remediate ?? false,
    enabled: policy?.enabled ?? true,
    intervalMinutes: String(policy?.intervalMinutes ?? 60),
    organizationId: policy ? (policy.organizationId ?? '') : defaults.organizationId,
    maxSeconds: text(p.maxSeconds, '900'),
    allowed: Array.isArray(p.allowed) ? p.allowed.filter((a): a is string => typeof a === 'string').join('\n') : '',
    minLength: text(p.minLength, '12'),
    maxAgeDays: text(p.maxAgeDays, '0'),
    complexity: p.complexity === true,
    language: text(p.language, 'bash'),
    checkScript: text(p.checkScript),
    remediationScript: text(p.remediationScript),
    firewallRules: rulesToForm(p.rules),
  };
}

/** Operating systems a policy with this form can target: the check's, narrowed by the script language. */
export function availableOs(form: Pick<PolicyForm, 'check' | 'language'>, checks: Record<string, string[]>): string[] {
  const os = checks[form.check] ?? [];
  if (form.check !== SCRIPT_CHECK) {
    return os;
  }
  const languageOs = SCRIPT_LANGUAGES[form.language]?.os ?? [];
  return os.filter((o) => languageOs.includes(o));
}

function wholeNumber(raw: string, min: number, max: number): number | null {
  const t = raw.trim();
  if (!/^\d+$/.test(t)) {
    return null;
  }
  const n = Number(t);
  return n >= min && n <= max ? n : null;
}

/** Account names from the "allowed administrators" box: one per line, trimmed, without duplicates. */
export function parseAccountList(textValue: string): string[] {
  return [
    ...new Set(
      textValue
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean),
    ),
  ];
}

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/;

export type ParamErrors = Partial<
  Record<
    | 'maxSeconds'
    | 'allowed'
    | 'minLength'
    | 'maxAgeDays'
    | 'language'
    | 'checkScript'
    | 'remediationScript'
    | 'firewallRules',
    string
  >
>;

/** The `params` object for a check, or the problems with what was entered. */
export function buildPolicyParams(
  form: PolicyForm,
): { ok: true; params: Record<string, unknown> } | { ok: false; errors: ParamErrors } {
  const errors: ParamErrors = {};
  let params: Record<string, unknown> = {};
  switch (form.check) {
    case 'screenlock.timeout': {
      const seconds = wholeNumber(form.maxSeconds, 30, 86400);
      if (seconds === null) {
        errors.maxSeconds = 'Enter a whole number of seconds from 30 to 86400 (24 hours).';
      }
      params = { maxSeconds: seconds };
      break;
    }
    case 'localadmins.allowed': {
      const allowed = parseAccountList(form.allowed);
      if (allowed.length > 100) {
        errors.allowed = 'List at most 100 accounts.';
      } else if (allowed.some((a) => a.length > 128 || CONTROL_CHARS.test(a))) {
        errors.allowed = 'Each account name can be up to 128 characters, one per line.';
      }
      params = { allowed };
      break;
    }
    case 'password.policy': {
      const minLength = wholeNumber(form.minLength, 0, 128);
      const maxAgeDays = wholeNumber(form.maxAgeDays, 0, 999);
      if (minLength === null) {
        errors.minLength = 'Enter a whole number from 0 to 128.';
      }
      if (maxAgeDays === null) {
        errors.maxAgeDays = 'Enter a whole number of days from 0 to 999. 0 means passwords do not expire.';
      }
      params = { minLength, maxAgeDays, complexity: form.complexity };
      break;
    }
    case FIREWALL_RULES_CHECK: {
      const built = buildFirewallRules(form.firewallRules);
      if (built.ok) {
        params = { rules: built.rules };
      } else {
        errors.firewallRules = built.error;
      }
      break;
    }
    case SCRIPT_CHECK: {
      if (!SCRIPT_LANGUAGES[form.language]) {
        errors.language = 'Choose a language.';
      }
      if (form.checkScript.trim() === '') {
        errors.checkScript = 'Enter the check script.';
      } else if (form.checkScript.length > MAX_SCRIPT_CHARS) {
        errors.checkScript = 'The script is too long (the limit is 512 KB).';
      }
      if (form.remediationScript.length > MAX_SCRIPT_CHARS) {
        errors.remediationScript = 'The script is too long (the limit is 512 KB).';
      }
      params = {
        language: form.language,
        checkScript: form.checkScript,
        remediationScript: form.remediationScript.trim() === '' ? null : form.remediationScript,
      };
      break;
    }
    default:
      params = {};
  }
  return Object.keys(errors).length > 0 ? { ok: false, errors } : { ok: true, params };
}

export type PolicyErrors = ParamErrors &
  Partial<Record<'name' | 'description' | 'check' | 'intervalMinutes' | 'osTargets' | 'remediate', string>>;

export type PolicyValidation = { ok: true; input: PolicyInput } | { ok: false; errors: PolicyErrors };

/**
 * Validates the whole form and builds the request body. `creating` adds the two fields the server reads only on
 * create (`check`, `organizationId`).
 */
export function validatePolicy(
  form: PolicyForm,
  checks: Record<string, string[]>,
  creating: boolean,
): PolicyValidation {
  const errors: PolicyErrors = {};
  const name = form.name.trim();
  if (name.length === 0 || name.length > 120) {
    errors.name = 'Enter a name of up to 120 characters.';
  }
  if (form.description.trim().length > 1000) {
    errors.description = 'Use at most 1000 characters.';
  }
  if (!(form.check in checks)) {
    errors.check = 'Choose a check.';
  }
  const interval = wholeNumber(form.intervalMinutes, MIN_INTERVAL_MINUTES, MAX_INTERVAL_MINUTES);
  if (interval === null) {
    errors.intervalMinutes = `Enter a whole number of minutes from ${MIN_INTERVAL_MINUTES} to ${MAX_INTERVAL_MINUTES} (7 days).`;
  }
  const os = availableOs(form, checks);
  if (form.osTargets.some((o) => !os.includes(o))) {
    errors.osTargets = 'One of the selected operating systems is not available for this check.';
  }
  const remediate = form.remediate && checkRemediation(form.check) !== null;
  if (remediate && form.check === SCRIPT_CHECK && form.remediationScript.trim() === '') {
    errors.remediationScript = 'Enter a remediation script, or turn automatic fixing off.';
  }
  const built = buildPolicyParams(form);
  if (!built.ok) {
    // A problem found above (the missing remediation script) is the more specific message; keep it.
    Object.assign(errors, { ...built.errors, ...errors });
  }
  if (Object.keys(errors).length > 0 || !built.ok || interval === null) {
    return { ok: false, errors };
  }
  // A script policy that targets "every OS" must still stay inside its language's operating systems.
  const osTargets = form.osTargets.length > 0 ? form.osTargets : form.check === SCRIPT_CHECK ? os : [];
  return {
    ok: true,
    input: {
      name,
      description: form.description.trim(),
      params: built.params,
      osTargets,
      remediate,
      enabled: form.enabled,
      intervalMinutes: interval,
      ...(creating
        ? { check: form.check, organizationId: form.organizationId === '' ? null : form.organizationId }
        : {}),
    },
  };
}

/** One line describing a policy's settings for the list. */
export function describePolicyParams(check: string, params: Record<string, unknown>): string {
  switch (check) {
    case 'screenlock.timeout':
      return typeof params.maxSeconds === 'number' ? `Within ${params.maxSeconds} seconds` : '';
    case 'localadmins.allowed': {
      const allowed = Array.isArray(params.allowed) ? params.allowed.filter((a) => typeof a === 'string') : [];
      return allowed.length === 0 ? 'No account is allowed' : `Allowed: ${allowed.join(', ')}`;
    }
    case 'password.policy':
      return [
        typeof params.minLength === 'number' ? `at least ${params.minLength} characters` : null,
        typeof params.maxAgeDays === 'number' && params.maxAgeDays > 0
          ? `changed every ${params.maxAgeDays} days`
          : null,
        params.complexity === true ? 'complexity required' : null,
      ]
        .filter(Boolean)
        .join(', ');
    case FIREWALL_RULES_CHECK: {
      const rules = Array.isArray(params.rules) ? (params.rules as FirewallRule[]) : [];
      return `${String(rules.length)} ${rules.length === 1 ? 'rule' : 'rules'}: ${rules.map((r) => r.name).join(', ')}`;
    }
    case SCRIPT_CHECK:
      return typeof params.language === 'string' ? (SCRIPT_LANGUAGES[params.language]?.label ?? params.language) : '';
    default:
      return '';
  }
}

export function formatInterval(minutes: number): string {
  if (minutes % 1440 === 0) {
    const d = minutes / 1440;
    return d === 1 ? 'Daily' : `Every ${d} days`;
  }
  if (minutes % 60 === 0) {
    const h = minutes / 60;
    return h === 1 ? 'Hourly' : `Every ${h} hours`;
  }
  return `Every ${minutes} minutes`;
}
