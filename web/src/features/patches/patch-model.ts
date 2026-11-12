import type { Tone } from '@/components/status';
import type { PatchPolicy, PatchPolicyInput } from '@/lib/api/patches';

export const SOURCE_LABELS: Record<string, string> = {
  wua: 'Windows Update',
  softwareupdate: 'macOS Software Update',
  apt: 'apt (Debian, Ubuntu)',
  dnf: 'dnf (Fedora, RHEL)',
  winget: 'winget (Windows apps)',
  brew: 'Homebrew (macOS apps)',
};

export function patchSourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? source;
}

export const SEVERITY: Record<string, { label: string; tone: Tone }> = {
  critical: { label: 'Critical', tone: 'danger' },
  important: { label: 'Important', tone: 'warn' },
  moderate: { label: 'Moderate', tone: 'info' },
  low: { label: 'Low', tone: 'idle' },
  unspecified: { label: 'Unrated', tone: 'idle' },
};

export function severity(value: string) {
  return SEVERITY[value] ?? { label: value, tone: 'idle' as Tone };
}

export const PATCH_STATUS: Record<string, { label: string; tone: Tone; explain: string }> = {
  pending: { label: 'Needs decision', tone: 'warn', explain: 'Offered by the device and not approved yet.' },
  approved: { label: 'Approved', tone: 'info', explain: 'Installs with the next install or maintenance window.' },
  rejected: { label: 'Rejected', tone: 'idle', explain: 'Will not be installed.' },
  deferred: { label: 'Deferred', tone: 'idle', explain: 'Postponed; decide again later.' },
  installed: { label: 'Installed', tone: 'ok', explain: 'No longer offered by the device.' },
  failed: { label: 'Failed', tone: 'danger', explain: 'The last install attempt failed.' },
};

export function patchStatus(value: string) {
  return PATCH_STATUS[value] ?? { label: value, tone: 'idle' as Tone, explain: '' };
}

export const COMPLIANCE: Record<string, { label: string; tone: Tone }> = {
  patched: { label: 'Patched', tone: 'ok' },
  unpatched: { label: 'Missing updates', tone: 'warn' },
  unknown: { label: 'Not scanned', tone: 'idle' },
};

export const REBOOT_MODE_TEXT: Record<string, { label: string; explain: string }> = {
  never: { label: 'Never restart', explain: 'Updates that need a restart finish when the user restarts.' },
  if_required: {
    label: 'Restart if an update needs it',
    explain: 'Only when an installed update requires it.',
  },
  force: { label: 'Always restart', explain: 'Restart after installing, even if no update asks for it.' },
};

export interface PolicyDraft {
  name: string;
  organizationId: string;
  enabled: boolean;
  autoApproveSeverities: string[];
  autoApproveCategories: string[];
  sources: string[];
  deferDays: string;
  windowEnabled: boolean;
  windowCron: string;
  windowMinutes: string;
  rebootMode: string;
  rebootNotifyUser: boolean;
  rebootDeferrals: string;
  rebootDeadlineMinutes: string;
}

export function policyDraft(policy: PatchPolicy | null, organizationId: string): PolicyDraft {
  return {
    name: policy?.name ?? '',
    organizationId: policy ? (policy.organizationId ?? '') : organizationId,
    enabled: policy?.enabled ?? true,
    autoApproveSeverities: policy?.autoApproveSeverities ?? ['critical', 'important'],
    autoApproveCategories: policy?.autoApproveCategories ?? [],
    sources: policy?.sources ?? [],
    deferDays: String(policy?.deferDays ?? 0),
    windowEnabled: Boolean(policy?.windowCron),
    windowCron: policy?.windowCron ?? '0 2 * * 6',
    windowMinutes: String(policy?.windowMinutes ?? 120),
    rebootMode: policy?.rebootMode ?? 'if_required',
    rebootNotifyUser: policy?.rebootNotifyUser ?? true,
    rebootDeferrals: String(policy?.rebootDeferrals ?? 3),
    rebootDeadlineMinutes: String(policy?.rebootDeadlineMinutes ?? 240),
  };
}

const LIMITS = {
  deferDays: [0, 90],
  windowMinutes: [15, 24 * 60],
  rebootDeferrals: [0, 20],
  rebootDeadlineMinutes: [0, 7 * 24 * 60],
} as const;

function bounded(text: string, [min, max]: readonly [number, number]): number | null {
  if (!/^\d+$/.test(text.trim())) {
    return null;
  }
  const n = Number.parseInt(text.trim(), 10);
  return n >= min && n <= max ? n : null;
}

export type PolicyErrors = Partial<Record<keyof PolicyDraft, string>>;

/** Client-side check of a policy draft. The server clamps numbers silently, so out-of-range values are caught here. */
export function validatePolicy(d: PolicyDraft, cronOk: (cron: string) => boolean): PolicyErrors {
  const e: PolicyErrors = {};
  if (!d.name.trim() || d.name.trim().length > 120) {
    e.name = 'Enter a name of up to 120 characters.';
  }
  for (const key of Object.keys(LIMITS) as (keyof typeof LIMITS)[]) {
    if (key === 'windowMinutes' && !d.windowEnabled) {
      continue;
    }
    if (bounded(d[key], LIMITS[key]) === null) {
      e[key] = `Enter a whole number from ${LIMITS[key][0]} to ${LIMITS[key][1]}.`;
    }
  }
  if (d.windowEnabled && !cronOk(d.windowCron)) {
    e.windowCron = 'Enter a valid schedule.';
  }
  if (d.autoApproveCategories.length > 32 || d.autoApproveCategories.some((c) => c.length > 64)) {
    e.autoApproveCategories = 'Up to 32 categories of up to 64 characters.';
  }
  return e;
}

/** Request body for create (all fields) and update (all editable fields; organization cannot change). */
export function toPolicyInput(d: PolicyDraft, creating: boolean): PatchPolicyInput {
  const input: PatchPolicyInput = {
    name: d.name.trim(),
    enabled: d.enabled,
    autoApproveSeverities: d.autoApproveSeverities,
    autoApproveCategories: d.autoApproveCategories.map((c) => c.trim()).filter(Boolean),
    sources: d.sources,
    deferDays: Number.parseInt(d.deferDays, 10),
    windowCron: d.windowEnabled ? d.windowCron.trim().split(/\s+/).join(' ') : '',
    windowMinutes: d.windowEnabled ? Number.parseInt(d.windowMinutes, 10) : undefined,
    rebootMode: d.rebootMode,
    rebootNotifyUser: d.rebootNotifyUser,
    rebootDeferrals: Number.parseInt(d.rebootDeferrals, 10),
    rebootDeadlineMinutes: Number.parseInt(d.rebootDeadlineMinutes, 10),
  };
  if (creating) {
    input.organizationId = d.organizationId || null;
  }
  return input;
}

/** "Auto-approves critical and important updates from any source after 3 days." */
export function describePolicy(
  p: Pick<PatchPolicy, 'autoApproveSeverities' | 'autoApproveCategories' | 'sources' | 'deferDays'>,
): string {
  const sev = p.autoApproveSeverities.map((s) => severity(s).label.toLowerCase());
  const parts: string[] = [];
  if (sev.length > 0) {
    parts.push(`${sev.join(', ')} updates`);
  }
  if (p.autoApproveCategories.length > 0) {
    parts.push(`category ${p.autoApproveCategories.join(', ')}`);
  }
  const what = parts.length > 0 ? `Auto-approves ${parts.join(' and ')}` : 'Approves nothing automatically';
  const from = p.sources.length > 0 ? ` from ${p.sources.map(patchSourceLabel).join(', ')}` : ' from any source';
  const wait = p.deferDays > 0 ? `; installs only after ${p.deferDays} ${p.deferDays === 1 ? 'day' : 'days'}` : '';
  return `${what}${parts.length > 0 ? from : ''}${wait}.`;
}

export function formatMinutes(minutes: number): string {
  if (minutes < 60) {
    return `${minutes} min`;
  }
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return m === 0 ? `${h} h` : `${h} h ${m} min`;
}
