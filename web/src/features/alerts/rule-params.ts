import type { Tone } from '@/components/status';
import type { ChannelInput, ChannelType } from '@/lib/api/alerts';

/**
 * What each alert type means and which settings it takes. The types and their parameters are defined by the server
 * (`AlertEngine.cs`); a type this file does not know is still shown, with its id as the label and no settings.
 */
export interface RuleParamField {
  /** Key in the rule's `params` object. */
  key: string;
  label: string;
  hint: string;
  unit: string;
  min: number;
  max: number;
  /** What the server uses when the value is missing. */
  fallback: number;
  integer: boolean;
}

interface AlertTypeInfo {
  label: string;
  description: string;
  fields: RuleParamField[];
}

const TYPES: Record<string, AlertTypeInfo> = {
  'device.offline': {
    label: 'Device offline',
    description: 'Opens when a device has had no contact for the time below. Closes by itself when it reconnects.',
    fields: [
      {
        key: 'minutes',
        label: 'Offline for',
        hint: 'From 1 minute to 30 days (43200 minutes).',
        unit: 'minutes',
        min: 1,
        max: 43200,
        fallback: 30,
        integer: true,
      },
    ],
  },
  'disk.usage': {
    label: 'Disk filling up',
    description: 'Opens for each disk that is at least this full. Closes by itself when space is freed.',
    fields: [
      {
        key: 'percent',
        label: 'Used space at or above',
        hint: 'From 1 to 100.',
        unit: 'percent',
        min: 1,
        max: 100,
        fallback: 90,
        integer: false,
      },
    ],
  },
  'antivirus.off': {
    label: 'Antivirus off or out of date',
    description: 'Opens when a device reports no enabled, up-to-date antivirus product.',
    fields: [],
  },
  'firewall.off': { label: 'Firewall off', description: 'Opens when the host firewall reports disabled.', fields: [] },
  'encryption.off': {
    label: 'Disk encryption off',
    description: 'Opens when at least one volume is not encrypted.',
    fields: [],
  },
  'patch.failed': {
    label: 'Update failed to install',
    description: 'Opens when an update fails to install.',
    fields: [],
  },
  'localadmin.new': {
    label: 'New local administrator',
    description: 'Opens when an account becomes a local administrator. A person has to resolve it.',
    fields: [],
  },
  'agent.tamper': {
    label: 'Agent tampering or uninstall',
    description: 'Opens when the agent reports tampering or a rolled-back update. A person has to resolve it.',
    fields: [],
  },
  'compliance.drift': {
    label: 'Compliance drift',
    description: 'Opens when a device fails a policy check. Closes by itself when it complies again.',
    fields: [],
  },
  'vulnerability.known_exploited': {
    label: 'Known exploited vulnerability',
    description: 'Opens when installed software matches a vulnerability that is known to be exploited.',
    fields: [],
  },
};

export function alertTypeLabel(type: string): string {
  return TYPES[type]?.label ?? type;
}

export function alertTypeDescription(type: string): string {
  return TYPES[type]?.description ?? '';
}

export function ruleParamFields(type: string): RuleParamField[] {
  return TYPES[type]?.fields ?? [];
}

/** Text-box values for a rule's stored params (or the server defaults for a new rule). */
export function paramsToForm(type: string, params: Record<string, unknown> | null | undefined): Record<string, string> {
  const form: Record<string, string> = {};
  for (const field of ruleParamFields(type)) {
    const value = params?.[field.key];
    form[field.key] = typeof value === 'number' && Number.isFinite(value) ? String(value) : String(field.fallback);
  }
  return form;
}

export type ParsedParams = { ok: true; params: Record<string, number> } | { ok: false; errors: Record<string, string> };

/**
 * Validates the per-type settings and builds the `params` object. The server clamps out-of-range numbers silently,
 * so the form refuses them instead: what is saved is what the person typed.
 */
export function parseRuleParams(type: string, form: Record<string, string>): ParsedParams {
  const params: Record<string, number> = {};
  const errors: Record<string, string> = {};
  for (const field of ruleParamFields(type)) {
    const raw = (form[field.key] ?? '').trim();
    const valid = field.integer ? /^\d+$/.test(raw) : /^\d+(\.\d+)?$/.test(raw);
    const value = Number(raw);
    if (!valid || !Number.isFinite(value) || value < field.min || value > field.max) {
      errors[field.key] = `Enter a ${field.integer ? 'whole number' : 'number'} from ${field.min} to ${field.max}.`;
    } else {
      params[field.key] = value;
    }
  }
  return Object.keys(errors).length > 0 ? { ok: false, errors } : { ok: true, params };
}

/** One line for the rules table: "Offline for 30 minutes", "Used space at or above 90 percent". */
export function describeRuleParams(type: string, params: Record<string, unknown> | null | undefined): string {
  return ruleParamFields(type)
    .map((f) => {
      const value = params?.[f.key];
      return `${f.label} ${typeof value === 'number' ? value : f.fallback} ${f.unit}`;
    })
    .join(', ');
}

export const SEVERITY: Record<string, { label: string; tone: Tone }> = {
  critical: { label: 'Critical', tone: 'danger' },
  warning: { label: 'Warning', tone: 'warn' },
  info: { label: 'Info', tone: 'info' },
};

export function severityLook(severity: string): { label: string; tone: Tone } {
  return SEVERITY[severity] ?? { label: severity, tone: 'idle' };
}

// ----- Notification channels -----

export const CHANNEL_LABEL: Record<string, string> = {
  email: 'Email',
  webhook: 'Webhook',
  teams: 'Microsoft Teams',
  slack: 'Slack',
};

export const WEBHOOK_EVENT_LABEL: Record<string, string> = {
  'alert.opened': 'An alert opens',
  'device.enrolled': 'A device enrolls',
  'device.offline': 'A device goes offline',
  'job.finished': 'A job finishes',
  'session.started': 'A remote session starts',
  'session.ended': 'A remote session ends',
  'audit.integrity_failed': 'The audit log fails its integrity check',
  test: 'Test notifications',
};

/** Splits a recipients box (commas, semicolons, spaces or new lines) into addresses, without duplicates. */
export function parseRecipients(text: string): string[] {
  return [
    ...new Set(
      text
        .split(/[\s,;]+/)
        .map((t) => t.trim())
        .filter(Boolean),
    ),
  ];
}

export interface ChannelForm {
  type: ChannelType;
  name: string;
  recipients: string;
  url: string;
  secret: string;
  eventTypes: string[];
}

export type ChannelValidation =
  | { ok: true; input: ChannelInput }
  | { ok: false; errors: Partial<Record<'name' | 'recipients' | 'url' | 'secret', string>> };

/**
 * Checks a channel form and builds the request. When editing, an empty URL or secret means "keep the stored one":
 * the server never sends them back, so they cannot be shown, and they are left out of the request.
 */
export function validateChannel(form: ChannelForm, editing: boolean): ChannelValidation {
  const errors: Partial<Record<'name' | 'recipients' | 'url' | 'secret', string>> = {};
  const name = form.name.trim();
  if (name.length === 0 || name.length > 120) {
    errors.name = 'Enter a name of up to 120 characters.';
  }
  const input: ChannelInput = { name };
  if (form.type === 'email') {
    const to = parseRecipients(form.recipients);
    if (to.length === 0 || to.length > 20) {
      errors.recipients = 'Enter 1 to 20 email addresses.';
    } else if (to.some((t) => !/^[^\s@,]+@[^\s@,]+$/.test(t) || t.length > 254)) {
      errors.recipients = 'One of these is not an email address.';
    } else {
      input.to = to;
    }
  } else {
    const url = form.url.trim();
    if (url === '') {
      if (!editing) {
        errors.url = 'Enter the URL to send to.';
      }
    } else {
      let parsed: URL | null = null;
      try {
        parsed = new URL(url);
      } catch {
        parsed = null;
      }
      if (!parsed || (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')) {
        errors.url = 'Enter a full URL starting with https://.';
      } else {
        input.url = url;
      }
    }
    if (form.type === 'webhook') {
      if (form.secret.length > 256) {
        errors.secret = 'Use at most 256 characters.';
      } else if (form.secret !== '') {
        input.secret = form.secret;
      }
      input.eventTypes = form.eventTypes;
    }
  }
  return Object.keys(errors).length > 0 ? { ok: false, errors } : { ok: true, input };
}
