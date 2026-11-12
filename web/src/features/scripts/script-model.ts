import type { ScriptLanguage, ScriptParameter, ScriptParameterType } from '@/lib/api/scripts';

/** Mirrors `ScriptEndpoints.LanguageOs`: which operating systems each language can target. */
export const LANGUAGE_OS: Record<ScriptLanguage, readonly string[]> = {
  powershell: ['windows'],
  cmd: ['windows'],
  bash: ['macos', 'linux'],
  zsh: ['macos', 'linux'],
  sh: ['macos', 'linux'],
  python: ['windows', 'macos', 'linux'],
};

export const LANGUAGES: readonly { id: ScriptLanguage; label: string }[] = [
  { id: 'powershell', label: 'PowerShell' },
  { id: 'cmd', label: 'Command Prompt (cmd)' },
  { id: 'bash', label: 'Bash' },
  { id: 'zsh', label: 'Zsh' },
  { id: 'sh', label: 'POSIX shell (sh)' },
  { id: 'python', label: 'Python' },
];

export const PARAMETER_TYPES: readonly { id: ScriptParameterType; label: string }[] = [
  { id: 'string', label: 'Text' },
  { id: 'int', label: 'Whole number' },
  { id: 'bool', label: 'Yes / no' },
];

export const MAX_BODY_CHARS = 512 * 1024;
export const MAX_PARAMETERS = 32;
export const MAX_PARAMETER_VALUE = 4096;
export const MAX_PARAMETER_DEFAULT = 1024;

/** Server `ScriptEndpoints.EnvName`: parameters reach the script as environment variables. */
export const PARAMETER_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;

export function languageLabel(language: string): string {
  return LANGUAGES.find((l) => l.id === language)?.label ?? language;
}

export function allowedOs(language: string): readonly string[] {
  return (LANGUAGE_OS as Record<string, readonly string[] | undefined>)[language] ?? [];
}

/** Keeps only the OS targets the language supports; none left means "all the language supports". */
export function clampOsTargets(language: string, osTargets: readonly string[]): string[] {
  const allowed = allowedOs(language);
  const kept = osTargets.filter((os) => allowed.includes(os));
  return kept.length > 0 ? kept : [...allowed];
}

/** `.NET long.TryParse`-compatible check for whole numbers (optional sign, digits, 64-bit range). */
export function isWholeNumber(text: string): boolean {
  const t = text.trim();
  if (!/^[+-]?\d{1,19}$/.test(t)) {
    return false;
  }
  try {
    const n = BigInt(t);
    return n >= -(2n ** 63n) && n <= 2n ** 63n - 1n;
  } catch {
    return false;
  }
}

// ----- Parameter definitions (script editor) -----

export interface ParameterDraft {
  /** Stable React key; not sent to the server. */
  key: string;
  name: string;
  type: ScriptParameterType;
  required: boolean;
  default: string;
}

let nextKey = 0;
export function newParameterDraft(patch: Partial<Omit<ParameterDraft, 'key'>> = {}): ParameterDraft {
  nextKey += 1;
  return { key: `p${nextKey}`, name: '', type: 'string', required: false, default: '', ...patch };
}

export function toParameterDrafts(parameters: readonly ScriptParameter[] | null | undefined): ParameterDraft[] {
  return (parameters ?? []).map((p) =>
    newParameterDraft({
      name: p.name,
      type: p.type === 'int' ? 'int' : p.type === 'bool' ? 'bool' : 'string',
      required: p.required,
      default: p.default ?? '',
    }),
  );
}

export function toScriptParameters(drafts: readonly ParameterDraft[]): ScriptParameter[] {
  return drafts.map((d) => ({
    name: d.name.trim(),
    type: d.type,
    required: d.required,
    default: d.default === '' ? null : d.type === 'string' ? d.default : d.default.trim(),
  }));
}

export interface ParameterDraftErrors {
  name?: string;
  default?: string;
}

/** Per-row problems of the definitions, keyed by draft key. An empty object means the list is valid. */
export function validateParameterDrafts(drafts: readonly ParameterDraft[]): Record<string, ParameterDraftErrors> {
  const errors: Record<string, ParameterDraftErrors> = {};
  const seen = new Map<string, number>();
  for (const d of drafts) {
    const lower = d.name.trim().toLowerCase();
    seen.set(lower, (seen.get(lower) ?? 0) + 1);
  }
  for (const d of drafts) {
    const e: ParameterDraftErrors = {};
    const name = d.name.trim();
    if (!name) {
      e.name = 'Enter a name.';
    } else if (!PARAMETER_NAME.test(name)) {
      e.name = 'Use letters, digits and underscores, starting with a letter or underscore (up to 64).';
    } else if ((seen.get(name.toLowerCase()) ?? 0) > 1) {
      e.name = 'Another parameter already has this name.';
    }
    if (d.default !== '') {
      const problem = valueProblem(d.type, d.default, MAX_PARAMETER_DEFAULT);
      if (problem) {
        e.default = problem;
      }
    }
    if (e.name || e.default) {
      errors[d.key] = e;
    }
  }
  return errors;
}

// ----- Parameter values (run dialog) -----

function valueProblem(type: string, value: string, max: number): string | null {
  if (value.length > max) {
    return `At most ${max} characters.`;
  }
  if (value.includes('\0')) {
    return 'Control characters are not allowed.';
  }
  if (type === 'int' && !isWholeNumber(value)) {
    return 'Enter a whole number, for example 30.';
  }
  if (type === 'bool' && value.trim() !== 'true' && value.trim() !== 'false') {
    return 'Enter true or false.';
  }
  return null;
}

/** What the run form holds per parameter: text for string/int, `'true' | 'false' | ''` for bool. */
export type ParameterValues = Record<string, string>;

export function initialParameterValues(parameters: readonly ScriptParameter[] | null | undefined): ParameterValues {
  const values: ParameterValues = {};
  for (const p of parameters ?? []) {
    values[p.name] = p.default ?? '';
  }
  return values;
}

/** Problems per parameter name; empty when the values can be sent. */
export function validateParameterValues(
  parameters: readonly ScriptParameter[] | null | undefined,
  values: ParameterValues,
): Record<string, string> {
  const errors: Record<string, string> = {};
  for (const p of parameters ?? []) {
    const raw = values[p.name] ?? '';
    const empty = p.type === 'string' ? raw === '' : raw.trim() === '';
    if (empty) {
      // An empty box falls back to the script's default on the server; without one a required value is missing.
      if (p.required && (p.default ?? '') === '') {
        errors[p.name] = 'This parameter is required.';
      }
      continue;
    }
    const problem = valueProblem(p.type, raw, MAX_PARAMETER_VALUE);
    if (problem) {
      errors[p.name] = problem;
    }
  }
  return errors;
}

/**
 * The `parameters` object for `POST /jobs/run-script`. Empty values are left out so the server applies the
 * script's default. Numbers are sent as text, which the server accepts and which keeps 64-bit values exact.
 */
export function buildParameterPayload(
  parameters: readonly ScriptParameter[] | null | undefined,
  values: ParameterValues,
): Record<string, string | boolean> {
  const payload: Record<string, string | boolean> = {};
  for (const p of parameters ?? []) {
    const raw = values[p.name] ?? '';
    if (p.type === 'bool') {
      const v = raw.trim();
      if (v === 'true' || v === 'false') {
        payload[p.name] = v === 'true';
      }
    } else if (p.type === 'int') {
      if (raw.trim() !== '') {
        payload[p.name] = raw.trim().replace(/^\+/, '');
      }
    } else if (raw !== '') {
      payload[p.name] = raw;
    }
  }
  return payload;
}

// ----- Run options -----

export const RUN_LIMITS = {
  timeoutSeconds: { min: 5, max: 24 * 3600, default: 300 },
  maxOutputKb: { min: 1, max: 16 * 1024, default: 1024 },
  maxParallel: { min: 0, max: 5000, default: 0 },
} as const;

/** Whole number inside `[min, max]`, or `null`. */
export function parseBounded(text: string, min: number, max: number): number | null {
  const t = text.trim();
  if (!/^\d+$/.test(t)) {
    return null;
  }
  const n = Number.parseInt(t, 10);
  return n >= min && n <= max ? n : null;
}
