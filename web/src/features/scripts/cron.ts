/**
 * Reads standard five-field cron expressions (minute hour day-of-month month day-of-week), the format the server
 * parses with Cronos. This only produces a plain-language preview and catches obvious mistakes early; the server is
 * the authority on validity.
 */

export type CronPreview = { ok: true; text: string; exact: boolean } | { ok: false; error: string };

interface FieldSpec {
  name: string;
  min: number;
  max: number;
  names?: readonly string[];
  /** Offset of `names[0]` (months start at 1). */
  nameBase?: number;
}

const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'] as const;
const DAYS = ['SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT'] as const;
const MONTH_NAMES = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
];
const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

const FIELDS: readonly FieldSpec[] = [
  { name: 'minute', min: 0, max: 59 },
  { name: 'hour', min: 0, max: 23 },
  { name: 'day of month', min: 1, max: 31 },
  { name: 'month', min: 1, max: 12, names: MONTHS, nameBase: 1 },
  { name: 'day of week', min: 0, max: 7, names: DAYS, nameBase: 0 },
];

/** A parsed field: `null` = any value, a sorted list of values, or `'advanced'` for syntax we do not summarise. */
type Parsed = { any: true; step: number } | { any: false; values: number[] } | 'advanced';

function parseNumber(token: string, spec: FieldSpec): number | null {
  if (/^\d+$/.test(token)) {
    const n = Number.parseInt(token, 10);
    return n >= spec.min && n <= spec.max ? n : null;
  }
  const index = spec.names?.indexOf(token.toUpperCase()) ?? -1;
  return index >= 0 ? index + (spec.nameBase ?? 0) : null;
}

function parseField(text: string, spec: FieldSpec): Parsed | { error: string } {
  // Cronos extras (last day, nearest weekday, nth weekday, "no specific value") are accepted but not summarised.
  const withoutNames = text.toUpperCase().replace(/[A-Z]{3}/g, (m) => (spec.names?.includes(m) ? '' : m));
  if (/[LW#?]/.test(withoutNames) && (spec.name === 'day of month' || spec.name === 'day of week')) {
    return /^[0-9A-Za-z,\-/*LW#?]+$/.test(text) ? 'advanced' : { error: `The ${spec.name} field is not valid.` };
  }
  const values = new Set<number>();
  let any: { step: number } | null = null;
  for (const part of text.split(',')) {
    if (part === '') {
      return { error: `The ${spec.name} field has an empty item.` };
    }
    const [range = '', stepText, ...rest] = part.split('/');
    if (rest.length > 0) {
      return { error: `The ${spec.name} field has more than one “/”.` };
    }
    let step = 1;
    if (stepText !== undefined) {
      if (!/^\d+$/.test(stepText) || Number.parseInt(stepText, 10) < 1) {
        return { error: `The step in the ${spec.name} field must be a positive number.` };
      }
      step = Number.parseInt(stepText, 10);
    }
    let from: number;
    let to: number;
    if (range === '*') {
      if (text === part) {
        any = { step };
      }
      from = spec.min;
      to = spec.name === 'day of week' ? 6 : spec.max;
    } else if (range.includes('-')) {
      const [a = '', b = '', ...more] = range.split('-');
      const lo = parseNumber(a, spec);
      const hi = parseNumber(b, spec);
      if (more.length > 0 || lo === null || hi === null) {
        return { error: `The ${spec.name} field must use values from ${spec.min} to ${spec.max}.` };
      }
      if (lo > hi) {
        return { error: `The range ${range} in the ${spec.name} field runs backwards.` };
      }
      from = lo;
      to = hi;
    } else {
      const n = parseNumber(range, spec);
      if (n === null) {
        return { error: `The ${spec.name} field must use values from ${spec.min} to ${spec.max}.` };
      }
      from = n;
      // "5/15" means "from 5, every 15".
      to = stepText !== undefined ? spec.max : n;
    }
    for (let v = from; v <= to; v += step) {
      values.add(spec.name === 'day of week' && v === 7 ? 0 : v);
    }
  }
  if (any) {
    return { any: true, step: any.step };
  }
  return { any: false, values: [...values].sort((a, b) => a - b) };
}

const two = (n: number) => String(n).padStart(2, '0');

function joinList(items: string[]): string {
  if (items.length <= 1) {
    return items[0] ?? '';
  }
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1] ?? ''}`;
}

function ordinal(n: number): string {
  const tens = n % 100;
  const suffix = tens >= 11 && tens <= 13 ? 'th' : (['th', 'st', 'nd', 'rd'][n % 10] ?? 'th');
  return `${n}${suffix}`;
}

function describeDays(values: number[]): string {
  if (values.length === 7) {
    return 'every day';
  }
  const key = values.join(',');
  if (key === '1,2,3,4,5') {
    return 'Monday to Friday';
  }
  if (key === '0,6') {
    return 'Saturday and Sunday';
  }
  // Read the week from Monday; cron's 0 is Sunday.
  const ordered = [...values].sort((a, b) => ((a + 6) % 7) - ((b + 6) % 7));
  return `every ${joinList(ordered.map((d) => DAY_NAMES[d] ?? ''))}`;
}

function describeTimes(minute: Parsed, hour: Parsed): string | null {
  if (minute === 'advanced' || hour === 'advanced') {
    return null;
  }
  if (minute.any && hour.any) {
    if (hour.step !== 1) {
      return null;
    }
    return minute.step === 1 ? 'every minute' : `every ${minute.step} minutes`;
  }
  if (!minute.any && hour.any) {
    if (minute.values.length !== 1) {
      return null;
    }
    const m = minute.values[0] ?? 0;
    const past = m === 0 ? 'on the hour' : `at ${m} ${m === 1 ? 'minute' : 'minutes'} past the hour`;
    return hour.step === 1 ? `every hour ${past}` : `every ${hour.step} hours ${past}`;
  }
  if (minute.any && !hour.any) {
    if (hour.values.length !== 1) {
      return null;
    }
    const h = hour.values[0] ?? 0;
    return `${minute.step === 1 ? 'every minute' : `every ${minute.step} minutes`} from ${two(h)}:00 to ${two(h)}:59`;
  }
  if (!minute.any && !hour.any) {
    const times = hour.values.flatMap((h) => minute.values.map((m) => `${two(h)}:${two(m)}`));
    if (times.length === 0 || times.length > 6) {
      return null;
    }
    return `at ${joinList(times)}`;
  }
  return null;
}

/** Plain-language reading of a cron expression, or the first problem found. */
export function describeCron(expression: string): CronPreview {
  const parts = expression.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) {
    return { ok: false, error: 'Enter a schedule.' };
  }
  if (parts.length !== 5) {
    return {
      ok: false,
      error: `A schedule has five fields (minute, hour, day of month, month, day of week); this has ${parts.length}.`,
    };
  }
  const parsed: Parsed[] = [];
  for (const [i, spec] of FIELDS.entries()) {
    const result = parseField(parts[i] ?? '', spec);
    if (typeof result === 'object' && 'error' in result) {
      return { ok: false, error: result.error };
    }
    parsed.push(result);
  }
  const [minute, hour, dom, month, dow] = parsed as [Parsed, Parsed, Parsed, Parsed, Parsed];
  const custom: CronPreview = {
    ok: true,
    exact: false,
    text: 'Custom schedule. The next run time is shown after you save it.',
  };
  if (dom === 'advanced' || dow === 'advanced' || month === 'advanced') {
    return custom;
  }
  const time = describeTimes(minute, hour);
  if (time === null) {
    return custom;
  }
  const frequent = time.startsWith('every');
  const monthText = month.any
    ? month.step === 1
      ? null
      : `every ${month.step} months`
    : joinList(month.values.map((m) => MONTH_NAMES[m - 1] ?? ''));
  if (!month.any && month.values.length === 0) {
    return custom;
  }
  if ((dom.any && dom.step !== 1) || (dow.any && dow.step !== 1) || (month.any && month.step !== 1)) {
    return custom;
  }

  let when: string;
  if (dom.any && dow.any) {
    when = monthText ? `every day in ${monthText}` : 'every day';
  } else if (dom.any && !dow.any) {
    when = describeDays(dow.values) + (monthText ? ` in ${monthText}` : '');
  } else if (!dom.any && dow.any) {
    const days = joinList(dom.values.map(ordinal));
    when = monthText ? `on the ${days} of ${monthText}` : `on the ${days} of every month`;
  } else {
    // Cron runs when either the day of month or the day of week matches.
    return custom;
  }
  const text = frequent ? `${time}, ${when}` : `${when} ${time}`;
  return { ok: true, exact: true, text: text.charAt(0).toUpperCase() + text.slice(1) };
}

export const CRON_PRESETS: readonly { label: string; cron: string }[] = [
  { label: 'Every day at 02:00', cron: '0 2 * * *' },
  { label: 'Weekdays at 08:00', cron: '0 8 * * 1-5' },
  { label: 'Every Sunday at 03:00', cron: '0 3 * * 0' },
  { label: 'First of the month at 01:00', cron: '0 1 1 * *' },
  { label: 'Every hour', cron: '0 * * * *' },
  { label: 'Every 15 minutes', cron: '*/15 * * * *' },
];
