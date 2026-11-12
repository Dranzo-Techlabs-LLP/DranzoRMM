const UNITS: [limit: number, seconds: number, unit: Intl.RelativeTimeFormatUnit][] = [
  [60, 1, 'second'],
  [3600, 60, 'minute'],
  [86400, 3600, 'hour'],
  [86400 * 30, 86400, 'day'],
  [86400 * 365, 86400 * 30, 'month'],
  [Infinity, 86400 * 365, 'year'],
];

const relative = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
const dateTime = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' });
const dateTimeSeconds = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'medium' });
const compactSeconds = new Intl.DateTimeFormat('en', {
  month: 'short',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
  second: '2-digit',
});

/** "3 minutes ago", "in 2 days". Returns "never" for missing or invalid dates. */
export function formatRelative(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) {
    return 'never';
  }
  const t = Date.parse(iso);
  if (Number.isNaN(t)) {
    return 'never';
  }
  const diff = (t - now) / 1000;
  const abs = Math.abs(diff);
  if (abs < 10) {
    return 'just now';
  }
  for (const [limit, seconds, unit] of UNITS) {
    if (abs < limit) {
      return relative.format(Math.round(diff / seconds), unit);
    }
  }
  return 'never';
}

export function formatDateTime(iso: string | null | undefined, withSeconds = false): string {
  if (!iso) {
    return '';
  }
  const t = Date.parse(iso);
  if (Number.isNaN(t)) {
    return '';
  }
  return (withSeconds ? dateTimeSeconds : dateTime).format(t);
}

/** Binary units, as operating systems report memory and disks. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes) || bytes < 0) {
    return '';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let value = bytes;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value >= 100 || i === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[i] ?? 'B'}`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) {
    return '';
  }
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) {
    return `${d}d ${h}h`;
  }
  if (h > 0) {
    return `${h}h ${m}m`;
  }
  return `${m}m`;
}

export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return '';
  }
  return value > 0 && value < 1 ? 'Under 1%' : `${Math.round(value)}%`;
}

/** `tenants.manage` → "Manage tenants" style label is done in features/admin; this just title-cases a word. */
export function capitalize(text: string): string {
  return text.length === 0 ? text : text.charAt(0).toUpperCase() + text.slice(1);
}

/** `<input type="datetime-local">` value → ISO instant (the input is in the viewer's local time). */
export function localInputToIso(value: string): string | undefined {
  if (!value) {
    return undefined;
  }
  const t = new Date(value);
  return Number.isNaN(t.getTime()) ? undefined : t.toISOString();
}

/** Timestamp for dense tables: the year is left out for dates in the current year ("Nov 11, 10:34:38 PM"). */
export function formatLogTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) {
    return '';
  }
  const t = Date.parse(iso);
  if (Number.isNaN(t)) {
    return '';
  }
  return new Date(t).getFullYear() === new Date(now).getFullYear()
    ? compactSeconds.format(t)
    : dateTimeSeconds.format(t);
}
