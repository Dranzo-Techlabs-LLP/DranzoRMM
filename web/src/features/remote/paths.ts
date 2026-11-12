/**
 * Path helpers for the remote file browser. Paths are only ever built here and sent to the device as text; the
 * device decides what exists. Windows (`C:\Users\x`, `\\server\share`) and POSIX (`/home/x`) are both handled.
 */
export type PathStyle = 'windows' | 'posix';

export interface Crumb {
  label: string;
  path: string;
}

export function pathStyleFor(os: string): PathStyle {
  return os === 'windows' ? 'windows' : 'posix';
}

/** Where the browser opens: the system drive on Windows, the root elsewhere. */
export function defaultPath(style: PathStyle): string {
  return style === 'windows' ? 'C:\\' : '/';
}

const DRIVE = /^[A-Za-z]:/;

function isUnc(path: string): boolean {
  return path.startsWith('\\\\');
}

/** The part of a Windows path that cannot be navigated above: `C:\` or `\\server\share`. */
function windowsRoot(path: string): string {
  if (isUnc(path)) {
    const parts = path.slice(2).split('\\').filter(Boolean);
    return parts.length >= 2 ? `\\\\${parts[0] ?? ''}\\${parts[1] ?? ''}` : `\\\\${parts.join('\\')}`;
  }
  const drive = DRIVE.exec(path);
  return drive ? `${drive[0].toUpperCase()}\\` : '\\';
}

/**
 * Tidies what a person typed into the path bar: trims, unifies separators (Windows accepts `/`), collapses repeated
 * separators and removes a trailing one. Does not resolve `.` or `..`: the device does that, and reports the
 * resulting path back.
 */
export function normalizePath(input: string, style: PathStyle): string {
  const raw = input.trim();
  if (raw === '') {
    return defaultPath(style);
  }
  if (style === 'posix') {
    const collapsed = raw.replace(/\/{2,}/g, '/');
    return collapsed.length > 1 ? collapsed.replace(/\/$/, '') : collapsed;
  }
  const slashed = raw.replaceAll('/', '\\');
  if (isUnc(slashed)) {
    return `\\\\${slashed.slice(2).split('\\').filter(Boolean).join('\\')}`;
  }
  const collapsed = slashed.replace(/\\{2,}/g, '\\');
  if (/^[A-Za-z]:\\?$/.test(collapsed)) {
    return `${collapsed.slice(0, 2).toUpperCase()}\\`;
  }
  const trimmed = collapsed.length > 1 ? collapsed.replace(/\\$/, '') : collapsed;
  return DRIVE.test(trimmed) ? trimmed.charAt(0).toUpperCase() + trimmed.slice(1) : trimmed;
}

/** `dir` + one entry name from a listing. The name is used as it is: it comes from the device. */
export function joinPath(dir: string, name: string, style: PathStyle): string {
  const sep = style === 'windows' ? '\\' : '/';
  return dir.endsWith(sep) ? `${dir}${name}` : `${dir}${sep}${name}`;
}

/** The containing folder, or `null` at a root (`/`, `C:\`, `\\server\share`). */
export function parentPath(path: string, style: PathStyle): string | null {
  const p = normalizePath(path, style);
  if (style === 'posix') {
    if (p === '/') {
      return null;
    }
    const i = p.lastIndexOf('/');
    return i <= 0 ? '/' : p.slice(0, i);
  }
  const root = windowsRoot(p);
  if (p.length <= root.length) {
    return null;
  }
  const i = p.lastIndexOf('\\');
  return i < root.length ? root : p.slice(0, i);
}

/** Last component, for download names and messages. */
export function baseName(path: string, style: PathStyle): string {
  const p = normalizePath(path, style);
  const sep = style === 'windows' ? '\\' : '/';
  return p.slice(p.lastIndexOf(sep) + 1) || p;
}

/** Root first, the current folder last. Every crumb carries the full path to navigate to. */
export function breadcrumbs(path: string, style: PathStyle): Crumb[] {
  const p = normalizePath(path, style);
  if (style === 'posix') {
    const crumbs: Crumb[] = [{ label: '/', path: '/' }];
    let current = '';
    for (const part of p.split('/').filter(Boolean)) {
      current += `/${part}`;
      crumbs.push({ label: part, path: current });
    }
    return crumbs;
  }
  const root = windowsRoot(p);
  const crumbs: Crumb[] = [{ label: isUnc(root) ? root : root.slice(0, 2), path: root }];
  let current = root;
  for (const part of p.slice(root.length).split('\\').filter(Boolean)) {
    current = joinPath(current, part, 'windows');
    crumbs.push({ label: part, path: current });
  }
  return crumbs;
}

/** Folders first, then by name without regard to case; the device's order is not relied on. */
export function sortEntries<T extends { name: string; isDir: boolean }>(entries: readonly T[]): T[] {
  return [...entries].sort(
    (a, b) => Number(b.isDir) - Number(a.isDir) || a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }),
  );
}
