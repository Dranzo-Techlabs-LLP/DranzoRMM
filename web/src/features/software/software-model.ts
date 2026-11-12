import type { DetectionRule, DetectionType, PackageManager, PackageType } from '@/lib/api/software';

/** Server `SoftwareEndpoints.PackageIdPattern`; the agent rejects anything else as well. */
export const PACKAGE_ID = /^[A-Za-z0-9][A-Za-z0-9+._:@/-]{0,199}$/;

export const PACKAGE_MANAGERS: readonly {
  id: PackageManager;
  label: string;
  os: string;
  devices: string;
  example: string;
}[] = [
  { id: 'winget', label: 'winget', os: 'windows', devices: 'Windows devices', example: '7zip.7zip' },
  { id: 'brew', label: 'Homebrew', os: 'macos', devices: 'macOS devices', example: 'firefox' },
  { id: 'apt', label: 'apt', os: 'linux', devices: 'Debian and Ubuntu devices', example: 'p7zip-full' },
  { id: 'dnf', label: 'dnf', os: 'linux', devices: 'Fedora, RHEL and similar devices', example: 'p7zip' },
];

export type PackageIds = Record<PackageManager, string>;
export const EMPTY_PACKAGE_IDS: PackageIds = { winget: '', brew: '', apt: '', dnf: '' };

/** `null` when valid; an explanation otherwise. Empty is valid for one manager (it is simply not used). */
export function packageIdProblem(id: string): string | null {
  const value = id.trim();
  if (value === '') {
    return null;
  }
  if (value.length > 200) {
    return 'At most 200 characters.';
  }
  if (!/^[A-Za-z0-9]/.test(value)) {
    return 'Start with a letter or digit.';
  }
  if (!PACKAGE_ID.test(value)) {
    return 'Use only letters, digits and + . _ : @ / - (no spaces).';
  }
  return null;
}

export interface PackageIdValidation {
  errors: Partial<Record<PackageManager, string>>;
  /** Problem with the form as a whole (nothing filled in). */
  form: string | null;
  packages: Partial<Record<PackageManager, string>>;
}

/** Validates the four package-id boxes and builds the `packages` map for `POST /software/deploy`. */
export function validatePackageIds(ids: PackageIds): PackageIdValidation {
  const errors: Partial<Record<PackageManager, string>> = {};
  const packages: Partial<Record<PackageManager, string>> = {};
  for (const m of PACKAGE_MANAGERS) {
    const value = ids[m.id].trim();
    const problem = packageIdProblem(value);
    if (problem) {
      errors[m.id] = problem;
    } else if (value) {
      packages[m.id] = value;
    }
  }
  const form =
    Object.keys(packages).length === 0 && Object.keys(errors).length === 0
      ? 'Enter a package id for at least one package manager.'
      : null;
  return { errors, form, packages };
}

/** Operating systems a set of package ids can reach. */
export function managedOs(packages: Partial<Record<PackageManager, string>>): string[] {
  return [...new Set(PACKAGE_MANAGERS.filter((m) => packages[m.id]).map((m) => m.os))];
}

/** Which package manager can remove an inventory item, from the agent's `source`. */
export function managerForSource(source: string): PackageManager | null {
  switch (source) {
    case 'winget':
      return 'winget';
    case 'brew':
      return 'brew';
    case 'dpkg':
      return 'apt';
    case 'rpm':
      return 'dnf';
    default:
      return null;
  }
}

const SOURCE_LABELS: Record<string, string> = {
  registry: 'Windows installer',
  winget: 'winget',
  app: 'Application',
  pkgutil: 'macOS package',
  brew: 'Homebrew',
  dpkg: 'Debian package',
  rpm: 'RPM package',
  snap: 'Snap',
  flatpak: 'Flatpak',
};

export function sourceLabel(source: string): string {
  return SOURCE_LABELS[source] ?? source;
}

// ----- Custom packages -----

export const PACKAGE_TYPES: readonly { id: PackageType; label: string; os: string; extension: string }[] = [
  { id: 'msi', label: 'Windows Installer (.msi)', os: 'windows', extension: '.msi' },
  { id: 'exe', label: 'Windows executable (.exe)', os: 'windows', extension: '.exe' },
  { id: 'pkg', label: 'macOS package (.pkg)', os: 'macos', extension: '.pkg' },
  { id: 'dmg', label: 'macOS disk image (.dmg)', os: 'macos', extension: '.dmg' },
  { id: 'deb', label: 'Debian package (.deb)', os: 'linux', extension: '.deb' },
  { id: 'rpm', label: 'RPM package (.rpm)', os: 'linux', extension: '.rpm' },
];

export const PACKAGE_ACCEPT = PACKAGE_TYPES.map((t) => t.extension).join(',');

/** Package type from a file name's extension, or `null` when the server would refuse the file. */
export function packageTypeFromFileName(fileName: string): PackageType | null {
  const dot = fileName.lastIndexOf('.');
  if (dot < 0) {
    return null;
  }
  const ext = fileName.slice(dot).toLowerCase();
  return PACKAGE_TYPES.find((t) => t.extension === ext)?.id ?? null;
}

export function packageTypeInfo(type: string) {
  return PACKAGE_TYPES.find((t) => t.id === type) ?? null;
}

/** "Acme VPN 5.2.1.msi" → "Acme VPN 5.2.1" as a starting point for the package name. */
export function suggestPackageName(fileName: string): string {
  const dot = fileName.lastIndexOf('.');
  return (dot > 0 ? fileName.slice(0, dot) : fileName).replace(/[_]+/g, ' ').trim().slice(0, 120);
}

export const DETECTION_TYPES: readonly {
  id: DetectionType;
  label: string;
  os: readonly string[];
  keyLabel: string;
  keyHint: string;
  valueName?: string;
}[] = [
  {
    id: 'file',
    label: 'A file exists',
    os: ['windows', 'macos', 'linux'],
    keyLabel: 'File path',
    keyHint: 'Full path on the device, for example C:\\Program Files\\Acme\\acme.exe or /opt/acme/bin/acme.',
  },
  {
    id: 'registry',
    label: 'A registry value exists',
    os: ['windows'],
    keyLabel: 'Registry key',
    keyHint: 'A key below HKLM, for example HKLM\\SOFTWARE\\Acme\\VPN.',
    valueName: 'Value name holding the version (optional)',
  },
  {
    id: 'app',
    label: 'An application bundle is installed',
    os: ['macos'],
    keyLabel: 'Application name or path',
    keyHint: 'A name searched in the Applications folders (for example Firefox), or a full path ending in .app.',
  },
  {
    id: 'pkgutil',
    label: 'A macOS package receipt exists',
    os: ['macos'],
    keyLabel: 'Package id',
    keyHint: 'As listed by pkgutil --pkgs, for example com.acme.vpn.',
  },
  {
    id: 'dpkg',
    label: 'A Debian package is installed',
    os: ['linux'],
    keyLabel: 'Package name',
    keyHint: 'As known to dpkg, for example acme-vpn.',
  },
  {
    id: 'rpm',
    label: 'An RPM package is installed',
    os: ['linux'],
    keyLabel: 'Package name',
    keyHint: 'As known to rpm, for example acme-vpn.',
  },
  {
    id: 'winget',
    label: 'winget lists the package',
    os: ['windows'],
    keyLabel: 'winget package id',
    keyHint: 'For example Acme.VPN.',
  },
  {
    id: 'brew',
    label: 'Homebrew lists the package',
    os: ['macos'],
    keyLabel: 'Formula or cask name',
    keyHint: 'For example acme-vpn.',
  },
];

export function detectionTypesFor(os: string) {
  return DETECTION_TYPES.filter((d) => d.os.includes(os));
}

export const MAX_ARGS = 32;
export const MAX_ARG_LENGTH = 1024;

/** Problem with an argument list (install arguments, uninstall command), or `null`. Empty rows are ignored. */
export function argListProblem(args: readonly string[]): string | null {
  const used = args.filter((a) => a !== '');
  if (used.length > MAX_ARGS) {
    return `At most ${MAX_ARGS} items.`;
  }
  if (used.some((a) => a.length > MAX_ARG_LENGTH)) {
    return `Each item can be at most ${MAX_ARG_LENGTH} characters.`;
  }
  if (used.some((a) => a.includes('\0'))) {
    return 'Control characters are not allowed.';
  }
  return null;
}

export function cleanArgs(args: readonly string[]): string[] {
  return args.filter((a) => a !== '');
}

export interface DetectionDraft {
  enabled: boolean;
  type: string;
  key: string;
  valueName: string;
  minVersion: string;
}

export const EMPTY_DETECTION: DetectionDraft = { enabled: false, type: 'file', key: '', valueName: '', minVersion: '' };

/** The agent's rule for `minVersion`. */
export const MIN_VERSION = /^[A-Za-z0-9][A-Za-z0-9+._:~-]{0,63}$/;

const PACKAGE_KEYED: readonly string[] = ['pkgutil', 'dpkg', 'rpm', 'winget', 'brew'];

/**
 * Problems of a detection rule. Besides the server's length limits this applies the checks the agent makes
 * (`agent/internal/jobs/pkginstall/detect.go`), because a rule the agent rejects would fail every deployment.
 */
export function detectionProblems(d: DetectionDraft): { key?: string; valueName?: string; minVersion?: string } {
  if (!d.enabled) {
    return {};
  }
  const problems: { key?: string; valueName?: string; minVersion?: string } = {};
  const key = d.key.trim();
  if (key === '') {
    problems.key = 'Enter what to look for.';
  } else if (key.length > 512) {
    problems.key = 'At most 512 characters.';
  } else if (d.type === 'file' && !/^(?:\/|[A-Za-z]:[\\/])/.test(key)) {
    problems.key = 'Enter a full path, starting with / or a drive letter such as C:\\.';
  } else if (d.type === 'registry' && !/^(?:HKLM|HKEY_LOCAL_MACHINE)\\[^\\/](?:.*[^\\])?$/i.test(key)) {
    problems.key = 'Enter a key below HKLM\\, for example HKLM\\SOFTWARE\\Acme. Other hives are not checked.';
  } else if (PACKAGE_KEYED.includes(d.type) && (!PACKAGE_ID.test(key) || key.startsWith('-'))) {
    problems.key = 'Use only letters, digits and + . _ : @ / - (no spaces).';
  } else if (d.type === 'app' && !key.startsWith('/') && (/[/\\:]/.test(key) || key.startsWith('.'))) {
    problems.key = 'Enter an application name such as Firefox, or a full path ending in .app.';
  } else if (d.type === 'app' && key.startsWith('/') && !key.toLowerCase().endsWith('.app')) {
    problems.key = 'A path must end in .app.';
  }
  if (d.valueName.length > 255) {
    problems.valueName = 'At most 255 characters.';
  }
  const min = d.minVersion.trim();
  if (min !== '' && !MIN_VERSION.test(min)) {
    problems.minVersion = 'Use a version such as 5.2.1 (letters, digits and + . _ : ~ -, up to 64 characters).';
  }
  return problems;
}

export function toDetectionRule(d: DetectionDraft): DetectionRule | undefined {
  if (!d.enabled) {
    return undefined;
  }
  return {
    type: d.type,
    key: d.key.trim(),
    valueName: d.type === 'registry' && d.valueName.trim() ? d.valueName.trim() : undefined,
    minVersion: d.minVersion.trim() || undefined,
  };
}

/** One line describing a stored detection rule. */
export function describeDetection(rule: DetectionRule | null): string {
  if (!rule) {
    return 'No detection rule';
  }
  const type = DETECTION_TYPES.find((t) => t.id === rule.type);
  const version = rule.minVersion ? `, version ${rule.minVersion} or newer` : '';
  return `${type?.label ?? rule.type}: ${rule.key}${rule.valueName ? ` (${rule.valueName})` : ''}${version}`;
}

/** The agent accepts install arguments only for Windows installers; the other types install silently by themselves. */
export function supportsInstallArgs(type: string): boolean {
  return type === 'msi' || type === 'exe';
}

export function installArgsHint(type: string): string {
  if (type === 'msi') {
    return 'Extra msiexec arguments, one per row, for example INSTALLDIR=C:\\Acme. /qn and /norestart are always added.';
  }
  if (type === 'exe') {
    return 'The installer is started with exactly these arguments, one per row. Most need a silent switch such as /S or /quiet.';
  }
  return '';
}

/** Tool names the agent accepts as the program of an uninstall command; anything else must be a full path. */
export const UNINSTALL_TOOLS: Record<string, readonly string[]> = {
  windows: ['msiexec', 'winget'],
  macos: ['pkgutil', 'brew'],
  linux: ['apt-get', 'dpkg', 'dnf', 'rpm', 'snap', 'flatpak'],
};

export function uninstallHint(os: string): string {
  const tools = UNINSTALL_TOOLS[os] ?? [];
  return `First row: the program, as a full path${tools.length > 0 ? ` or one of ${tools.join(', ')}` : ''}. Following rows: one argument each. Without a command the package can be installed but not uninstalled from here.`;
}

/** Problem with the program (first item) of an uninstall command, or `null`. */
export function uninstallProgramProblem(command: readonly string[], os: string): string | null {
  if (command.length === 0) {
    return null;
  }
  const program = (command[0] ?? '').trim();
  if (program === '') {
    return 'Enter the program in the first row, or remove the rows.';
  }
  const absolute = /^(?:\/|[A-Za-z]:[\\/])/.test(program);
  if (!absolute && !(UNINSTALL_TOOLS[os] ?? []).includes(program)) {
    return `The program must be a full path or one of: ${(UNINSTALL_TOOLS[os] ?? []).join(', ')}.`;
  }
  return null;
}
