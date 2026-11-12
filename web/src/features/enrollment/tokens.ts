import type { Tone } from '@/components/status';
import type { EnrollmentToken, InstallInfo } from '@/lib/api';

export type TokenState = 'active' | 'expired' | 'revoked' | 'used-up';

export function tokenState(token: EnrollmentToken, now: number = Date.now()): TokenState {
  if (token.revokedAt) {
    return 'revoked';
  }
  if (Date.parse(token.expiresAt) <= now) {
    return 'expired';
  }
  if (token.uses >= token.maxUses) {
    return 'used-up';
  }
  return 'active';
}

export const TOKEN_STATE: Record<TokenState, { label: string; tone: Tone }> = {
  active: { label: 'Active', tone: 'ok' },
  expired: { label: 'Expired', tone: 'idle' },
  revoked: { label: 'Revoked', tone: 'danger' },
  'used-up': { label: 'Used up', tone: 'idle' },
};

export interface InstallCommand {
  id: keyof InstallInfo['commands'];
  label: string;
  command: string;
  /** Placeholders still in the command that the technician fills in (`<arch>`, `<version>`). */
  placeholders: string[];
}

/** Commands shown as tabs. Package-based commands (msi/deb/rpm) are shown only once installers are published. */
const LABELS: Partial<Record<keyof InstallInfo['commands'], string>> = {
  windows: 'Windows',
  macos: 'macOS',
  linux: 'Linux',
  check: 'Connection test',
};

/** Per-OS install commands from `GET /agent/install-info` with the one-time token substituted for `<token>`. */
export function installCommands(info: InstallInfo, token: string): InstallCommand[] {
  return (Object.keys(LABELS) as (keyof InstallInfo['commands'])[])
    .filter((id) => typeof info.commands[id] === 'string')
    .map((id) => {
      const command = info.commands[id].replaceAll('<token>', token);
      const placeholders = [...new Set(command.match(/<[a-z]+>/g) ?? [])];
      return { id, label: LABELS[id] ?? id, command, placeholders };
    });
}

/** Saves a small text file in the browser (the CA certificate and trust file the agent needs). */
export function downloadText(fileName: string, content: string): void {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function trustFileContent(info: InstallInfo): string {
  return JSON.stringify(info.trust);
}

export const EXPIRY_PRESETS: { hours: number; label: string }[] = [
  { hours: 24, label: '1 day' },
  { hours: 72, label: '3 days' },
  { hours: 168, label: '7 days' },
  { hours: 720, label: '30 days' },
  { hours: 2160, label: '90 days' },
];
