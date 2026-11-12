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

const LABELS: Record<keyof InstallInfo['commands'], string> = {
  windows: 'Windows',
  macos: 'macOS',
  linuxDeb: 'Linux (.deb)',
  linuxRpm: 'Linux (.rpm)',
};

/** Per-OS install commands from `GET /agent/install-info` with the one-time token substituted for `<token>`. */
export function installCommands(info: InstallInfo, token: string): InstallCommand[] {
  return (Object.keys(LABELS) as (keyof InstallInfo['commands'])[]).map((id) => {
    const command = info.commands[id].replaceAll('<token>', token);
    const placeholders = [...new Set(command.match(/<[a-z]+>/g) ?? [])];
    return { id, label: LABELS[id], command, placeholders };
  });
}

export const EXPIRY_PRESETS: { hours: number; label: string }[] = [
  { hours: 24, label: '1 day' },
  { hours: 72, label: '3 days' },
  { hours: 168, label: '7 days' },
  { hours: 720, label: '30 days' },
  { hours: 2160, label: '90 days' },
];
