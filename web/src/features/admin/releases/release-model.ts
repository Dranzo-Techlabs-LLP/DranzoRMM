import type { DeviceGroup } from '@/lib/api';
import type { ReleaseArch, ReleaseFileKind, ReleaseOs, ReleaseRing } from '@/lib/api/releases';

export const RING_ORDER: readonly ReleaseRing[] = ['none', 'test', 'pilot', 'all'];

export const RING_LABEL: Record<string, string> = {
  none: 'Not offered',
  test: 'Test ring',
  pilot: 'Test and pilot rings',
  all: 'Every device',
};

/** Device-group rings a release ring reaches (server `UpdateRollout.Reaches`). Ungrouped devices count as `all`. */
export function ringReaches(releaseRing: string, groupRing: string): boolean {
  switch (releaseRing) {
    case 'test':
      return groupRing === 'test';
    case 'pilot':
      return groupRing === 'test' || groupRing === 'pilot';
    case 'all':
      return true;
    default:
      return false;
  }
}

/** Which groups a ring reaches, from the group list. `null` when the ring reaches every device. */
export function groupsReached(ring: string, groups: DeviceGroup[]): DeviceGroup[] | null {
  if (ring === 'all') {
    return null;
  }
  return groups.filter((g) => ringReaches(ring, g.updateRing));
}

/** A file slot of the release wizard: the agent binary or an installer for one OS/arch. */
export interface ReleaseSlot {
  os: ReleaseOs;
  arch: ReleaseArch;
  kind: ReleaseFileKind;
}

export const RELEASE_SLOTS: ReleaseSlot[] = (['windows', 'macos', 'linux'] as const).flatMap((os) =>
  (['amd64', 'arm64'] as const).flatMap((arch) => {
    const installers: ReleaseFileKind[] = os === 'windows' ? ['msi'] : os === 'macos' ? ['pkg'] : ['deb', 'rpm'];
    return (['binary', ...installers] as ReleaseFileKind[]).map((kind) => ({ os, arch, kind }));
  }),
);

export function slotKey(slot: ReleaseSlot): string {
  return `${slot.os}-${slot.arch}-${slot.kind}`;
}

export const KIND_LABEL: Record<string, string> = {
  binary: 'Agent binary (self-update)',
  msi: 'Windows installer (.msi)',
  pkg: 'macOS installer (.pkg)',
  deb: 'Debian/Ubuntu package (.deb)',
  rpm: 'RHEL/Fedora package (.rpm)',
};

export const VERSION_PATTERN = /^\d+\.\d+\.\d+(-[0-9A-Za-z.]{1,20})?$/;

export const MIN_RELEASE_FILE_BYTES = 1024 * 1024;
export const MAX_RELEASE_FILE_BYTES = 500 * 1024 * 1024;

export const UPDATE_STATE_LABEL: Record<string, string> = {
  offered: 'Offered',
  downloading: 'Downloading',
  verifying: 'Verifying',
  installed: 'Installed',
  rolled_back: 'Rolled back',
  failed: 'Failed',
};
