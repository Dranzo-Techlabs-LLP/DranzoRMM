import type { NetworkDevice, NetworkDeviceStatus } from '@/lib/api/network';

export const STATUS_LABEL: Record<NetworkDeviceStatus, string> = {
  unknown: 'Not reviewed',
  approved: 'Approved',
  blocked: 'Blocked',
};

export const STATUS_TONE = { unknown: 'warn', approved: 'ok', blocked: 'danger' } as const;

/** Best name for a discovered device: managed hostname, then reverse DNS, then the MAC. */
export function displayName(d: NetworkDevice): string {
  return d.managedHostname ?? d.hostname ?? d.mac;
}

/** Short description of what kind of device this probably is. */
export function deviceKind(d: NetworkDevice): string {
  if (d.isGateway) {
    return 'Router / gateway';
  }
  if (d.managedDeviceId) {
    return 'Managed by DranzoRMM';
  }
  if (d.randomized) {
    return 'Private address (phone or laptop)';
  }
  return d.vendor ?? 'Unknown device';
}
