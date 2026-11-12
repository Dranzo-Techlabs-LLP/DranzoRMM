import { devicesApi, type DeviceListItem, type Id, type Organization } from '@/lib/api';

export const FLEET_PAGE_SIZE = 500; // server maximum
export const FLEET_MAX_PAGES = 10;

export interface Fleet {
  devices: DeviceListItem[];
  total: number;
  /** False when the fleet is larger than the dashboard is willing to page through. */
  complete: boolean;
}

/**
 * Loads the device list page by page. The API has no summary endpoint and no "pending restart" filter, so the
 * overview derives its counts from the list itself.
 */
export async function fetchFleet(organizationId?: Id, signal?: AbortSignal): Promise<Fleet> {
  const first = await devicesApi.list({ organizationId, page: 1, pageSize: FLEET_PAGE_SIZE }, signal);
  const devices = [...first.items];
  const pages = Math.ceil(first.total / FLEET_PAGE_SIZE);
  for (let page = 2; page <= Math.min(pages, FLEET_MAX_PAGES); page++) {
    const next = await devicesApi.list({ organizationId, page, pageSize: FLEET_PAGE_SIZE }, signal);
    devices.push(...next.items);
  }
  return { devices, total: first.total, complete: pages <= FLEET_MAX_PAGES };
}

export interface FleetCounts {
  total: number;
  online: number;
  offline: number;
  pendingReboot: number;
}

export interface OrgRow extends FleetCounts {
  id: Id;
  name: string;
}

export function countDevices(devices: Pick<DeviceListItem, 'isOnline' | 'pendingReboot'>[]): FleetCounts {
  const online = devices.filter((d) => d.isOnline).length;
  return {
    total: devices.length,
    online,
    offline: devices.length - online,
    pendingReboot: devices.filter((d) => d.pendingReboot).length,
  };
}

/**
 * One row per organization. Names (and organizations without devices) come from the organization list when the
 * user may read it; counts come from the devices the user can actually see.
 */
export function summarizeByOrganization(fleet: Fleet, organizations: Organization[] | undefined): OrgRow[] {
  const byOrg = new Map<Id, DeviceListItem[]>();
  for (const d of fleet.devices) {
    const list = byOrg.get(d.organizationId);
    if (list) {
      list.push(d);
    } else {
      byOrg.set(d.organizationId, [d]);
    }
  }
  const rows: OrgRow[] = [];
  const seen = new Set<Id>();
  for (const org of organizations ?? []) {
    seen.add(org.id);
    const counts = countDevices(byOrg.get(org.id) ?? []);
    // If the device list was cut off, the organization list's own totals are the accurate ones.
    rows.push(
      fleet.complete
        ? { id: org.id, name: org.name, ...counts }
        : {
            id: org.id,
            name: org.name,
            total: org.deviceCount,
            online: org.onlineCount,
            offline: org.deviceCount - org.onlineCount,
            pendingReboot: counts.pendingReboot,
          },
    );
  }
  for (const [id, devices] of byOrg) {
    if (!seen.has(id)) {
      rows.push({ id, name: `Organization ${id.slice(0, 8)}`, ...countDevices(devices) });
    }
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name));
}
