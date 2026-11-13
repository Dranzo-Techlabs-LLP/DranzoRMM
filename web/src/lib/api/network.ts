import { api } from './client';
import type { Id, IsoDate, Paged } from './types';

/** Network discovery and the device approval list (`server/src/Dranzo.Api/Features/NetworkEndpoints.cs`). */

export type NetworkDeviceStatus = 'unknown' | 'approved' | 'blocked';

export interface NetworkDevice {
  id: Id;
  organizationId: Id;
  siteId: Id;
  siteName: string | null;
  mac: string;
  ip: string;
  hostname: string | null;
  vendor: string | null;
  /** Private (locally administered) MAC, typically a phone or laptop on Wi-Fi. */
  randomized: boolean;
  isGateway: boolean;
  firstSeenAt: IsoDate;
  lastSeenAt: IsoDate;
  status: NetworkDeviceStatus;
  note: string | null;
  statusChangedAt: IsoDate | null;
  statusChangedBy: string | null;
  managedDeviceId: Id | null;
  managedHostname: string | null;
  seenByDeviceId: Id | null;
  seenByHostname: string | null;
}

export interface NetworkDeviceList extends Paged<NetworkDevice> {
  lastScanAt: IsoDate | null;
  counts: Record<NetworkDeviceStatus, number>;
}

export interface NetworkDeviceFilter {
  organizationId?: Id;
  siteId?: Id;
  status?: NetworkDeviceStatus;
  search?: string;
  page?: number;
  pageSize?: number;
}

export const networkApi = {
  devices: (filter: NetworkDeviceFilter) => api.get<NetworkDeviceList>('/network/devices', { query: { ...filter } }),
  /** Runs network.scan on one device, or on the most recently seen capable device of the site. */
  scan: (target: { siteId: Id } | { deviceId: Id }) =>
    api.post<{ jobId: Id; deviceId: Id; hostname: string }>('/network/scan', target),
  setStatus: (id: Id, status: NetworkDeviceStatus, note?: string) =>
    api.post(`/network/devices/${id}/status`, { status, note }),
  setStatusBulk: (ids: Id[], status: NetworkDeviceStatus) =>
    api.post<{ updated: number }>('/network/devices/status', { ids, status }),
  forget: (id: Id) => api.delete(`/network/devices/${id}`),
};

export const networkKeys = {
  all: ['network'] as const,
  devices: (filter: NetworkDeviceFilter) => ['network', 'devices', filter] as const,
};
