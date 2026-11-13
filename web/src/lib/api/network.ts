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
  /** `controller` says whether the decision was applied on the Wi-Fi controller. */
  setStatus: (id: Id, status: NetworkDeviceStatus, note?: string) =>
    api.post<{ controller: string }>(`/network/devices/${id}/status`, { status, note }),
  setStatusBulk: (ids: Id[], status: NetworkDeviceStatus) =>
    api.post<{ updated: number; controller: string }>('/network/devices/status', { ids, status }),
  forget: (id: Id) => api.delete(`/network/devices/${id}`),
};

export interface NetworkController {
  id: Id;
  organizationId: Id;
  siteId: Id | null;
  name: string;
  kind: string;
  baseUrl: string;
  unifiSite: string;
  unifiOs: boolean;
  authMode: 'apikey' | 'password';
  username: string | null;
  pinned: boolean;
  createdAt: IsoDate;
  lastSyncAt: IsoDate | null;
  lastError: string | null;
}

export interface ControllerInput {
  organizationId?: Id;
  siteId?: Id | null;
  name?: string;
  baseUrl?: string;
  unifiSite?: string;
  unifiOs?: boolean;
  authMode?: 'apikey' | 'password';
  username?: string;
  /** API key or password; omit to keep the stored one. */
  secret?: string;
  certificateSha256?: string;
}

export interface ControllerOverview {
  reachable: boolean;
  error?: string;
  devices?: {
    mac: string;
    name: string;
    model: string;
    type: string;
    ip: string;
    version: string;
    state: 'online' | 'offline' | 'busy' | 'unknown';
    uptimeSeconds: number | null;
    clients: number | null;
    upgradable: boolean;
  }[];
  wlans?: {
    id: string;
    name: string;
    security: string;
    enabled: boolean;
    isGuest: boolean;
    clientIsolation: boolean;
    network: string | null;
  }[];
  networks?: { id: string; name: string; purpose: string; vlan: number | null; subnet: string }[];
  clientCount?: number;
  guestClientCount?: number;
}

export interface WifiNetworkInput {
  ssid: string;
  passphrase?: string;
  vlan: number;
  subnet: string;
  clientIsolation?: boolean;
}

export const controllersApi = {
  list: (organizationId?: Id) => api.get<NetworkController[]>('/network-controllers', { query: { organizationId } }),
  create: (input: ControllerInput) => api.post<NetworkController>('/network-controllers', input),
  update: (id: Id, input: ControllerInput) => api.patch<NetworkController>(`/network-controllers/${id}`, input),
  remove: (id: Id) => api.delete(`/network-controllers/${id}`),
  sync: (id: Id) => api.post<NetworkController>(`/network-controllers/${id}/sync`),
  overview: (id: Id) => api.get<ControllerOverview>(`/network-controllers/${id}/overview`),
  restartDevice: (id: Id, mac: string) =>
    api.post(`/network-controllers/${id}/devices/${encodeURIComponent(mac)}/restart`),
  wifiSetup: (id: Id, input: { office?: WifiNetworkInput; guest?: WifiNetworkInput }) =>
    api.post<{ steps: string[] }>(`/network-controllers/${id}/wifi-setup`, input),
};

export const networkKeys = {
  all: ['network'] as const,
  devices: (filter: NetworkDeviceFilter) => ['network', 'devices', filter] as const,
  controllers: (organizationId?: Id) => ['network', 'controllers', organizationId ?? 'all'] as const,
  overview: (id: Id) => ['network', 'controller-overview', id] as const,
};
