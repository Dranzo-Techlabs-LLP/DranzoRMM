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

export interface RadiusStatus {
  id: Id;
  organizationId: Id;
  clientsCidr: string;
  officeSsid: string;
  createdAt: IsoDate;
  updatedAt: IsoDate;
  caPem: string;
  activeCertificates: number;
  installedCertificates: number;
  revokedCertificates: number;
}

export const radiusApi = {
  list: (organizationId?: Id) => api.get<RadiusStatus[]>('/radius', { query: { organizationId } }),
  /** Enables or updates 802.1X for an organization. Partner-wide network.configure + step-up. */
  save: (input: { organizationId: Id; clientsCidr: string; officeSsid: string }) =>
    api.post<{ id: Id }>('/radius', input),
  /**
   * Downloads the FreeRADIUS bundle (private key and shared secret inside). The server asks for a fresh authenticator
   * code; on `401 step_up_required` the step-up dialog opens and the download is tried once more.
   */
  downloadBundle: async (id: Id) => {
    const url = `/api/v1/radius/${id}/bundle.zip`;
    let res = await fetch(url, { credentials: 'same-origin' });
    if (res.status === 401 && (await res.clone().text()).includes('step_up_required')) {
      if (!(await api.confirmStepUp())) {
        return false;
      }
      res = await fetch(url, { credentials: 'same-origin' });
    }
    if (!res.ok) {
      throw new Error(`Download failed (HTTP ${String(res.status)}).`);
    }
    const href = URL.createObjectURL(await res.blob());
    const a = document.createElement('a');
    a.href = href;
    a.download = 'dranzo-radius.zip';
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(href);
    }, 10_000);
    return true;
  },
  enroll: (id: Id, deviceIds?: Id[]) =>
    api.post<{ jobId: Id; deviceCount: number }>(`/radius/${id}/enroll`, { deviceIds }),
  useOnUnifi: (id: Id, input: { controllerId: Id; radiusHost: string; radiusPort?: number }) =>
    api.post<{ ssid: string; security: string }>(`/radius/${id}/unifi`, input),
};

export const networkKeys = {
  all: ['network'] as const,
  devices: (filter: NetworkDeviceFilter) => ['network', 'devices', filter] as const,
  controllers: (organizationId?: Id) => ['network', 'controllers', organizationId ?? 'all'] as const,
  overview: (id: Id) => ['network', 'controller-overview', id] as const,
  radius: (organizationId?: Id) => ['network', 'radius', organizationId ?? 'all'] as const,
};
