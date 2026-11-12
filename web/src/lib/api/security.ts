import { api } from './client';
import type { Id, IsoDate, Paged } from './types';

/** Security posture and vulnerabilities (`server/src/Dranzo.Api/Features/SecurityEndpoints.cs`). */

/** `true` = fine, `false` = problem, `null` = not reported or not supported on that operating system. */
export type TriState = boolean | null;

export interface PostureRow {
  id: Id;
  hostname: string;
  organizationId: Id;
  os: string;
  isOnline: boolean;
  pendingReboot: boolean;
  lastPatchDate: IsoDate | null;
  /** `null` when the device has not sent a posture report yet. */
  collectedAt: IsoDate | null;
  antivirusOk: TriState;
  firewallOk: TriState;
  encryptionOk: TriState;
  localAdmins: string[];
  vulnerabilities: number;
  knownExploited: number;
  criticalVulnerabilities: number;
}

export interface PostureOverview {
  total: number;
  antivirusIssues: number;
  firewallIssues: number;
  encryptionIssues: number;
  notReporting: number;
  withKnownExploited: number;
  items: PostureRow[];
}

/** `posture` payload, docs/PROTOCOL.md section 7.3. Every field is optional: agents and versions differ. */
export interface PostureData {
  collectedAt?: IsoDate;
  antivirus?: {
    name?: string;
    enabled?: boolean;
    upToDate?: boolean | null;
    signatureVersion?: string;
    source?: string;
  }[];
  firewall?: { enabled?: boolean | null; detail?: string };
  diskEncryption?: { volume?: string; method?: string; status?: string }[];
  localAdmins?: string[];
  screenLock?: { enabled?: boolean | null; timeoutSeconds?: number | null };
  lastPatchDate?: IsoDate | null;
  pendingReboot?: boolean;
  listeningPorts?: { protocol?: string; address?: string; port?: number; process?: string }[];
  unsupported?: string[];
}

export interface DevicePosture {
  collectedAt: IsoDate;
  antivirusOk: TriState;
  firewallOk: TriState;
  encryptionOk: TriState;
  localAdmins: string[];
  data: PostureData | null;
}

export interface DeviceVulnerability {
  cveId: string;
  softwareName: string;
  softwareVersion: string;
  severity: string;
  cvssScore: number | null;
  knownExploited: boolean;
  detectedAt: IsoDate;
}

export interface VulnerabilityRow {
  cveId: string;
  severity: string;
  cvssScore: number | null;
  knownExploited: boolean;
  devices: number;
  software: string | null;
  summary: string | null;
  published: IsoDate | null;
}

export interface VulnerabilityList extends Paged<VulnerabilityRow> {
  /** The server's own statement about how reliable the matches are. Always shown with the list. */
  note: string;
}

export interface VulnerabilityFilter {
  organizationId?: Id;
  severity?: string;
  knownExploited?: boolean;
  page?: number;
  pageSize?: number;
}

export interface FeedStatus {
  feeds: {
    name: string;
    lastSyncedAt: IsoDate | null;
    lastModifiedCursor: IsoDate | null;
    lastError: string | null;
    items: number;
  }[];
  cveCount: number;
  knownExploited: number;
}

export const securityApi = {
  posture: (organizationId?: Id) => api.get<PostureOverview>('/security/posture', { query: { organizationId } }),
  /** `null` until the device has reported. */
  devicePosture: (deviceId: Id) => api.get<DevicePosture | null>(`/devices/${deviceId}/posture`),
  deviceVulnerabilities: (deviceId: Id) => api.get<DeviceVulnerability[]>(`/devices/${deviceId}/vulnerabilities`),
  vulnerabilities: (filter: VulnerabilityFilter) =>
    api.get<VulnerabilityList>('/vulnerabilities', { query: { ...filter } }),
  feedStatus: () => api.get<FeedStatus>('/vulnerabilities/feed-status'),
  /** Asks devices to collect posture now. Needs `devices.manage`. */
  scan: (target: { deviceIds: Id[] } | { organizationId: Id }) =>
    api.post<{ jobId: Id; deviceCount: number }>('/security/scan', target),
};

export const securityKeys = {
  all: ['security'] as const,
  posture: (organizationId?: Id) => ['security', 'posture', organizationId ?? 'all'] as const,
  devicePosture: (deviceId: Id) => ['security', 'device-posture', deviceId] as const,
  deviceVulnerabilities: (deviceId: Id) => ['security', 'device-vulnerabilities', deviceId] as const,
  vulnerabilities: (filter: VulnerabilityFilter) => ['security', 'vulnerabilities', filter] as const,
  feedStatus: ['security', 'feed-status'] as const,
};
