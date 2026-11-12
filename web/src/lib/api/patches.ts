import { api } from './client';
import type { JobCreated, TargetRequest } from './jobs';
import type { Id, IsoDate } from './types';

/** Patch catalog, per-device updates, compliance and patch policies (`PatchEndpoints.cs`). */

export const PATCH_SOURCES = ['wua', 'softwareupdate', 'apt', 'dnf', 'winget', 'brew'] as const;
export type PatchSource = (typeof PATCH_SOURCES)[number];

export const PATCH_SEVERITIES = ['critical', 'important', 'moderate', 'low', 'unspecified'] as const;
export type PatchSeverity = (typeof PATCH_SEVERITIES)[number];

export const REBOOT_MODES = ['never', 'if_required', 'force'] as const;
export type RebootMode = (typeof REBOOT_MODES)[number];

export type PatchStatus = 'pending' | 'approved' | 'rejected' | 'deferred' | 'installed' | 'failed';
/** Statuses a technician can set (`POST /patches/approve`). */
export type PatchDecision = 'approved' | 'rejected' | 'deferred' | 'pending';

export interface PatchCatalogRow {
  /** Catalog entry id. */
  id: Id;
  title: string;
  kb: string | null;
  source: PatchSource | (string & {});
  severity: PatchSeverity | (string & {});
  category: string;
  firstSeenAt: IsoDate;
  devices: number;
  pending: number;
  approved: number;
  failed: number;
  rejected: number;
}

export interface PatchCatalogFilter {
  organizationId?: Id;
  status?: string;
  severity?: string;
  source?: string;
}

export interface DevicePatchItem {
  id: Id;
  title: string;
  kb: string | null;
  source: string;
  severity: string;
  category: string;
  status: PatchStatus | (string & {});
  currentVersion: string | null;
  newVersion: string | null;
  requiresReboot: boolean;
  firstSeenAt: IsoDate;
  installedAt: IsoDate | null;
  error: string | null;
}

export interface DevicePatches {
  lastPatchScanAt: IsoDate | null;
  lastPatchInstallAt: IsoDate | null;
  pendingReboot: boolean;
  items: DevicePatchItem[];
}

export type ComplianceState = 'patched' | 'unpatched' | 'unknown';

export interface ComplianceRow {
  id: Id;
  hostname: string;
  organizationId: Id;
  os: string;
  isOnline: boolean;
  lastPatchScanAt: IsoDate | null;
  lastPatchInstallAt: IsoDate | null;
  pendingReboot: boolean;
  missing: number;
  /** Missing updates rated critical or important. */
  missingCritical: number;
  failed: number;
  state: ComplianceState | (string & {});
}

export interface Compliance {
  total: number;
  patched: number;
  unpatched: number;
  unknown: number;
  items: ComplianceRow[];
}

export interface RebootOptions {
  mode?: RebootMode;
  notifyUser?: boolean;
  deferrals?: number;
  deadlineMinutes?: number;
  message?: string;
}

export interface PatchPolicy {
  id: Id;
  organizationId: Id | null;
  name: string;
  enabled: boolean;
  autoApproveSeverities: string[];
  autoApproveCategories: string[];
  sources: string[];
  deferDays: number;
  windowCron: string | null;
  windowMinutes: number;
  rebootMode: RebootMode | (string & {});
  rebootNotifyUser: boolean;
  rebootDeferrals: number;
  rebootDeadlineMinutes: number;
  nextWindowAt: IsoDate | null;
  createdAt: IsoDate;
}

export interface PatchPolicyInput {
  name?: string;
  organizationId?: Id | null;
  enabled?: boolean;
  autoApproveSeverities?: string[];
  autoApproveCategories?: string[];
  sources?: string[];
  deferDays?: number;
  /** Empty string clears the maintenance window. */
  windowCron?: string;
  windowMinutes?: number;
  rebootMode?: string;
  rebootNotifyUser?: boolean;
  rebootDeferrals?: number;
  rebootDeadlineMinutes?: number;
}

export const patchesApi = {
  catalog: (filter: PatchCatalogFilter) => api.get<PatchCatalogRow[]>('/patches', { query: { ...filter } }),
  forDevice: (deviceId: Id) => api.get<DevicePatches>(`/devices/${deviceId}/patches`),
  compliance: (organizationId?: Id) => api.get<Compliance>('/patches/compliance', { query: { organizationId } }),
  decide: (input: { catalogEntryIds: Id[]; status: PatchDecision; organizationId?: Id; deviceIds?: Id[] }) =>
    api.post<{ updated: number }>('/patches/approve', input),
  scan: (target: TargetRequest) => api.post<JobCreated>('/patches/scan', target),
  install: (input: { target: TargetRequest; catalogEntryIds?: Id[]; reboot?: RebootOptions }) =>
    api.post<JobCreated>('/patches/install', input),
  rebootDevice: (deviceId: Id, input: { delaySeconds?: number; message?: string; notifyUser?: boolean }) =>
    api.post<{ jobId: Id }>(`/devices/${deviceId}/reboot`, input),
};

export const patchPoliciesApi = {
  list: () => api.get<PatchPolicy[]>('/patch-policies'),
  create: (input: PatchPolicyInput) => api.post<{ id: Id }>('/patch-policies', input),
  update: (id: Id, input: PatchPolicyInput) => api.patch(`/patch-policies/${id}`, input),
  remove: (id: Id) => api.delete(`/patch-policies/${id}`),
};

export const patchKeys = {
  all: ['patches'] as const,
  catalog: (filter: PatchCatalogFilter) => ['patches', 'catalog', filter] as const,
  device: (deviceId: Id) => ['patches', 'device', deviceId] as const,
  compliance: (organizationId?: Id | null) => ['patches', 'compliance', organizationId ?? 'all'] as const,
  policies: ['patch-policies'] as const,
};
