import { api } from './client';
import type { Id, IsoDate, Paged } from './types';

/** Jobs, runs, schedules and saved filters (`server/src/Dranzo.Api/Features/JobEndpoints.cs`). */

/** Server `DeviceFilter`: the same fields as the device list filter. */
export interface DeviceFilterSpec {
  organizationId?: Id | null;
  siteId?: Id | null;
  groupId?: Id | null;
  os?: string | null;
  online?: boolean | null;
  search?: string | null;
  tag?: string | null;
}

/**
 * Server `TargetRequest`. The server reads the first field that is set, in this order:
 * deviceIds, groupId, siteId, savedFilterId, filter, organizationId.
 */
export interface TargetRequest {
  deviceIds?: Id[];
  groupId?: Id;
  siteId?: Id;
  organizationId?: Id;
  savedFilterId?: Id;
  filter?: DeviceFilterSpec;
}

export interface TargetPreview {
  deviceCount: number;
  /** The server will ask for the authenticator code before it starts a job on this target. */
  stepUpRequired: boolean;
  byOs: Record<string, number>;
  online: number;
}

export type RunAs = 'system' | 'user';

export interface RunScriptInput {
  scriptId: Id;
  version?: number;
  target: TargetRequest;
  parameters?: Record<string, string | number | boolean>;
  runAs?: RunAs;
  timeoutSeconds?: number;
  maxOutputBytes?: number;
  maxParallel?: number;
  schedule?: { cron: string; timeZone?: string };
  name?: string;
}

export interface JobCreated {
  jobId: Id;
  deviceCount: number;
  nextRunAt?: IsoDate | null;
}

export type RunStatus =
  | 'pending'
  | 'dispatched'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'timedout'
  | 'cancelled'
  | 'rejected'
  | 'unsupported'
  | 'expired';

export const ACTIVE_RUN_STATUSES: readonly string[] = ['pending', 'dispatched', 'running'];

export function isActiveRun(status: string): boolean {
  return ACTIVE_RUN_STATUSES.includes(status);
}

export interface JobListItem {
  id: Id;
  name: string;
  kind: string;
  organizationId: Id | null;
  requestedByName: string;
  createdAt: IsoDate;
  cron: string | null;
  timeZone: string | null;
  nextRunAt: IsoDate | null;
  enabled: boolean;
  scriptId: Id | null;
  scriptVersion: number | null;
  isSystem: boolean;
  total: number;
  succeeded: number;
  failed: number;
  active: number;
  lastRunAt: IsoDate;
}

export interface JobRunRow {
  id: Id;
  deviceId: Id;
  hostname: string;
  os: string;
  status: RunStatus | (string & {});
  exitCode: number | null;
  message: string | null;
  createdAt: IsoDate;
  startedAt: IsoDate | null;
  finishedAt: IsoDate | null;
  truncated: boolean;
  attempt: number;
  batchId: Id;
}

export interface JobDetail {
  id: Id;
  name: string;
  kind: string;
  organizationId: Id | null;
  requestedByName: string;
  createdAt: IsoDate;
  cron: string | null;
  timeZone: string | null;
  nextRunAt: IsoDate | null;
  enabled: boolean;
  scriptId: Id | null;
  scriptVersion: number | null;
  timeoutSeconds: number;
  maxOutputBytes: number;
  contentSha256: string;
  isSystem: boolean;
  runs: JobRunRow[];
}

export interface RunListItem {
  id: Id;
  jobId: Id;
  jobName: string;
  kind: string;
  deviceId: Id;
  hostname: string;
  status: RunStatus | (string & {});
  exitCode: number | null;
  message: string | null;
  createdAt: IsoDate;
  startedAt: IsoDate | null;
  finishedAt: IsoDate | null;
  truncated: boolean;
  requestedBy: string;
  attempt: number;
}

export interface OutputChunk {
  seq: number;
  stream: 'stdout' | 'stderr' | (string & {});
  data: string;
}

export interface RunDetail extends RunListItem {
  dispatchedAt: IsoDate | null;
  outputBytes: number;
  outputSha256: string | null;
  maxAttempts: number;
  result: unknown;
  output: OutputChunk[];
}

export interface Schedule {
  id: Id;
  name: string;
  kind: string;
  organizationId: Id | null;
  cron: string;
  timeZone: string | null;
  nextRunAt: IsoDate | null;
  enabled: boolean;
  requestedByName: string;
  createdAt: IsoDate;
  scriptId: Id | null;
  /** JSON text of the stored target (`JobTarget`). */
  targetJson: string;
}

export interface SavedFilter {
  id: Id;
  name: string;
  organizationId: Id | null;
  filter: DeviceFilterSpec;
}

export interface JobListFilter {
  deviceId?: Id;
  kind?: string;
  scheduled?: boolean;
  page?: number;
  pageSize?: number;
}

export interface RunListFilter {
  deviceId?: Id;
  jobId?: Id;
  status?: string;
  kind?: string;
  page?: number;
  pageSize?: number;
}

export const jobsApi = {
  previewTarget: (target: TargetRequest, signal?: AbortSignal) =>
    api.post<TargetPreview>('/jobs/preview-target', target, { signal }),
  /** Wide or scheduled runs are answered `401 step_up_required`; the API client asks for the code and retries. */
  runScript: (input: RunScriptInput) => api.post<JobCreated>('/jobs/run-script', input),
  list: (filter: JobListFilter) => api.get<Paged<JobListItem>>('/jobs', { query: { ...filter } }),
  get: (id: Id) => api.get<JobDetail>(`/jobs/${id}`),
  cancel: (id: Id) => api.post<{ cancelled: number }>(`/jobs/${id}/cancel`),
  schedules: () => api.get<Schedule[]>('/schedules'),
  setScheduleEnabled: (id: Id, enabled: boolean) => api.patch(`/jobs/${id}`, { enabled }),
  /** Stops the schedule; run history stays. */
  removeSchedule: (id: Id) => api.delete(`/jobs/${id}`),
};

export const runsApi = {
  list: (filter: RunListFilter) => api.get<Paged<RunListItem>>('/runs', { query: { ...filter } }),
  get: (id: Id) => api.get<RunDetail>(`/runs/${id}`),
  cancel: (id: Id) => api.post(`/runs/${id}/cancel`),
};

export const savedFiltersApi = {
  list: () => api.get<SavedFilter[]>('/saved-filters'),
  create: (input: { name: string; organizationId?: Id; filter: DeviceFilterSpec }) =>
    api.post<{ id: Id }>('/saved-filters', input),
  remove: (id: Id) => api.delete(`/saved-filters/${id}`),
};

export const jobKeys = {
  all: ['jobs'] as const,
  lists: ['jobs', 'list'] as const,
  list: (filter: JobListFilter) => ['jobs', 'list', filter] as const,
  detail: (id: Id) => ['jobs', 'detail', id] as const,
  schedules: ['jobs', 'schedules'] as const,
  preview: (target: TargetRequest) => ['jobs', 'preview', target] as const,
  runs: ['runs'] as const,
  runList: (filter: RunListFilter) => ['runs', 'list', filter] as const,
  run: (id: Id) => ['runs', 'detail', id] as const,
  savedFilters: ['saved-filters'] as const,
};
