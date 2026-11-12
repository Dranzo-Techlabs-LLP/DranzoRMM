import { api, buildUrl } from './client';
import type { ConsentMode, Id, IsoDate, Paged } from './types';
import { uploadRaw, type RawUploadOptions } from './upload';

/** Remote support sessions (`server/src/Dranzo.Api/Features/RemoteEndpoints.cs`, `RemoteSessions.cs`). */

export type SessionKind = 'terminal' | 'files' | 'desktop';
export const SESSION_KINDS: readonly SessionKind[] = ['terminal', 'files', 'desktop'];

/** States as the live hub reports them (docs/PROTOCOL.md section 6.5). */
export type SessionStateName = 'requested' | 'pending_consent' | 'active' | 'ended' | 'denied' | 'failed';

export const OPEN_SESSION_STATES: readonly SessionStateName[] = ['requested', 'pending_consent', 'active'];

/**
 * REST answers spell the consent state `pendingconsent` (the enum name lower-cased); the hub sends
 * `pending_consent`. Returns `null` for anything that is not a session state.
 */
export function normalizeSessionState(value: unknown): SessionStateName | null {
  if (typeof value !== 'string') {
    return null;
  }
  const v = value.toLowerCase().replace(/[^a-z]/g, '');
  switch (v) {
    case 'requested':
    case 'active':
    case 'ended':
    case 'denied':
    case 'failed':
      return v;
    case 'pendingconsent':
      return 'pending_consent';
    default:
      return null;
  }
}

export interface SessionCreated {
  sessionId: Id;
  state: string;
  consent: ConsentMode;
}

export interface RemoteSession {
  id: Id;
  deviceId: Id;
  hostname: string;
  organizationId: Id;
  userId: Id;
  userName: string;
  kind: SessionKind | (string & {});
  consent: ConsentMode | (string & {});
  /** Raw server spelling; use {@link normalizeSessionState}. */
  state: string;
  consentResult: string | null;
  endReason: string | null;
  requestedAt: IsoDate;
  startedAt: IsoDate | null;
  endedAt: IsoDate | null;
  ip?: string | null;
  bytesIn: number;
  bytesOut: number;
}

export interface RemoteSessionDetail extends RemoteSession {
  inputSha256: string | null;
  /** The caller started this session. */
  mine: boolean;
}

export interface SessionFilter {
  deviceId?: Id;
  organizationId?: Id;
  /** Server enum name, case-insensitive: `requested`, `pendingconsent`, `active`, `ended`, `denied`, `failed`. */
  state?: string;
  page?: number;
  pageSize?: number;
}

export interface FileEntry {
  name: string;
  isDir: boolean;
  sizeBytes: number;
  modifiedAt: IsoDate | null;
  mode: string;
}

export interface FileListing {
  path: string;
  entries: FileEntry[];
  truncated: boolean;
}

export interface DownloadTicket {
  ticketId: Id;
  fileName: string;
  sha256: string | null;
}

export type TerminalRunAs = 'system' | 'user';

export const remoteApi = {
  // Starting any session needs a fresh authenticator code; the API client asks for it.
  startTerminal: (deviceId: Id, input: { cols: number; rows: number; runAs: TerminalRunAs }) =>
    api.post<SessionCreated>(`/devices/${deviceId}/sessions/terminal`, input),
  startFiles: (deviceId: Id) => api.post<SessionCreated>(`/devices/${deviceId}/sessions/files`),
  startDesktop: (deviceId: Id) => api.post<SessionCreated>(`/devices/${deviceId}/sessions/desktop`),
  list: (filter: SessionFilter, signal?: AbortSignal) =>
    api.get<Paged<RemoteSession>>('/sessions', { query: { ...filter }, signal }),
  get: (id: Id, signal?: AbortSignal) => api.get<RemoteSessionDetail>(`/sessions/${id}`, { signal }),
  end: (id: Id) => api.post(`/sessions/${id}/end`),
  listFiles: (sessionId: Id, path: string, signal?: AbortSignal) =>
    api.post<FileListing>(`/sessions/${sessionId}/files/list`, { path }, { signal }),
  /** Has the device send the file to the server; the content is then fetched with {@link remoteApi.contentUrl}. */
  prepareDownload: (sessionId: Id, path: string) =>
    api.post<DownloadTicket>(`/sessions/${sessionId}/files/download`, { path }),
  /** Same-origin link for a normal browser download; the server always answers with `attachment`. */
  contentUrl: (sessionId: Id, ticket: DownloadTicket) =>
    buildUrl(`/sessions/${sessionId}/files/content/${ticket.ticketId}`, { fileName: ticket.fileName }),
  uploadFile: (sessionId: Id, path: string, file: Blob, overwrite: boolean, options: RawUploadOptions = {}) =>
    uploadRaw<{ sizeBytes: number; sha256: string }>(`/sessions/${sessionId}/files/upload`, file, {
      ...options,
      query: { path, overwrite },
    }),
  /** A short-lived MeshCentral link. Keep it in memory only: it signs the technician in. */
  desktopUrl: (sessionId: Id) => api.get<{ url: string }>(`/sessions/${sessionId}/desktop-url`),
  installMeshAgent: (deviceId: Id) => api.post<{ jobId: Id }>(`/devices/${deviceId}/mesh/install`),
  /** Empty strings clear the values. Partner-wide `settings.manage` plus step-up. */
  setOrganizationMesh: (organizationId: Id, input: { meshUser: string; meshGroupId: string }) =>
    api.patch(`/organizations/${organizationId}/mesh`, input),
};

export const remoteKeys = {
  all: ['sessions'] as const,
  list: (filter: SessionFilter) => ['sessions', 'list', filter] as const,
  detail: (id: Id) => ['sessions', 'detail', id] as const,
};
