import { api } from './client';
import type { Id, IsoDate } from './types';
import { uploadRaw, type RawUploadOptions } from './upload';

/** Agent releases and rollout (`server/src/Dranzo.Api/Features/ReleaseEndpoints.cs`). Partner-wide. */

export type ReleaseRing = 'none' | 'test' | 'pilot' | 'all';
export const RELEASE_RINGS: readonly ReleaseRing[] = ['none', 'test', 'pilot', 'all'];

export type ReleaseOs = 'windows' | 'macos' | 'linux';
export type ReleaseArch = 'amd64' | 'arm64';
/** `binary` is the agent executable used for self-update; the others are installer packages for enrollment. */
export type ReleaseFileKind = 'binary' | 'msi' | 'pkg' | 'deb' | 'rpm';

export interface ReleaseBinary {
  id: Id;
  os: ReleaseOs | (string & {});
  arch: ReleaseArch | (string & {});
  kind: ReleaseFileKind | (string & {});
  sha256: string;
  sizeBytes: number;
  keyId: string;
}

export interface AgentRelease {
  id: Id;
  version: string;
  notes: string;
  ring: ReleaseRing | (string & {});
  paused: boolean;
  createdAt: IsoDate;
  binaries: ReleaseBinary[];
  /** Device update state → number of devices (`offered`, `downloading`, `installed`, `rolled_back`, ...). */
  progress: Record<string, number>;
}

export interface ReleaseList {
  installedVersions: { version: string; devices: number }[];
  items: AgentRelease[];
}

export interface UploadedReleaseFile {
  blobId: Id;
  sha256: string;
  sizeBytes: number;
}

export interface ReleaseDeviceState {
  deviceId: Id;
  hostname: string | null;
  currentVersion: string | null;
  state: string;
  error: string | null;
  offeredAt: IsoDate;
  updatedAt: IsoDate;
}

export interface ReleaseFileInput {
  os: ReleaseOs;
  arch: ReleaseArch;
  blobId: Id;
  /** Omit for the agent binary. */
  kind?: Exclude<ReleaseFileKind, 'binary'>;
}

// Every write here needs a fresh authenticator code; the API client (and `uploadRaw`) ask for it.
export const releasesApi = {
  list: () => api.get<ReleaseList>('/releases'),
  upload: (file: File, options: RawUploadOptions = {}) =>
    uploadRaw<UploadedReleaseFile>('/releases/upload', file, { ...options, query: { fileName: file.name } }),
  create: (input: { version: string; notes: string; binaries: ReleaseFileInput[] }) =>
    api.post<{ id: Id }>('/releases', input),
  rollout: (id: Id, input: { ring?: ReleaseRing; paused?: boolean }) => api.post(`/releases/${id}/rollout`, input),
  devices: (id: Id) => api.get<ReleaseDeviceState[]>(`/releases/${id}/devices`),
};

export const releaseKeys = {
  list: ['releases'] as const,
  devices: (id: Id) => ['releases', id, 'devices'] as const,
};
