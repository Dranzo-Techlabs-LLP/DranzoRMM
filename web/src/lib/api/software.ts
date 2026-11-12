import { api, buildUrl, CSRF_HEADER } from './client';
import { ApiError } from './errors';
import type { JobCreated, TargetRequest } from './jobs';
import type { Id, IsoDate, Paged } from './types';

/** Software inventory, package-manager deployment and custom packages (`SoftwareEndpoints.cs`). */

export interface DeviceSoftwareItem {
  name: string;
  version: string;
  publisher: string | null;
  source: string;
  packageId: string | null;
  installDate: IsoDate | null;
  seenAt: IsoDate;
}

export interface SoftwareSummary {
  name: string;
  publisher: string | null;
  devices: number;
  versions: number;
}

export interface SoftwareDevice {
  deviceId: Id;
  hostname: string;
  organizationId: Id;
  version: string;
  source: string;
}

export type PackageManager = 'winget' | 'brew' | 'apt' | 'dnf';
export type DeployAction = 'install' | 'uninstall';

export interface SoftwareDeployInput {
  action: DeployAction;
  name?: string;
  /** One package id per package manager; each device uses the entry for its own manager. */
  packages: Partial<Record<PackageManager, string>>;
  version?: string;
  target: TargetRequest;
}

export type PackageType = 'msi' | 'exe' | 'pkg' | 'dmg' | 'deb' | 'rpm';
export type DetectionType = 'file' | 'registry' | 'pkgutil' | 'dpkg' | 'rpm' | 'winget' | 'brew' | 'app';

export interface DetectionRule {
  type: DetectionType | (string & {});
  key: string;
  valueName?: string | null;
  minVersion?: string | null;
}

export interface PackageItem {
  id: Id;
  organizationId: Id | null;
  name: string;
  version: string;
  os: string;
  type: PackageType | (string & {});
  createdAt: IsoDate;
  fileName: string | null;
  sizeBytes: number | null;
  sha256: string | null;
  installArgs: string[] | null;
  uninstallCommand: string[] | null;
  detection: DetectionRule | null;
}

export interface PackageInput {
  name: string;
  version?: string;
  type: PackageType;
  blobId: Id;
  installArgs?: string[];
  uninstallCommand?: string[];
  detection?: DetectionRule;
  organizationId?: Id | null;
}

export interface UploadedBlob {
  blobId: Id;
  /** Computed by the server from the bytes it received. */
  sha256: string;
  sizeBytes: number;
}

export interface SoftwareListFilter {
  organizationId?: Id;
  search?: string;
  page?: number;
  pageSize?: number;
}

export interface UploadOptions {
  onProgress?: (fraction: number) => void;
  signal?: AbortSignal;
  /** Test seam. */
  createRequest?: () => XMLHttpRequest;
}

function parseUploadError(xhr: XMLHttpRequest): ApiError {
  let code = xhr.status >= 500 ? 'server_error' : 'error';
  let message =
    xhr.status === 413
      ? 'The file is larger than the server allows.'
      : xhr.status === 403
        ? 'You do not have permission to upload packages.'
        : xhr.status === 401
          ? 'Your session has ended. Sign in again and retry the upload.'
          : `Upload failed (${xhr.status}).`;
  try {
    const body: unknown = JSON.parse(xhr.responseText);
    if (typeof body === 'object' && body !== null) {
      const b = body as Record<string, unknown>;
      if (typeof b.error === 'string') {
        code = b.error;
      }
      if (typeof b.message === 'string') {
        message = b.message;
      }
    }
  } catch {
    // Not JSON (for example a proxy error page): keep the generic message.
  }
  return new ApiError(xhr.status, code, message);
}

/**
 * Step 1 of adding a package: `PUT /packages/upload?fileName=` with the file as the raw request body.
 * `fetch` cannot report upload progress, so this one call uses XMLHttpRequest with the same cookie session and
 * CSRF header as the API client.
 */
export function uploadPackageFile(file: File, options: UploadOptions = {}): Promise<UploadedBlob> {
  return new Promise<UploadedBlob>((resolve, reject) => {
    const xhr = options.createRequest ? options.createRequest() : new XMLHttpRequest();
    xhr.open('PUT', buildUrl('/packages/upload', { fileName: file.name }));
    xhr.setRequestHeader('Accept', 'application/json');
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    const csrf = api.getCsrfToken();
    if (csrf) {
      xhr.setRequestHeader(CSRF_HEADER, csrf);
    }
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && e.total > 0) {
        options.onProgress?.(e.loaded / e.total);
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText) as UploadedBlob);
        } catch {
          reject(new ApiError(xhr.status, 'bad_response', 'The server sent an unreadable answer to the upload.'));
        }
      } else {
        reject(parseUploadError(xhr));
      }
    };
    xhr.onerror = () => {
      reject(new ApiError(0, 'network', 'The upload was interrupted. Check your connection and try again.'));
    };
    xhr.onabort = () => {
      reject(new ApiError(0, 'upload_cancelled', 'Upload cancelled.'));
    };
    options.signal?.addEventListener('abort', () => {
      xhr.abort();
    });
    xhr.send(file);
  });
}

export const softwareApi = {
  forDevice: (deviceId: Id, search?: string, signal?: AbortSignal) =>
    api.get<DeviceSoftwareItem[]>(`/devices/${deviceId}/software`, { query: { search }, signal }),
  list: (filter: SoftwareListFilter, signal?: AbortSignal) =>
    api.get<Paged<SoftwareSummary>>('/software', { query: { ...filter }, signal }),
  devicesWith: (name: string, organizationId?: Id) =>
    api.get<SoftwareDevice[]>('/software/devices', { query: { name, organizationId } }),
  deploy: (input: SoftwareDeployInput) => api.post<JobCreated>('/software/deploy', input),
};

export const packagesApi = {
  list: () => api.get<PackageItem[]>('/packages'),
  upload: uploadPackageFile,
  create: (input: PackageInput) => api.post<{ id: Id }>('/packages', input),
  remove: (id: Id) => api.delete(`/packages/${id}`),
  deploy: (id: Id, action: DeployAction, target: TargetRequest) =>
    api.post<JobCreated>(`/packages/${id}/deploy`, { action, target }),
};

export const softwareKeys = {
  all: ['software'] as const,
  list: (filter: SoftwareListFilter) => ['software', 'list', filter] as const,
  devicesWith: (name: string, organizationId?: Id | null) =>
    ['software', 'devices-with', name, organizationId ?? 'all'] as const,
  device: (deviceId: Id, search: string) => ['software', 'device', deviceId, search] as const,
  deviceAll: (deviceId: Id) => ['software', 'device', deviceId] as const,
  packages: ['packages'] as const,
};
