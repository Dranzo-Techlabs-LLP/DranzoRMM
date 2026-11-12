import { api } from './client';
import type { Id, IsoDate } from './types';

/** Scripts API (`server/src/Dranzo.Api/Features/ScriptEndpoints.cs`). */

export type ScriptLanguage = 'powershell' | 'cmd' | 'bash' | 'zsh' | 'sh' | 'python';
export type ScriptParameterType = 'string' | 'int' | 'bool';

export interface ScriptParameter {
  name: string;
  type: ScriptParameterType | (string & {});
  required: boolean;
  default: string | null;
}

export interface ScriptListItem {
  id: Id;
  /** `null` means shared with every organization of the partner. */
  organizationId: Id | null;
  name: string;
  description: string;
  language: ScriptLanguage | (string & {});
  osTargets: string[];
  currentVersion: number;
  updatedAt: IsoDate;
}

export interface ScriptVersionInfo {
  version: number;
  createdAt: IsoDate;
  createdByUserId: Id | null;
  changeNote: string | null;
  bodySha256: string;
}

export interface ScriptDetail extends ScriptListItem {
  createdAt: IsoDate;
  /** The version whose body and parameters are in this response. */
  version: number;
  body: string;
  bodySha256: string;
  parameters: ScriptParameter[] | null;
  versions: ScriptVersionInfo[];
}

export interface ScriptInput {
  name?: string;
  description?: string;
  language?: string;
  osTargets?: string[];
  body: string;
  parameters?: ScriptParameter[];
  organizationId?: Id | null;
  changeNote?: string;
}

export interface ScriptSaved {
  id: Id;
  version: number;
}

export const scriptsApi = {
  list: (organizationId?: Id) => api.get<ScriptListItem[]>('/scripts', { query: { organizationId } }),
  get: (id: Id, version?: number) => api.get<ScriptDetail>(`/scripts/${id}`, { query: { version } }),
  create: (input: ScriptInput) => api.post<ScriptSaved>('/scripts', input),
  /** Saving never overwrites: the server stores a new immutable version. */
  update: (id: Id, input: ScriptInput) => api.request<ScriptSaved>('PUT', `/scripts/${id}`, { body: input }),
  remove: (id: Id) => api.delete(`/scripts/${id}`),
};

export const scriptKeys = {
  all: ['scripts'] as const,
  list: (organizationId?: Id | null) => ['scripts', 'list', organizationId ?? 'all'] as const,
  detail: (id: Id, version?: number) => ['scripts', 'detail', id, version ?? 'current'] as const,
  detailAll: (id: Id) => ['scripts', 'detail', id] as const,
};
