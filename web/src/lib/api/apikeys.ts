import { api } from './client';
import type { Id, IsoDate, RoleAssignment } from './types';

/** API keys (`server/src/Dranzo.Api/Features/ApiKeyEndpoints.cs`). Partner-wide. */

export interface ApiKey {
  id: Id;
  name: string;
  createdAt: IsoDate;
  expiresAt: IsoDate | null;
  revokedAt: IsoDate | null;
  lastUsedAt: IsoDate | null;
  /** First characters of the key, for recognising it. The key itself is never returned again. */
  prefix: string;
  assignments: RoleAssignment[];
}

export interface ApiKeyCreated {
  id: Id;
  /** The secret. Returned exactly once; only its hash is stored. */
  key: string;
  expiresAt: IsoDate;
}

export const apiKeysApi = {
  list: () => api.get<ApiKey[]>('/api-keys'),
  // Creating and revoking need a fresh authenticator code; the API client asks for it.
  create: (input: { name: string; expiresInDays: number }) => api.post<ApiKeyCreated>('/api-keys', input),
  revoke: (id: Id) => api.delete(`/api-keys/${id}`),
};

export const apiKeyKeys = { list: ['api-keys'] as const };
