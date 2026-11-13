import { api } from './client';
import type { Id } from './types';

/** Access review (`server/src/Dranzo.Api/Features/AccessReviewEndpoints.cs`). */

export interface AccessGrant {
  role: string;
  /** Partner, Organization, Site or Group. */
  scope: string;
  scopeName: string;
}

export interface AccessPrincipal {
  kind: 'user' | 'apikey';
  id: Id;
  name: string;
  email: string | null;
  disabled: boolean;
  locked: boolean;
  /** Null for API keys. */
  mfaEnabled: boolean | null;
  lastActiveAt: string | null;
  expiresAt: string | null;
  grants: AccessGrant[];
  permissions: string[];
  findings: string[];
}

export interface AccessReview {
  generatedAt: string;
  totalPermissions: number;
  principals: AccessPrincipal[];
}

export const accessApi = {
  review: () => api.get<AccessReview>('/access-review'),
};

export const accessKeys = { review: ['access-review'] as const };
