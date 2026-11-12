import { api } from './client';
import type { Id, IsoDate, ScopeType } from './types';

/** Desired-state policies and compliance (`server/src/Dranzo.Api/Features/PolicyEndpoints.cs`). */

export interface PolicyAssignment {
  id: Id;
  scopeType: ScopeType;
  scopeId: Id | null;
}

export interface Policy {
  id: Id;
  name: string;
  description: string | null;
  check: string;
  /** Empty = every operating system the check exists on. */
  osTargets: string[];
  remediate: boolean;
  enabled: boolean;
  intervalMinutes: number;
  /** `null` = shared with every organization. */
  organizationId: Id | null;
  params: Record<string, unknown>;
  assignments: PolicyAssignment[];
}

export interface PolicyList {
  /** Check id → operating systems it exists on. The only checks the server accepts. */
  checks: Record<string, string[]>;
  items: Policy[];
}

export interface PolicyInput {
  name?: string;
  description?: string;
  /** Only read by the server when creating. */
  check?: string;
  params?: Record<string, unknown>;
  osTargets?: string[];
  remediate?: boolean;
  enabled?: boolean;
  intervalMinutes?: number;
  /** Only read by the server when creating. */
  organizationId?: Id | null;
}

export interface PolicyCompliance {
  policyId: Id;
  name: string | null;
  check: string | null;
  compliant: number;
  nonCompliant: number;
  unsupported: number;
  remediated: number;
}

export interface NonCompliantRow {
  policyId: Id;
  policy: string | null;
  deviceId: Id;
  hostname: string;
  organizationId: Id;
  detail: string | null;
  evaluatedAt: IsoDate;
  nonCompliantSince: IsoDate | null;
}

export interface ComplianceSummary {
  /** Devices that have reported at least one result. */
  devices: number;
  compliantDevices: number;
  policies: PolicyCompliance[];
  nonCompliant: NonCompliantRow[];
}

export interface DeviceComplianceRow {
  policyId: Id;
  policy: string | null;
  check: string | null;
  compliant: boolean;
  remediated: boolean;
  /** `false` when the check does not exist on the device's operating system. */
  supported: boolean | null;
  detail: string | null;
  evaluatedAt: IsoDate;
  nonCompliantSince: IsoDate | null;
}

export type EvaluateTarget = { deviceIds: Id[] } | { organizationId: Id } | { siteId: Id } | { groupId: Id };

export const policiesApi = {
  list: () => api.get<PolicyList>('/policies'),
  // Script policies need a fresh authenticator code on create and on every change; the API client asks for it.
  create: (input: PolicyInput) => api.post<{ id: Id }>('/policies', input),
  update: (id: Id, input: PolicyInput) => api.patch(`/policies/${id}`, input),
  remove: (id: Id) => api.delete(`/policies/${id}`),
  assign: (id: Id, scopeType: ScopeType, scopeId: Id | null) =>
    api.post<{ id: Id }>(`/policies/${id}/assignments`, { scopeType, scopeId }),
  unassign: (id: Id, assignmentId: Id) => api.delete(`/policies/${id}/assignments/${assignmentId}`),
  /** Runs every applicable policy now on the online devices of the target. */
  evaluate: (target: EvaluateTarget) => api.post<{ deviceCount: number }>('/policies/evaluate', target),
  compliance: (organizationId?: Id) => api.get<ComplianceSummary>('/compliance', { query: { organizationId } }),
  deviceCompliance: (deviceId: Id) => api.get<DeviceComplianceRow[]>(`/devices/${deviceId}/compliance`),
};

export const policyKeys = {
  list: ['policies'] as const,
  complianceAll: ['compliance'] as const,
  compliance: (organizationId?: Id) => ['compliance', organizationId ?? 'all'] as const,
  deviceCompliance: (deviceId: Id) => ['compliance', 'device', deviceId] as const,
};
