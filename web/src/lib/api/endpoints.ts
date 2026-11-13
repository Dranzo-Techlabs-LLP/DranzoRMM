import { api, buildUrl } from './client';
import type {
  AgentInstallers,
  AssignmentInput,
  AuditEvent,
  AuditFilter,
  AuditVerification,
  Created,
  DeviceDetail,
  DeviceGroup,
  DeviceListFilter,
  DevicePage,
  DeviceUpdateInput,
  EnrollmentTargets,
  EnrollmentToken,
  EnrollmentTokenCreated,
  EnrollmentTokenInput,
  EnrollStartResponse,
  EnrollVerifyResponse,
  Id,
  InstallInfo,
  LoginResponse,
  Me,
  MfaVerifyResponse,
  Organization,
  OrganizationInput,
  OverviewSummary,
  Paged,
  PermissionCatalog,
  Role,
  Site,
  UpdateRing,
  User,
} from './types';

/** One function per server endpoint. Paths mirror `server/src/Dranzo.Api/Features`. */

export const authApi = {
  login: (email: string, password: string) =>
    api.post<LoginResponse>('/auth/login', { email, password }, { anonymous: true }),
  enrollStart: (challengeToken: string) =>
    api.post<EnrollStartResponse>('/auth/mfa/enroll/start', { challengeToken }, { anonymous: true }),
  enrollVerify: (challengeToken: string, code: string) =>
    api.post<EnrollVerifyResponse>('/auth/mfa/enroll/verify', { challengeToken, code }, { anonymous: true }),
  mfaVerify: (challengeToken: string, by: { code: string } | { recoveryCode: string }) =>
    api.post<MfaVerifyResponse>('/auth/mfa/verify', { challengeToken, ...by }, { anonymous: true }),
  me: () => api.get<Me>('/auth/me', { anonymous: true }),
  logout: () => api.post('/auth/logout'),
  stepUp: (code: string) => api.post<{ status: 'ok' }>('/auth/step-up', { code }, { noStepUp: true }),
  changePassword: (currentPassword: string, newPassword: string) =>
    api.post('/auth/password', { currentPassword, newPassword }),
  permissions: () => api.get<PermissionCatalog>('/auth/permissions'),
  /** Replaces the user's recovery codes. Needs a fresh authenticator code (the client asks for it). */
  regenerateRecoveryCodes: () => api.post<{ recoveryCodes: string[] }>('/auth/recovery-codes'),
  /** Time-zone ids the server accepts for organizations and schedules. */
  timeZones: () => api.get<string[]>('/auth/time-zones'),
};

export const organizationsApi = {
  list: () => api.get<Organization[]>('/organizations'),
  create: (input: OrganizationInput) => api.post<Created>('/organizations', input),
  update: (id: Id, input: OrganizationInput) => api.patch(`/organizations/${id}`, input),
  remove: (id: Id) => api.delete(`/organizations/${id}`),
};

export const sitesApi = {
  list: (organizationId?: Id) => api.get<Site[]>('/sites', { query: { organizationId } }),
  create: (organizationId: Id, name: string) => api.post<Created>('/sites', { organizationId, name }),
  rename: (id: Id, name: string) => api.patch(`/sites/${id}`, { name }),
  remove: (id: Id) => api.delete(`/sites/${id}`),
};

export const groupsApi = {
  list: (filter: { organizationId?: Id; siteId?: Id } = {}) => api.get<DeviceGroup[]>('/groups', { query: filter }),
  create: (siteId: Id, name: string, updateRing: UpdateRing) =>
    api.post<Created>('/groups', { siteId, name, updateRing }),
  update: (id: Id, input: { name?: string; updateRing?: UpdateRing }) => api.patch(`/groups/${id}`, input),
  remove: (id: Id) => api.delete(`/groups/${id}`),
};

export const usersApi = {
  list: () => api.get<User[]>('/users'),
  create: (input: { email: string; displayName: string; password: string }) =>
    api.post<{ id: Id; email: string }>('/users', input),
  update: (id: Id, input: { displayName?: string; disabled?: boolean }) => api.patch(`/users/${id}`, input),
  resetMfa: (id: Id) => api.post(`/users/${id}/reset-mfa`),
  /** Clears a lockout caused by failed sign-ins. */
  unlock: (id: Id) => api.post(`/users/${id}/unlock`),
  /** Sets a temporary password: the user is signed out everywhere and must change it at next sign-in. */
  resetPassword: (id: Id, password: string) => api.post(`/users/${id}/reset-password`, { password }),
  remove: (id: Id) => api.delete(`/users/${id}`),
};

export const rolesApi = {
  list: () => api.get<Role[]>('/roles'),
  create: (input: { name: string; permissions: string[] }) => api.post<Created>('/roles', input),
  update: (id: Id, input: { name?: string; permissions?: string[] }) => api.patch(`/roles/${id}`, input),
  remove: (id: Id) => api.delete(`/roles/${id}`),
  assign: (input: AssignmentInput) => api.post<{ id: Id }>('/role-assignments', input),
  unassign: (assignmentId: Id) => api.delete(`/role-assignments/${assignmentId}`),
};

export const enrollmentApi = {
  listTokens: (organizationId?: Id) => api.get<EnrollmentToken[]>('/enrollment-tokens', { query: { organizationId } }),
  createToken: (input: EnrollmentTokenInput) => api.post<EnrollmentTokenCreated>('/enrollment-tokens', input),
  revokeToken: (id: Id) => api.delete(`/enrollment-tokens/${id}`),
  installInfo: () => api.get<InstallInfo>('/agent/install-info'),
  targets: () => api.get<EnrollmentTargets>('/enrollment-tokens/targets'),
  installers: () => api.get<AgentInstallers>('/agent/installers'),
};

export const devicesApi = {
  list: (filter: DeviceListFilter, signal?: AbortSignal) =>
    api.get<DevicePage>('/devices', { query: { ...filter }, signal }),
  get: (id: Id) => api.get<DeviceDetail>(`/devices/${id}`),
  update: (id: Id, input: DeviceUpdateInput) => api.patch(`/devices/${id}`, input),
  revoke: (id: Id) => api.post(`/devices/${id}/revoke`),
  remove: (id: Id) => api.delete(`/devices/${id}`),
  /** Sets (8 to 64 characters) or clears (`null`) the code needed to uninstall the agent locally. Needs step-up. */
  setUninstallCode: (id: Id, code: string | null) => api.post<{ jobId: Id }>(`/devices/${id}/uninstall-code`, { code }),
  /** Asks the agent to remove itself; the device is revoked once it confirms. Needs step-up. */
  uninstallAgent: (id: Id) => api.post<{ jobId: Id }>(`/devices/${id}/uninstall-agent`),
  /** Cuts the device off the network except DranzoRMM (and remote desktop). Needs devices.isolate and step-up. */
  isolate: (id: Id, input: { reason: string; message?: string }) =>
    api.post<{ jobId: Id }>(`/devices/${id}/isolate`, input),
  release: (id: Id, input: { reason?: string; message?: string }) =>
    api.post<{ jobId: Id }>(`/devices/${id}/release`, input),
  reboot: (id: Id, input: { delaySeconds: number; message?: string; notifyUser: boolean }) =>
    api.post<{ jobId: Id }>(`/devices/${id}/reboot`, input),
  overview: (organizationId?: Id, signal?: AbortSignal) =>
    api.get<OverviewSummary>('/overview', { query: { organizationId }, signal }),
};

export const auditApi = {
  list: (filter: AuditFilter) => api.get<Paged<AuditEvent>>('/audit', { query: { ...filter } }),
  verify: () => api.get<AuditVerification>('/audit/verify'),
  /** Same-origin download link; the browser sends the session cookie itself. Filters match the list. */
  exportUrl: (filter: AuditFilter) => {
    const query: AuditFilter = { ...filter };
    delete query.page;
    delete query.pageSize;
    return buildUrl('/audit/export.csv', { ...query });
  },
};
