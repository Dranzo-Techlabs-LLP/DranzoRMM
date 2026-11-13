/**
 * Request/response shapes of the dashboard API. The contract is the server source
 * (`server/src/Dranzo.Api/Features/*Endpoints.cs`); JSON is camelCase, ids are GUID strings, times are ISO 8601.
 */

export type Id = string;
export type IsoDate = string;

export interface Paged<T> {
  total: number;
  page: number;
  pageSize: number;
  items: T[];
}

// ----- Auth -----

export type ScopeType = 'Partner' | 'Organization' | 'Site' | 'Group';
export const SCOPE_TYPES: readonly ScopeType[] = ['Partner', 'Organization', 'Site', 'Group'];

export interface LoginResponse {
  status: 'mfa_required' | 'mfa_enrollment_required';
  challengeToken: string;
}

export interface EnrollStartResponse {
  secret: string;
  otpauthUri: string;
}

export interface EnrollVerifyResponse {
  status: 'ok';
  csrfToken: string;
  recoveryCodes: string[];
}

export interface MfaVerifyResponse {
  status: 'ok';
  csrfToken: string;
}

export interface Me {
  user: { id: Id; email: string; displayName: string; mustChangePassword: boolean };
  partner: { id: Id; name: string };
  permissions: string[];
  partnerWide: boolean;
  roles: { name: string; scopeType: ScopeType; scopeId: Id | null }[];
  csrfToken: string;
  stepUpFresh: boolean;
  sessionIdleMinutes: number;
  /** How long a step-up stays fresh. Older servers omit the three settings below. */
  stepUpMinutes?: number;
  passwordMinLength?: number;
  /** Jobs that target more devices than this ask for the authenticator code. */
  bulkStepUpThreshold?: number;
}

export interface PermissionCatalog {
  permissions: string[];
  builtInRoles: Record<string, string[]>;
}

// ----- Tenants -----

export type ConsentMode = 'none' | 'notify' | 'require';
export const CONSENT_MODES: readonly ConsentMode[] = ['none', 'notify', 'require'];

export type UpdateRing = 'test' | 'pilot' | 'all';
export const UPDATE_RINGS: readonly UpdateRing[] = ['test', 'pilot', 'all'];

export interface Organization {
  id: Id;
  name: string;
  timeZone: string;
  consentMode: ConsentMode;
  requireSignedPowerShell: boolean;
  createdAt: IsoDate;
  deviceCount: number;
  onlineCount: number;
}

export interface OrganizationInput {
  name?: string;
  timeZone?: string;
  consentMode?: ConsentMode;
  requireSignedPowerShell?: boolean;
}

export interface Site {
  id: Id;
  organizationId: Id;
  name: string;
}

export interface DeviceGroup {
  id: Id;
  organizationId: Id;
  siteId: Id;
  name: string;
  updateRing: UpdateRing;
}

export interface Created {
  id: Id;
  name: string;
}

// ----- Users and roles -----

export interface RoleAssignment {
  id: Id;
  roleId: Id;
  roleName: string;
  scopeType: ScopeType;
  scopeId: Id | null;
}

export interface User {
  id: Id;
  email: string;
  displayName: string;
  disabled: boolean;
  totpEnabled: boolean;
  lastLoginAt: IsoDate | null;
  createdAt: IsoDate;
  locked: boolean;
  assignments: RoleAssignment[];
}

export interface Role {
  id: Id;
  name: string;
  isBuiltIn: boolean;
  permissions: string[];
}

/** Exactly one of `userId` and `apiKeyId` is set. */
export interface AssignmentInput {
  userId?: Id;
  apiKeyId?: Id;
  roleId: Id;
  scopeType: ScopeType;
  scopeId: Id | null;
}

// ----- Enrollment -----

export interface EnrollmentToken {
  id: Id;
  organizationId: Id;
  siteId: Id;
  /** Names are resolved by the server, so the list does not need `tenants.read`. */
  siteName?: string | null;
  groupId: Id | null;
  groupName?: string | null;
  name: string;
  tokenPrefix: string;
  expiresAt: IsoDate;
  maxUses: number;
  uses: number;
  revokedAt: IsoDate | null;
  createdAt: IsoDate;
}

export interface EnrollmentTokenInput {
  siteId: Id;
  groupId?: Id | null;
  name: string;
  expiresInHours: number;
  maxUses: number;
}

export interface EnrollmentTokenCreated {
  id: Id;
  /** The secret. Returned exactly once; only its hash is stored. */
  token: string;
  expiresAt: IsoDate;
  maxUses: number;
}

/** `GET /enrollment-tokens/targets`: the sites and groups the caller may create tokens for. */
export interface EnrollmentTargets {
  sites: { id: Id; organizationId: Id; name: string }[];
  groups: { id: Id; siteId: Id; name: string }[];
}

/** `GET /agent/installers`: installer packages of the newest release that has any. */
export interface AgentInstallers {
  version: string | null;
  installers: {
    id: Id;
    os: string;
    arch: string;
    kind: string;
    sha256: string;
    sizeBytes: number;
    fileName: string;
    /** Same-origin download path (`/api/v1/agent/installers/{id}`). */
    url: string;
  }[];
}

export interface InstallInfo {
  serverUrl: string;
  caCertificatePem: string;
  trust: { commandKeys: { kid: string; alg: string; publicKey: string }[] };
  commands: {
    windows: string;
    macos: string;
    linux: string;
    windowsMsi: string;
    linuxDeb: string;
    linuxRpm: string;
    check: string;
  };
}

// ----- Devices -----

export type OsFamily = 'windows' | 'macos' | 'linux';
export const OS_FAMILIES: readonly OsFamily[] = ['windows', 'macos', 'linux'];

/** Lower-cased `DeviceStatus`; `revoked` is the one the UI treats specially. */
export type DeviceStatus = 'active' | 'revoked' | (string & {});

export interface DeviceListItem {
  id: Id;
  organizationId: Id;
  siteId: Id;
  groupId: Id | null;
  hostname: string;
  os: OsFamily | (string & {});
  osName: string;
  osVersion: string;
  arch: string;
  serial: string;
  model: string;
  agentVersion: string;
  status: DeviceStatus;
  isOnline: boolean;
  lastSeenAt: IsoDate | null;
  tags: string[];
  consoleUser: string | null;
  pendingReboot: boolean;
  /** Set while the device is isolated from the network. */
  isolatedAt?: IsoDate | null;
  cpuPercent: number | null;
  memUsedPercent: number | null;
}

/** `inventory` payload, docs/PROTOCOL.md section 7.1. Every field is optional: agents and versions differ. */
export interface Inventory {
  collectedAt?: IsoDate;
  hostname?: string;
  machineId?: string;
  os?: { family?: string; name?: string; version?: string; build?: string; kernel?: string };
  arch?: string;
  cpu?: { model?: string; cores?: number; logicalCores?: number };
  memoryBytes?: number;
  disks?: { device?: string; mountPoint?: string; fsType?: string; totalBytes?: number; freeBytes?: number }[];
  network?: { name?: string; mac?: string; ipv4?: string[]; ipv6?: string[] }[];
  serial?: string;
  manufacturer?: string;
  model?: string;
  consoleUser?: string;
  loggedInUsers?: string[];
  bootTime?: IsoDate;
  uptimeSeconds?: number;
  pendingReboot?: boolean;
  timezone?: string;
  agent?: { version?: string; cpuPercent?: number; rssBytes?: number };
  unsupported?: string[];
}

export interface DeviceDetail extends DeviceListItem {
  manufacturer: string;
  machineId: string;
  enrolledAt: IsoDate;
  agentRssBytes: number | null;
  certNotAfter: IsoDate | null;
  possibleDuplicateOfDeviceId: Id | null;
  capabilities: string[] | null;
  lastIp: string | null;
  uninstallCodeSet: boolean;
  lastPatchScanAt: IsoDate | null;
  lastPatchInstallAt: IsoDate | null;
  meshInstalled: boolean;
  macAddresses?: string[];
  defaultGateway?: string | null;
  /** "" when the OS hides the SSID; null when not on Wi-Fi. */
  wifiSsid?: string | null;
  isolatedBy?: string | null;
  isolationReason?: string | null;
  inventoryCollectedAt: IsoDate | null;
  inventory: Inventory | null;
}

export interface DeviceListFilter {
  organizationId?: Id;
  siteId?: Id;
  groupId?: Id;
  os?: string;
  online?: boolean;
  search?: string;
  tag?: string;
  pendingReboot?: boolean;
  sort?: DeviceSort;
  page?: number;
  pageSize?: number;
}

/** `GET /devices?sort=`; anything else sorts by hostname. */
export type DeviceSort = 'hostname' | 'lastSeen' | 'os' | 'status';

/** `GET /devices` also returns how many devices matching the filter are online. */
export interface DevicePage extends Paged<DeviceListItem> {
  online?: number;
}

/** `GET /overview`: one-screen fleet summary (active devices only). */
export interface OverviewSummary {
  devices: { total: number; online: number; pendingReboot: number; byOs: { os: string; count: number }[] };
  organizations: { id: Id; name: string }[];
}

export interface DeviceUpdateInput {
  tags?: string[];
  groupId?: Id;
  clearGroup?: boolean;
  siteId?: Id;
}

// ----- Audit -----

export interface AuditEvent {
  sequence: number;
  occurredAt: IsoDate;
  actorType: string;
  actorId: Id | null;
  actorName: string;
  action: string;
  targetType: string | null;
  targetId: string | null;
  organizationId: Id | null;
  deviceId: Id | null;
  ip: string | null;
  result: string;
  /** Parsed JSON (an object). Older servers sent JSON text. */
  detail: unknown;
  contentSha256: string | null;
  hash: string;
}

export interface AuditFilter {
  organizationId?: Id;
  deviceId?: Id;
  action?: string;
  actor?: string;
  from?: IsoDate;
  to?: IsoDate;
  page?: number;
  pageSize?: number;
}

export interface AuditVerification {
  ok: boolean;
  count: number;
  firstBadSequence: number | null;
  problem: string | null;
}

// ----- Live hub events (server `LiveNotifier`) -----

export interface DeviceEvent {
  id: Id;
  organizationId: Id;
  isOnline: boolean;
  lastSeenAt: IsoDate | null;
  hostname: string;
  status: DeviceStatus;
  /** Sent by current servers; absent on older ones. */
  siteId?: Id;
  groupId?: Id | null;
  pendingReboot?: boolean;
  consoleUser?: string | null;
  tags?: string[];
}
