import type { Id } from '@/lib/api';
import type { DeviceFilterSpec, TargetRequest } from '@/lib/api/jobs';

/** What a job runs on. One mode is active at a time; the other fields keep their values so switching back is cheap. */
export type TargetMode = 'devices' | 'group' | 'site' | 'organization' | 'savedFilter' | 'filter';

export const TARGET_MODES: readonly { id: TargetMode; label: string; hint: string }[] = [
  { id: 'devices', label: 'Devices', hint: 'Pick individual devices.' },
  { id: 'group', label: 'Group', hint: 'Every device in one group.' },
  { id: 'site', label: 'Site', hint: 'Every device at one site.' },
  { id: 'organization', label: 'Organization', hint: 'Every device of one organization.' },
  { id: 'savedFilter', label: 'Saved filter', hint: 'Devices matching a saved filter.' },
  { id: 'filter', label: 'Filter', hint: 'Devices matching criteria you set here.' },
];

export interface PickedDevice {
  id: Id;
  hostname: string;
  os?: string;
  organizationId?: Id;
}

export interface FilterDraft {
  siteId: string;
  groupId: string;
  os: string;
  status: '' | 'online' | 'offline';
  search: string;
  tag: string;
}

export interface TargetDraft {
  mode: TargetMode;
  devices: PickedDevice[];
  /** Organization for the group, site, organization and filter modes. `''` = all organizations (filter mode only). */
  organizationId: string;
  siteId: string;
  groupId: string;
  savedFilterId: string;
  filter: FilterDraft;
}

export const EMPTY_FILTER: FilterDraft = { siteId: '', groupId: '', os: '', status: '', search: '', tag: '' };

/** The server accepts at most this many explicit device ids per job. */
export const MAX_EXPLICIT_DEVICES = 5000;

export function emptyTarget(patch: Partial<TargetDraft> = {}): TargetDraft {
  return {
    mode: 'devices',
    devices: [],
    organizationId: '',
    siteId: '',
    groupId: '',
    savedFilterId: '',
    filter: { ...EMPTY_FILTER },
    ...patch,
  };
}

export function deviceTarget(device: PickedDevice): TargetDraft {
  return emptyTarget({ mode: 'devices', devices: [device] });
}

/** Server `DeviceFilter` from the form, without empty criteria. */
export function toFilterSpec(filter: FilterDraft, organizationId: string): DeviceFilterSpec {
  const spec: DeviceFilterSpec = {};
  if (organizationId) {
    spec.organizationId = organizationId;
  }
  if (filter.siteId) {
    spec.siteId = filter.siteId;
  }
  if (filter.groupId) {
    spec.groupId = filter.groupId;
  }
  if (filter.os) {
    spec.os = filter.os;
  }
  if (filter.status) {
    spec.online = filter.status === 'online';
  }
  if (filter.search.trim()) {
    spec.search = filter.search.trim();
  }
  if (filter.tag.trim()) {
    spec.tag = filter.tag.trim();
  }
  return spec;
}

/** A filter with no narrowing criteria covers a whole organization (or everything). */
export function filterIsUnrestricted(filter: FilterDraft): boolean {
  return (
    !filter.siteId && !filter.groupId && !filter.os && !filter.status && !filter.search.trim() && !filter.tag.trim()
  );
}

/** Why the draft cannot be sent yet, or `null` when it is complete. */
export function targetProblem(draft: TargetDraft): string | null {
  switch (draft.mode) {
    case 'devices':
      if (draft.devices.length === 0) {
        return 'Choose at least one device.';
      }
      if (draft.devices.length > MAX_EXPLICIT_DEVICES) {
        return `Choose at most ${MAX_EXPLICIT_DEVICES} devices, or use a group or filter instead.`;
      }
      return null;
    case 'group':
      return draft.groupId ? null : 'Choose a group.';
    case 'site':
      return draft.siteId ? null : 'Choose a site.';
    case 'organization':
      return draft.organizationId ? null : 'Choose an organization.';
    case 'savedFilter':
      return draft.savedFilterId ? null : 'Choose a saved filter.';
    case 'filter':
      return null;
  }
}

/**
 * Maps the draft to the server's `TargetRequest`. Exactly the fields of the active mode are sent, because the server
 * reads the first one that is set (deviceIds, groupId, siteId, savedFilterId, filter, organizationId).
 * Returns `null` while the draft is incomplete.
 */
export function toTargetRequest(draft: TargetDraft): TargetRequest | null {
  if (targetProblem(draft) !== null) {
    return null;
  }
  switch (draft.mode) {
    case 'devices':
      return { deviceIds: [...new Set(draft.devices.map((d) => d.id))] };
    case 'group':
      return { groupId: draft.groupId };
    case 'site':
      return { siteId: draft.siteId };
    case 'organization':
      return { organizationId: draft.organizationId };
    case 'savedFilter':
      return { savedFilterId: draft.savedFilterId };
    case 'filter': {
      const filter = toFilterSpec(draft.filter, draft.organizationId);
      return draft.organizationId ? { organizationId: draft.organizationId, filter } : { filter };
    }
  }
}

export interface TargetNames {
  organizations?: { id: Id; name: string }[];
  sites?: { id: Id; name: string }[];
  groups?: { id: Id; name: string }[];
  savedFilters?: { id: Id; name: string }[];
}

const nameOf = (list: { id: Id; name: string }[] | undefined, id: string, fallback: string) =>
  list?.find((x) => x.id === id)?.name ?? fallback;

/** Human-readable criteria of a stored filter, for example "Windows, online, tag kiosk". */
export function describeFilter(filter: DeviceFilterSpec, names: TargetNames = {}): string {
  const parts: string[] = [];
  if (filter.siteId) {
    parts.push(`site ${nameOf(names.sites, filter.siteId, 'unknown')}`);
  }
  if (filter.groupId) {
    parts.push(`group ${nameOf(names.groups, filter.groupId, 'unknown')}`);
  }
  if (filter.os) {
    parts.push(
      filter.os === 'macos'
        ? 'macOS'
        : filter.os === 'windows'
          ? 'Windows'
          : filter.os === 'linux'
            ? 'Linux'
            : filter.os,
    );
  }
  if (filter.online === true) {
    parts.push('online');
  } else if (filter.online === false) {
    parts.push('offline');
  }
  if (filter.search) {
    parts.push(`matching “${filter.search}”`);
  }
  if (filter.tag) {
    parts.push(`tag ${filter.tag}`);
  }
  return parts.length > 0 ? parts.join(', ') : 'all devices';
}

/** One line for confirmations and toasts: "3 devices", "group Finance", "all devices of Acme". */
export function describeTarget(draft: TargetDraft, names: TargetNames = {}): string {
  switch (draft.mode) {
    case 'devices':
      return draft.devices.length === 1
        ? (draft.devices[0]?.hostname ?? '1 device')
        : `${draft.devices.length} selected devices`;
    case 'group':
      return `group ${nameOf(names.groups, draft.groupId, 'unknown')}`;
    case 'site':
      return `site ${nameOf(names.sites, draft.siteId, 'unknown')}`;
    case 'organization':
      return `all devices of ${nameOf(names.organizations, draft.organizationId, 'the organization')}`;
    case 'savedFilter':
      return `saved filter ${nameOf(names.savedFilters, draft.savedFilterId, 'unknown')}`;
    case 'filter': {
      const where = draft.organizationId
        ? nameOf(names.organizations, draft.organizationId, 'the organization')
        : 'all organizations';
      return `${describeFilter(toFilterSpec(draft.filter, ''), names)} in ${where}`;
    }
  }
}

/** Parses the `targetJson` the server stores with a schedule into a short description. */
export function describeStoredTarget(targetJson: string, names: TargetNames = {}): string {
  let raw: unknown;
  try {
    raw = JSON.parse(targetJson);
  } catch {
    return 'Unknown target';
  }
  if (typeof raw !== 'object' || raw === null) {
    return 'Unknown target';
  }
  const t = raw as {
    deviceIds?: unknown;
    groupId?: unknown;
    siteId?: unknown;
    organizationId?: unknown;
    filter?: unknown;
  };
  if (Array.isArray(t.deviceIds) && t.deviceIds.length > 0) {
    return t.deviceIds.length === 1 ? '1 device' : `${t.deviceIds.length} devices`;
  }
  if (typeof t.groupId === 'string') {
    return `Group ${nameOf(names.groups, t.groupId, 'unknown')}`;
  }
  if (typeof t.siteId === 'string') {
    return `Site ${nameOf(names.sites, t.siteId, 'unknown')}`;
  }
  const org =
    typeof t.organizationId === 'string' ? nameOf(names.organizations, t.organizationId, 'one organization') : null;
  if (typeof t.filter === 'object' && t.filter !== null) {
    const text = describeFilter(t.filter, names);
    return `Filter: ${text}${org ? ` in ${org}` : ''}`;
  }
  return org ? `All devices of ${org}` : 'All devices';
}
