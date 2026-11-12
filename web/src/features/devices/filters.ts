import type { DeviceListFilter, DeviceSort, Id } from '@/lib/api';

export const DEVICE_PAGE_SIZE = 50;

/** Device list filters kept in the URL so a filtered view can be bookmarked and shared. */
export interface DeviceUrlFilters {
  search: string;
  siteId: string;
  groupId: string;
  os: string;
  status: '' | 'online' | 'offline';
  tag: string;
  /** Only devices waiting for a restart. */
  reboot: boolean;
  sort: DeviceSort;
  page: number;
}

export const DEVICE_SORTS: { value: DeviceSort; label: string }[] = [
  { value: 'hostname', label: 'Name' },
  { value: 'status', label: 'Offline first' },
  { value: 'lastSeen', label: 'Last seen' },
  { value: 'os', label: 'Operating system' },
];

function readSort(value: string | null): DeviceSort {
  return DEVICE_SORTS.find((s) => s.value === value)?.value ?? 'hostname';
}

export function readDeviceFilters(params: URLSearchParams): DeviceUrlFilters {
  const status = params.get('status');
  const page = Number.parseInt(params.get('page') ?? '1', 10);
  return {
    search: params.get('q') ?? '',
    siteId: params.get('site') ?? '',
    groupId: params.get('group') ?? '',
    os: params.get('os') ?? '',
    status: status === 'online' || status === 'offline' ? status : '',
    tag: params.get('tag') ?? '',
    reboot: params.get('reboot') === '1',
    sort: readSort(params.get('sort')),
    page: Number.isFinite(page) && page > 0 ? page : 1,
  };
}

export function writeDeviceFilters(filters: DeviceUrlFilters): URLSearchParams {
  const params = new URLSearchParams();
  const set = (key: string, value: string) => {
    if (value) {
      params.set(key, value);
    }
  };
  set('q', filters.search.trim());
  set('site', filters.siteId);
  set('group', filters.groupId);
  set('os', filters.os);
  set('status', filters.status);
  set('tag', filters.tag.trim());
  set('reboot', filters.reboot ? '1' : '');
  set('sort', filters.sort === 'hostname' ? '' : filters.sort);
  if (filters.page > 1) {
    params.set('page', String(filters.page));
  }
  return params;
}

export function toApiFilter(filters: DeviceUrlFilters, organizationId: Id | null): DeviceListFilter {
  return {
    organizationId: organizationId ?? undefined,
    siteId: filters.siteId || undefined,
    groupId: filters.groupId || undefined,
    os: filters.os || undefined,
    online: filters.status === '' ? undefined : filters.status === 'online',
    search: filters.search.trim() || undefined,
    tag: filters.tag.trim() || undefined,
    pendingReboot: filters.reboot ? true : undefined,
    sort: filters.sort === 'hostname' ? undefined : filters.sort,
    page: filters.page,
    pageSize: DEVICE_PAGE_SIZE,
  };
}

export function hasActiveFilters(filters: DeviceUrlFilters): boolean {
  return Boolean(
    filters.search ||
    filters.siteId ||
    filters.groupId ||
    filters.os ||
    filters.status ||
    filters.tag ||
    filters.reboot,
  );
}
