import type { QueryClient } from '@tanstack/react-query';
import { qk, type DeviceDetail, type DeviceEvent, type DeviceListItem, type Paged } from '@/lib/api';

function isDeviceEvent(value: unknown): value is DeviceEvent {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return typeof v.id === 'string' && typeof v.isOnline === 'boolean';
}

/**
 * Applies a `device` hub event to cached data: patches the row in every cached device list and the cached detail,
 * so status dots change at once. Returns `true` when aggregate data (counts, filtered lists) should be refetched.
 */
export function applyDeviceEvent(queryClient: QueryClient, payload: unknown): boolean {
  if (!isDeviceEvent(payload)) {
    return false;
  }
  // Older servers send only the first four fields; a field that is absent must not overwrite cached data.
  const patch: Partial<DeviceListItem> = {
    isOnline: payload.isOnline,
    lastSeenAt: payload.lastSeenAt,
    hostname: payload.hostname,
    status: payload.status,
    ...(typeof payload.siteId === 'string' ? { siteId: payload.siteId } : {}),
    ...(payload.groupId === null || typeof payload.groupId === 'string' ? { groupId: payload.groupId } : {}),
    ...(typeof payload.pendingReboot === 'boolean' ? { pendingReboot: payload.pendingReboot } : {}),
    ...(payload.consoleUser === null || typeof payload.consoleUser === 'string'
      ? { consoleUser: payload.consoleUser }
      : {}),
    ...(Array.isArray(payload.tags) ? { tags: payload.tags.filter((t): t is string => typeof t === 'string') } : {}),
  };
  queryClient.setQueriesData<Paged<DeviceListItem>>({ queryKey: qk.deviceLists }, (old) =>
    old && old.items.some((d) => d.id === payload.id)
      ? { ...old, items: old.items.map((d) => (d.id === payload.id ? { ...d, ...patch } : d)) }
      : old,
  );
  queryClient.setQueryData<DeviceDetail>(qk.deviceDetail(payload.id), (old) => (old ? { ...old, ...patch } : old));
  return true;
}

/** Refetches what an event may have changed beyond the patched rows: list membership and per-organization counts. */
export function refreshAfterDeviceEvents(queryClient: QueryClient): void {
  void queryClient.invalidateQueries({ queryKey: qk.devices });
  void queryClient.invalidateQueries({ queryKey: qk.organizations });
}
