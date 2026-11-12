import { QueryClient } from '@tanstack/react-query';
import { describe, expect, it } from 'vitest';
import { qk, type DeviceDetail, type DeviceListItem, type Paged } from '@/lib/api';
import { applyDeviceEvent } from './device-events';

function device(id: string, isOnline: boolean): DeviceListItem {
  return {
    id,
    organizationId: 'org-1',
    siteId: 'site-1',
    groupId: null,
    hostname: `host-${id}`,
    os: 'linux',
    osName: 'Ubuntu',
    osVersion: '24.04',
    arch: 'amd64',
    serial: '',
    model: '',
    agentVersion: '0.1.0',
    status: 'active',
    isOnline,
    lastSeenAt: '2026-11-11T10:00:00Z',
    tags: [],
    consoleUser: null,
    pendingReboot: false,
    cpuPercent: null,
    memUsedPercent: null,
  };
}

describe('applyDeviceEvent', () => {
  it('patches the device in every cached list and in the cached detail', () => {
    const qc = new QueryClient();
    const listA = qk.deviceList({ page: 1 });
    const listB = qk.deviceList({ online: true });
    qc.setQueryData<Paged<DeviceListItem>>(listA, {
      total: 2,
      page: 1,
      pageSize: 50,
      items: [device('a', true), device('b', true)],
    });
    qc.setQueryData<Paged<DeviceListItem>>(listB, { total: 1, page: 1, pageSize: 50, items: [device('a', true)] });
    qc.setQueryData(qk.deviceDetail('a'), { ...device('a', true), machineId: 'm' } as DeviceDetail);

    const changed = applyDeviceEvent(qc, {
      id: 'a',
      organizationId: 'org-1',
      isOnline: false,
      lastSeenAt: '2026-11-11T11:00:00Z',
      hostname: 'renamed',
      status: 'active',
    });

    expect(changed).toBe(true);
    const a = qc.getQueryData<Paged<DeviceListItem>>(listA)!;
    expect(a.items[0]).toMatchObject({
      id: 'a',
      isOnline: false,
      hostname: 'renamed',
      lastSeenAt: '2026-11-11T11:00:00Z',
    });
    expect(a.items[1]).toMatchObject({ id: 'b', isOnline: true });
    expect(qc.getQueryData<Paged<DeviceListItem>>(listB)!.items[0]?.isOnline).toBe(false);
    expect(qc.getQueryData<DeviceDetail>(qk.deviceDetail('a'))).toMatchObject({ isOnline: false, machineId: 'm' });
  });

  it('leaves lists that do not contain the device untouched (same object)', () => {
    const qc = new QueryClient();
    const key = qk.deviceList({});
    const before = { total: 1, page: 1, pageSize: 50, items: [device('b', true)] };
    qc.setQueryData(key, before);
    applyDeviceEvent(qc, {
      id: 'zzz',
      organizationId: 'o',
      isOnline: true,
      lastSeenAt: null,
      hostname: 'x',
      status: 'active',
    });
    expect(qc.getQueryData(key)).toBe(before);
  });

  it('ignores malformed payloads', () => {
    const qc = new QueryClient();
    expect(applyDeviceEvent(qc, null)).toBe(false);
    expect(applyDeviceEvent(qc, { id: 5 })).toBe(false);
    expect(applyDeviceEvent(qc, 'device')).toBe(false);
  });
});
