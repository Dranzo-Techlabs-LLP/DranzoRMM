import { describe, expect, it } from 'vitest';
import {
  describeStoredTarget,
  describeTarget,
  emptyTarget,
  EMPTY_FILTER,
  MAX_EXPLICIT_DEVICES,
  targetProblem,
  toTargetRequest,
} from './target';

describe('target picker → TargetRequest', () => {
  it('sends only the field of the active mode, because the server reads the first one that is set', () => {
    // A draft that has leftovers from other modes.
    const base = emptyTarget({
      devices: [{ id: 'd1', hostname: 'a' }],
      organizationId: 'o1',
      siteId: 's1',
      groupId: 'g1',
      savedFilterId: 'f1',
      filter: { ...EMPTY_FILTER, os: 'linux' },
    });
    expect(toTargetRequest({ ...base, mode: 'devices' })).toEqual({ deviceIds: ['d1'] });
    expect(toTargetRequest({ ...base, mode: 'group' })).toEqual({ groupId: 'g1' });
    expect(toTargetRequest({ ...base, mode: 'site' })).toEqual({ siteId: 's1' });
    expect(toTargetRequest({ ...base, mode: 'organization' })).toEqual({ organizationId: 'o1' });
    expect(toTargetRequest({ ...base, mode: 'savedFilter' })).toEqual({ savedFilterId: 'f1' });
    expect(toTargetRequest({ ...base, mode: 'filter' })).toEqual({
      organizationId: 'o1',
      filter: { organizationId: 'o1', os: 'linux' },
    });
  });

  it('de-duplicates explicit devices', () => {
    const draft = emptyTarget({
      devices: [
        { id: 'd1', hostname: 'a' },
        { id: 'd1', hostname: 'a' },
        { id: 'd2', hostname: 'b' },
      ],
    });
    expect(toTargetRequest(draft)).toEqual({ deviceIds: ['d1', 'd2'] });
  });

  it('maps every filter criterion and drops empty ones', () => {
    const draft = emptyTarget({
      mode: 'filter',
      filter: { siteId: 's', groupId: 'g', os: 'windows', status: 'offline', search: '  web ', tag: ' kiosk ' },
    });
    expect(toTargetRequest(draft)).toEqual({
      filter: { siteId: 's', groupId: 'g', os: 'windows', online: false, search: 'web', tag: 'kiosk' },
    });
    expect(toTargetRequest(emptyTarget({ mode: 'filter', filter: { ...EMPTY_FILTER, status: 'online' } }))).toEqual({
      filter: { online: true },
    });
    // No criteria and no organization: an all-devices filter (the server applies the caller's scope).
    expect(toTargetRequest(emptyTarget({ mode: 'filter' }))).toEqual({ filter: {} });
  });

  it('returns null and a reason while the draft is incomplete', () => {
    expect(toTargetRequest(emptyTarget())).toBeNull();
    expect(targetProblem(emptyTarget())).toBe('Choose at least one device.');
    expect(targetProblem(emptyTarget({ mode: 'group' }))).toBe('Choose a group.');
    expect(targetProblem(emptyTarget({ mode: 'site' }))).toBe('Choose a site.');
    expect(targetProblem(emptyTarget({ mode: 'organization' }))).toBe('Choose an organization.');
    expect(targetProblem(emptyTarget({ mode: 'savedFilter' }))).toBe('Choose a saved filter.');
    const tooMany = emptyTarget({
      devices: Array.from({ length: MAX_EXPLICIT_DEVICES + 1 }, (_, i) => ({ id: `d${i}`, hostname: `h${i}` })),
    });
    expect(toTargetRequest(tooMany)).toBeNull();
  });

  it('describes targets for confirmations', () => {
    const names = {
      organizations: [{ id: 'o1', name: 'Acme' }],
      groups: [{ id: 'g1', name: 'Finance' }],
      savedFilters: [{ id: 'f1', name: 'Kiosks' }],
    };
    expect(describeTarget(emptyTarget({ devices: [{ id: 'd', hostname: 'srv-01' }] }), names)).toBe('srv-01');
    expect(describeTarget(emptyTarget({ mode: 'group', groupId: 'g1' }), names)).toBe('group Finance');
    expect(describeTarget(emptyTarget({ mode: 'organization', organizationId: 'o1' }), names)).toBe(
      'all devices of Acme',
    );
    expect(describeTarget(emptyTarget({ mode: 'savedFilter', savedFilterId: 'f1' }), names)).toBe(
      'saved filter Kiosks',
    );
    expect(
      describeTarget(
        emptyTarget({ mode: 'filter', organizationId: 'o1', filter: { ...EMPTY_FILTER, os: 'macos', tag: 'x' } }),
        names,
      ),
    ).toBe('macOS, tag x in Acme');
  });

  it('describes the target stored with a schedule, tolerating bad JSON', () => {
    expect(describeStoredTarget('{"deviceIds":["a","b"]}')).toBe('2 devices');
    expect(describeStoredTarget('{"organizationId":"o1"}', { organizations: [{ id: 'o1', name: 'Acme' }] })).toBe(
      'All devices of Acme',
    );
    expect(describeStoredTarget('{"filter":{"os":"linux","online":true}}')).toBe('Filter: Linux, online');
    expect(describeStoredTarget('not json')).toBe('Unknown target');
  });
});
