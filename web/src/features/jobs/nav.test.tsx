import { describe, expect, it } from 'vitest';
import { NAV_AREAS, visibleNav } from '@/app/pages';
import { DEVICE_TABS } from '@/features/devices/tabs/registry';
import { accessFor } from '@/lib/auth/permissions';

const labels = (areas: ReturnType<typeof visibleNav>) => areas.flatMap((a) => a.pages.map((p) => p.label));
const mine = ['Scripts', 'Jobs', 'Software', 'Patches'];
const shownOf = (permissions: string[]) =>
  labels(visibleNav(accessFor({ permissions, partnerWide: false }))).filter((l) => mine.includes(l));

describe('automation, software and patch navigation', () => {
  it('is implemented and gated by its read permission', () => {
    const pages = NAV_AREAS.flatMap((a) => a.pages).filter((p) => mine.includes(p.label));
    expect(pages.map((p) => [p.label, p.permission, typeof p.load])).toEqual([
      ['Scripts', 'scripts.read', 'function'],
      ['Jobs', 'jobs.read', 'function'],
      ['Software', 'software.read', 'function'],
      ['Patches', 'patches.read', 'function'],
    ]);
  });

  it('shows each entry only to users holding that permission', () => {
    expect(shownOf([])).toEqual([]);
    expect(shownOf(['scripts.read'])).toEqual(['Scripts']);
    expect(shownOf(['jobs.read', 'patches.read'])).toEqual(['Jobs', 'Patches']);
    // Manage / run permissions alone do not open the pages.
    expect(shownOf(['scripts.run', 'scripts.manage', 'software.deploy', 'patches.install'])).toEqual([]);
    // The built-in Organization Viewer role sees software and patches but not scripts or jobs.
    expect(shownOf(['tenants.read', 'devices.read', 'software.read', 'patches.read'])).toEqual(['Software', 'Patches']);
  });

  it('registers detail routes under the gated pages', () => {
    const paths = NAV_AREAS.flatMap((a) => a.pages).flatMap((p) => (p.children ?? []).map((c) => c.path));
    expect(paths).toEqual(
      expect.arrayContaining([
        'scripts/new',
        'scripts/:scriptId',
        'scripts/:scriptId/edit',
        'jobs/:jobId',
        'jobs/:jobId/runs/:runId',
      ]),
    );
  });

  it('adds device tabs gated the same way', () => {
    const tabs = Object.fromEntries(DEVICE_TABS.map((t) => [t.id, t.permission]));
    expect(tabs).toMatchObject({ scripts: 'scripts.read', software: 'software.read', patches: 'patches.read' });
    const viewer = accessFor({ permissions: ['devices.read', 'software.read'], partnerWide: false });
    expect(DEVICE_TABS.filter((t) => viewer.can(t)).map((t) => t.id)).toEqual(['overview', 'software']);
  });
});
