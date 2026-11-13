import { screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { accessFor } from '@/lib/auth/permissions';
import { ME, mockApi } from '@/test/mock-api';
import { renderApp } from '@/test/render';
import { RequireAccess, RequireAuth } from './guards';
import { firstAccessiblePath, implementedPages, NAV_AREAS, visibleNav } from './pages';
import { Sidebar } from './shell/Sidebar';

const labels = (areas: ReturnType<typeof visibleNav>) => areas.flatMap((a) => a.pages.map((p) => p.label));

describe('permission-gated navigation', () => {
  it('shows a Partner Admin every implemented page, grouped by area', () => {
    const nav = visibleNav(accessFor(ME));
    expect(labels(nav)).toEqual([
      'Overview',
      'Devices',
      'Organizations',
      'Enrollment',
      'Audit log',
      'Users & roles',
      'Access review',
    ]);
    expect(nav.map((a) => a.label)).toEqual(['Fleet', 'Records', 'Admin']);
  });

  it('hides pages whose permission the user lacks', () => {
    const viewer = accessFor({ permissions: ['tenants.read', 'devices.read'], partnerWide: false });
    expect(labels(visibleNav(viewer))).toEqual(['Overview', 'Devices', 'Organizations']);
  });

  it('hides partner-wide pages from users scoped to one organization', () => {
    const scoped = accessFor({ permissions: ['users.read', 'audit.read'], partnerWide: false });
    expect(labels(visibleNav(scoped))).toEqual(['Audit log']);
    const partner = accessFor({ permissions: ['users.read', 'audit.read'], partnerWide: true });
    expect(labels(visibleNav(partner))).toEqual(['Audit log', 'Users & roles', 'Access review']);
  });

  it('shows nothing without a session or without roles', () => {
    expect(visibleNav(accessFor(null))).toEqual([]);
    expect(visibleNav(accessFor({ permissions: [], partnerWide: false }))).toEqual([]);
    expect(firstAccessiblePath(accessFor({ permissions: [], partnerWide: false }))).toBeNull();
  });

  it('renders every registered page once its permission is held (no page is left planned)', () => {
    const everything = accessFor({
      permissions: NAV_AREAS.flatMap((a) => a.pages.map((p) => p.permission ?? '')),
      partnerWide: true,
    });
    const shown = labels(visibleNav(everything));
    for (const page of ['Security', 'Alerts', 'Remote sessions', 'Policies', 'Reports', 'Agent releases', 'API keys']) {
      expect(shown).toContain(page);
    }
  });

  it('every implemented page declares the permission its API needs', () => {
    for (const page of implementedPages()) {
      expect(page.permission, page.id).toBeTruthy();
    }
  });

  it('picks the first accessible page as the landing page', () => {
    expect(firstAccessiblePath(accessFor({ permissions: ['audit.read'], partnerWide: false }))).toBe('/audit');
    expect(firstAccessiblePath(accessFor(ME))).toBe('/');
  });
});

describe('Sidebar', () => {
  const routes = [
    {
      path: '*',
      element: (
        <RequireAuth>
          <Sidebar collapsed={false} />
        </RequireAuth>
      ),
    },
  ];

  it('renders only the links the signed-in user may open', async () => {
    mockApi({
      'GET /auth/me': { body: { ...ME, permissions: ['devices.read', 'tenants.read'], partnerWide: false } },
    });
    renderApp(routes, '/devices');

    const nav = await screen.findByRole('navigation', { name: 'Main' });
    const links = within(nav).getAllByRole('link');
    expect(links.map((l) => l.textContent)).toEqual(['Overview', 'Devices', 'Organizations']);
    expect(within(nav).getByRole('link', { name: 'Devices' })).toHaveAttribute('aria-current', 'page');
    expect(within(nav).queryByRole('link', { name: 'Users & roles' })).not.toBeInTheDocument();
    expect(within(nav).queryByRole('link', { name: 'Enrollment' })).not.toBeInTheDocument();
  });

  it('keeps accessible names when collapsed to the icon rail', async () => {
    mockApi({ 'GET /auth/me': { body: ME } });
    renderApp(
      [
        {
          path: '*',
          element: (
            <RequireAuth>
              <Sidebar collapsed />
            </RequireAuth>
          ),
        },
      ],
      '/',
    );
    const nav = await screen.findByRole('navigation', { name: 'Main' });
    expect(within(nav).getByRole('link', { name: 'Audit log' })).toBeInTheDocument();
    expect(within(nav).getAllByRole('link')).toHaveLength(7);
    // The rail wraps links in a tooltip trigger; the active state and classes must survive that.
    const overview = within(nav).getByRole('link', { name: 'Overview' });
    expect(overview).toHaveAttribute('aria-current', 'page');
    expect(overview.className).not.toMatch(/isActive|=>/);
    expect(within(nav).getByRole('link', { name: 'Audit log' })).not.toHaveAttribute('aria-current');
  });
});

describe('RequireAccess', () => {
  it('explains the missing permission instead of rendering the page', async () => {
    mockApi({ 'GET /auth/me': { body: { ...ME, permissions: ['devices.read'], partnerWide: false } } });
    renderApp(
      [
        {
          path: '*',
          element: (
            <RequireAuth>
              <RequireAccess requirement={{ permission: 'users.read', partnerWide: true }}>
                <p>Secret admin page</p>
              </RequireAccess>
            </RequireAuth>
          ),
        },
      ],
      '/admin/users',
    );
    expect(await screen.findByText('You do not have access to this page')).toBeInTheDocument();
    expect(screen.queryByText('Secret admin page')).not.toBeInTheDocument();
  });
});
