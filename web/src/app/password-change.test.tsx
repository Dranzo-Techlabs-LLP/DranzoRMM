import { useQuery } from '@tanstack/react-query';
import { screen } from '@testing-library/react';
import { Outlet, useLocation } from 'react-router';
import { describe, expect, it, vi } from 'vitest';
import { ApiClient, devicesApi } from '@/lib/api';
import { useMe } from '@/lib/auth/session';
import { ME, mockApi } from '@/test/mock-api';
import { renderApp } from '@/test/render';
import { RequireAuth } from './guards';
import { Navigate } from 'react-router';

const PASSWORD_CHANGE = {
  status: 403,
  body: { error: 'password_change_required', message: 'Change your temporary password before doing anything else.' },
};

/** The same rule as `AppShell`: a temporary password sends every page to Account. */
function Shell() {
  const me = useMe();
  const location = useLocation();
  if (me.user.mustChangePassword && location.pathname !== '/account') {
    return <Navigate to="/account" replace />;
  }
  return <Outlet />;
}

function DevicesProbe() {
  const q = useQuery({ queryKey: ['devices', 'list', {}], queryFn: () => devicesApi.list({}), retry: false });
  return <p>{q.isError ? 'Devices failed' : 'Devices loading'}</p>;
}

describe('403 password_change_required', () => {
  it('tells the app through the client handler, once per failed call', async () => {
    const onPasswordChangeRequired = vi.fn();
    const fetchMock = vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify(PASSWORD_CHANGE.body), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    );
    const client = new ApiClient(fetchMock as unknown as typeof fetch);
    client.configure({ onPasswordChangeRequired });
    await expect(client.get('/devices')).rejects.toMatchObject({ status: 403, code: 'password_change_required' });
    expect(onPasswordChangeRequired).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('sends the user to Account when any call is refused for a temporary password', async () => {
    mockApi({ 'GET /auth/me': { body: ME }, 'GET /devices': PASSWORD_CHANGE });
    renderApp(
      [
        {
          path: '/',
          element: (
            <RequireAuth>
              <Shell />
            </RequireAuth>
          ),
          children: [
            { path: 'devices', element: <DevicesProbe /> },
            { path: 'account', element: <p>Account page</p> },
          ],
        },
      ],
      '/devices',
    );
    expect(await screen.findByText('Account page')).toBeInTheDocument();
  });
});
