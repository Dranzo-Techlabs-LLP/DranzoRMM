import { useQuery } from '@tanstack/react-query';
import { act, screen, waitFor } from '@testing-library/react';
import { useLocation } from 'react-router';
import { describe, expect, it } from 'vitest';
import { api, devicesApi } from '@/lib/api';
import { clearSession, loginUrl, safeReturnTo } from '@/lib/auth/session';
import { ME, mockApi, UNAUTHENTICATED } from '@/test/mock-api';
import { renderApp } from '@/test/render';
import { RequireAuth } from './guards';

function LoginProbe() {
  const location = useLocation();
  return <p>Sign-in page at {location.pathname + location.search}</p>;
}

function DevicesProbe() {
  const query = useQuery({
    queryKey: ['devices', 'list', {}],
    queryFn: () => devicesApi.list({}),
    retry: false,
  });
  return <p>Devices: {query.data ? query.data.total : 'loading'}</p>;
}

const routes = [
  { path: '/login', element: <LoginProbe /> },
  {
    path: '*',
    element: (
      <RequireAuth>
        <DevicesProbe />
      </RequireAuth>
    ),
  },
];

describe('session handling', () => {
  it('redirects to sign-in with the return URL when there is no session', async () => {
    mockApi({ 'GET /auth/me': UNAUTHENTICATED });
    renderApp(routes, '/devices?status=offline');
    expect(
      await screen.findByText('Sign-in page at /login?returnTo=%2Fdevices%3Fstatus%3Doffline'),
    ).toBeInTheDocument();
  });

  it('on 401 unauthenticated from any call: clears cached data and redirects to sign-in', async () => {
    const server = mockApi({
      'GET /auth/me': { body: ME },
      'GET /devices': [{ body: { total: 3, page: 1, pageSize: 50, items: [] } }, UNAUTHENTICATED],
    });
    const { queryClient } = renderApp(routes, '/devices?status=offline');

    expect(await screen.findByText('Devices: 3')).toBeInTheDocument();
    expect(api.getCsrfToken()).toBe('csrf-from-me');

    // The session expires; the next API call anywhere in the app is answered with 401.
    await queryClient.refetchQueries({ queryKey: ['devices'] });

    expect(
      await screen.findByText('Sign-in page at /login?returnTo=%2Fdevices%3Fstatus%3Doffline'),
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(queryClient.getQueryData(['devices', 'list', {}])).toBeUndefined();
    });
    expect(api.getCsrfToken()).toBeNull();
    expect(server.callsTo('GET /devices')).toHaveLength(2);
  });

  it('after an explicit sign-out the sign-in page gets no return URL', async () => {
    mockApi({
      'GET /auth/me': { body: ME },
      'GET /devices': { body: { total: 3, page: 1, pageSize: 50, items: [] } },
    });
    const { queryClient } = renderApp(routes, '/devices?status=offline');
    expect(await screen.findByText('Devices: 3')).toBeInTheDocument();

    act(() => {
      clearSession(queryClient, { explicit: true });
    });

    expect(await screen.findByText('Sign-in page at /login')).toBeInTheDocument();
  });

  it('shows a retry screen, not the sign-in page, when the server is unreachable', async () => {
    mockApi({ 'GET /auth/me': { status: 503 } });
    renderApp(routes, '/devices');
    expect(await screen.findByText('Could not load your session.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });
});

describe('return URL', () => {
  it('only accepts same-origin paths', () => {
    expect(safeReturnTo('/devices?status=offline')).toBe('/devices?status=offline');
    expect(safeReturnTo('https://evil.example/')).toBe('/');
    expect(safeReturnTo('//evil.example/')).toBe('/');
    expect(safeReturnTo('/\\evil.example')).toBe('/');
    expect(safeReturnTo('/login?returnTo=/login')).toBe('/');
    expect(safeReturnTo(null)).toBe('/');
  });

  it('omits the parameter for the default landing page', () => {
    expect(loginUrl('/')).toBe('/login');
    expect(loginUrl('/audit')).toBe('/login?returnTo=%2Faudit');
  });
});
