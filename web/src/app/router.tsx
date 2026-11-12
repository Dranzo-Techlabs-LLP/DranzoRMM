import { lazy, type ComponentType } from 'react';
import { createBrowserRouter, type RouteObject } from 'react-router';
import LoginPage from '@/features/auth/LoginPage';
import { NotFound, RequireAccess, RequireAuth, RouteError } from './guards';
import { implementedPages } from './pages';
import { AppShell } from './shell/AppShell';

function page(load: () => Promise<{ default: ComponentType }>): ComponentType {
  return lazy(load);
}

const AccountPage = page(() => import('@/features/auth/AccountPage'));

/** Routes are generated from the page registry (`pages.ts`); do not add page routes here. */
export function buildRoutes(): RouteObject[] {
  const pageRoutes: RouteObject[] = implementedPages().flatMap((def) => {
    const requirement = { permission: def.permission, partnerWide: def.partnerWide };
    const routes = [{ path: def.path, load: def.load }, ...(def.children ?? [])];
    return routes.map(({ path, load }): RouteObject => {
      const Component = page(load);
      const element = (
        <RequireAccess requirement={requirement} isIndex={path === ''}>
          <Component />
        </RequireAccess>
      );
      return path === '' ? { index: true, element } : { path, element };
    });
  });

  return [
    { path: '/login', element: <LoginPage />, errorElement: <RouteError /> },
    {
      path: '/',
      element: (
        <RequireAuth>
          <AppShell />
        </RequireAuth>
      ),
      errorElement: <RouteError />,
      children: [
        {
          errorElement: <RouteError />,
          children: [
            ...pageRoutes,
            { path: 'account', element: <AccountPage /> },
            { path: '*', element: <NotFound /> },
          ],
        },
      ],
    },
  ];
}

export function createAppRouter() {
  return createBrowserRouter(buildRoutes());
}
