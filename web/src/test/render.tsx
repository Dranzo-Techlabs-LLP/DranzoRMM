import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import type { ReactElement } from 'react';
import { createMemoryRouter, type RouteObject } from 'react-router';
import { RouterProvider } from 'react-router/dom';
import { ThemeProvider } from '@/app/theme';
import { Toaster } from '@/components/ui/sonner';
import { TooltipProvider } from '@/components/ui/tooltip';
import { api } from '@/lib/api';
import { SessionWatcher } from '@/lib/auth/SessionWatcher';

export function testQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
  });
}

/** Renders routes inside the same providers as the real app, with an in-memory router. */
export function renderApp(routes: RouteObject[], initialPath = '/') {
  api.setCsrfToken(null);
  const queryClient = testQueryClient();
  const router = createMemoryRouter(routes, { initialEntries: [initialPath] });
  const view = render(
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <SessionWatcher />
          <RouterProvider router={router} />
          <Toaster />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>,
  );
  return { ...view, router, queryClient };
}

export function renderElement(element: ReactElement, initialPath = '/') {
  return renderApp([{ path: '*', element }], initialPath);
}
