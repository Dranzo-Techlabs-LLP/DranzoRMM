import { useQueryClient } from '@tanstack/react-query';
import { ShieldOff } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link, Navigate, useLocation, useRouteError } from 'react-router';
import { EmptyState, ErrorState } from '@/components/page';
import { Button } from '@/components/ui/button';
import type { Requirement } from '@/lib/auth/permissions';
import { loginUrl, useAccess, useMeQuery, wasExplicitSignOut } from '@/lib/auth/session';
import { firstAccessiblePath } from './pages';

/** Renders children only with a session; otherwise goes to sign-in and remembers where the user was heading. */
export function RequireAuth({ children }: { children: ReactNode }) {
  const me = useMeQuery();
  const location = useLocation();
  const queryClient = useQueryClient();
  if (me.isPending) {
    return (
      <div role="status" className="text-muted-foreground grid min-h-dvh place-items-center">
        Loading…
      </div>
    );
  }
  if (me.isError) {
    return (
      <div className="grid min-h-dvh place-items-center">
        <ErrorState error={me.error} what="your session" onRetry={() => void me.refetch()} />
      </div>
    );
  }
  if (!me.data) {
    const returnTo = wasExplicitSignOut(queryClient) ? '/' : location.pathname + location.search;
    return <Navigate to={loginUrl(returnTo)} replace />;
  }
  return <>{children}</>;
}

/** Page-level permission gate for people who arrive by URL. The server still enforces every call. */
export function RequireAccess({
  requirement,
  isIndex = false,
  children,
}: {
  requirement: Requirement;
  isIndex?: boolean;
  children: ReactNode;
}) {
  const access = useAccess();
  if (access.can(requirement)) {
    return <>{children}</>;
  }
  const fallback = firstAccessiblePath(access);
  if (isIndex && fallback && fallback !== '/') {
    return <Navigate to={fallback} replace />;
  }
  return (
    <EmptyState icon={ShieldOff} title="You do not have access to this page">
      This page needs the permission <span className="ident">{requirement.permission ?? 'for this area'}</span>
      {requirement.partnerWide ? ' for all organizations' : ''}, which your roles do not include. Ask a Partner Admin if
      you need it.
    </EmptyState>
  );
}

export function NotFound() {
  return (
    <EmptyState
      title="Page not found"
      action={
        <Button asChild variant="outline" size="sm">
          <Link to="/">Go to overview</Link>
        </Button>
      }
    >
      The address may be mistyped, or the page may have moved.
    </EmptyState>
  );
}

export function RouteError() {
  const error = useRouteError();
  return (
    <div className="grid min-h-[50dvh] place-items-center">
      <ErrorState
        error={error}
        what="this page"
        onRetry={() => {
          window.location.reload();
        }}
      />
    </div>
  );
}
