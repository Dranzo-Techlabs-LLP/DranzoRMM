import { useQuery, type QueryClient } from '@tanstack/react-query';
import { useMemo } from 'react';
import { api, authApi, isApiError, qk, type Me } from '@/lib/api';
import { accessFor, type Access } from './permissions';

/**
 * Loads the signed-in user. `null` means "not signed in" (the server answered 401); errors are real failures.
 * The CSRF token from the response is handed to the API client and kept in memory only.
 */
export async function fetchMe(): Promise<Me | null> {
  try {
    const me = await authApi.me();
    api.setCsrfToken(me.csrfToken);
    return me;
  } catch (error) {
    if (isApiError(error) && error.status === 401) {
      api.setCsrfToken(null);
      return null;
    }
    throw error;
  }
}

export function useMeQuery() {
  return useQuery({ queryKey: qk.me, queryFn: fetchMe, staleTime: 60_000, retry: false });
}

/** The signed-in user. Only call below `RequireAuth`, which guarantees a session. */
export function useMe(): Me {
  const { data } = useMeQuery();
  if (!data) {
    throw new Error('useMe() used outside an authenticated route');
  }
  return data;
}

export function useAccess(): Access {
  const { data } = useMeQuery();
  // With a temporary password the server refuses everything but the account endpoints
  // (`403 password_change_required`), so no page, query or live connection is attempted until it is changed.
  return useMemo(
    () => accessFor(data?.user.mustChangePassword ? { permissions: [], partnerWide: false } : data),
    [data],
  );
}

/**
 * Drops every cached server response and marks the session as gone.
 * `explicit` is set when the user chose to sign out: the next person at this browser must land on the default page,
 * not on whatever the previous user was looking at.
 */
export function clearSession(queryClient: QueryClient, options: { explicit?: boolean } = {}): void {
  api.setCsrfToken(null);
  void queryClient.cancelQueries();
  queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== 'auth' || q.queryKey[1] === 'permissions' });
  if (options.explicit) {
    queryClient.setQueryData(qk.signedOut, true);
  }
  queryClient.setQueryData(qk.me, null);
}

export function wasExplicitSignOut(queryClient: QueryClient): boolean {
  return queryClient.getQueryData(qk.signedOut) === true;
}

/** Only same-origin paths are accepted as a return target (no open redirects). */
export function safeReturnTo(value: string | null | undefined): string {
  if (!value?.startsWith('/') || value.startsWith('//') || value.includes('\\') || value.startsWith('/login')) {
    return '/';
  }
  return value;
}

export function loginUrl(returnTo: string): string {
  const target = safeReturnTo(returnTo);
  return target === '/' ? '/login' : `/login?returnTo=${encodeURIComponent(target)}`;
}

/**
 * Reaction to `403 password_change_required` from any call: the user is still on a temporary password (for example
 * an administrator reset it while this tab was open). Marking the cached session makes the shell send every page to
 * Account, where the password can be changed; the session is then re-read from the server.
 */
export function markPasswordChangeRequired(queryClient: QueryClient): void {
  queryClient.setQueryData<Me | null>(qk.me, (me) =>
    me && !me.user.mustChangePassword ? { ...me, user: { ...me.user, mustChangePassword: true } } : me,
  );
}
