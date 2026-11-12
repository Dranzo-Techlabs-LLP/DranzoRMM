import { useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { api } from '@/lib/api';
import { clearSession, markPasswordChangeRequired } from './session';

/**
 * Wires app-wide API outcomes to state:
 * - `401 unauthenticated` clears everything; `RequireAuth` then redirects to the sign-in page with the current URL
 *   as the return target.
 * - `403 password_change_required` routes the user to Account (see {@link markPasswordChangeRequired}).
 */
export function SessionWatcher() {
  const queryClient = useQueryClient();
  useEffect(
    () =>
      api.configure({
        onUnauthenticated: () => {
          clearSession(queryClient);
        },
        onPasswordChangeRequired: () => {
          markPasswordChangeRequired(queryClient);
        },
      }),
    [queryClient],
  );
  return null;
}
