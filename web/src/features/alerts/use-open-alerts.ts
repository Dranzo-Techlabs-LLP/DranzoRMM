import { useQuery } from '@tanstack/react-query';
import { alertKeys, alertsApi } from '@/lib/api/alerts';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';

/**
 * Number of open alerts the user can see (all organizations), for the badge in the navigation. Refreshed by the
 * live `alert` event and once a minute as a fallback. `undefined` while unknown or when the user cannot read alerts.
 */
export function useOpenAlertCount(): number | undefined {
  const access = useAccess();
  const query = useQuery({
    queryKey: alertKeys.openCount(),
    queryFn: async ({ signal }) => (await alertsApi.list({ state: 'open', page: 1, pageSize: 1 }, signal)).total,
    enabled: access.has(P.alertsRead),
    refetchInterval: 60_000,
    staleTime: 10_000,
  });
  return query.data;
}
