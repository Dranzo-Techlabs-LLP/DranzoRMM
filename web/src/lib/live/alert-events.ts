import type { QueryClient } from '@tanstack/react-query';

/** Root of every alert query key (`lib/api/alerts.ts` builds its keys on it). */
export const ALERTS_KEY = ['alerts'] as const;

/** An `alert` hub event means some alert opened or changed state: refetch alert lists and the open-alert count. */
export function refreshAfterAlertEvent(queryClient: QueryClient): void {
  void queryClient.invalidateQueries({ queryKey: ALERTS_KEY });
}
