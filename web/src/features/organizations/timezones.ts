import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';
import { authApi, qk } from '@/lib/api';

/** IANA time zones the browser knows, with UTC and the current value always present. */
export function timeZoneOptions(current?: string): string[] {
  let zones: string[] = [];
  try {
    zones = Intl.supportedValuesOf('timeZone');
  } catch {
    // Very old browsers: fall back to the essentials below.
  }
  const set = new Set(zones);
  set.add('UTC');
  if (current) {
    set.add(current);
  }
  return [...set].sort((a, b) => a.localeCompare(b));
}

export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

/**
 * Time zones for a select: the server's list (`GET /auth/time-zones`, the ids it accepts) when it loads, otherwise
 * the browser's. The current value is always included.
 */
export function useTimeZoneOptions(current?: string): string[] {
  const server = useQuery({ queryKey: qk.timeZones, queryFn: authApi.timeZones, staleTime: Infinity, retry: false });
  return useMemo(() => {
    if (!server.data || server.data.length === 0) {
      return timeZoneOptions(current);
    }
    const set = new Set(server.data);
    if (current) {
      set.add(current);
    }
    return [...set].sort((a, b) => a.localeCompare(b));
  }, [server.data, current]);
}
