import { useQueryClient } from '@tanstack/react-query';
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { P } from '@/lib/auth/permissions';
import { useAccess, useMe } from '@/lib/auth/session';
import { refreshAfterAlertEvent } from './alert-events';
import { applyDeviceEvent, refreshAfterDeviceEvents } from './device-events';
import { createLiveClient, type LiveClient, type LiveState } from './hub';

interface LiveContextValue {
  state: LiveState;
  /** False when the user cannot use the hub (it requires `devices.read`). */
  available: boolean;
  /**
   * The connection, for features that subscribe to their own events or call hub methods (run output, remote
   * sessions). `null` when the hub is not available to this user.
   */
  client: LiveClient | null;
}

const LiveContext = createContext<LiveContextValue>({ state: 'offline', available: false, client: null });

const REFRESH_DELAY_MS = 1500;

/**
 * Owns the SignalR connection for the signed-in user and keeps device and alert data current.
 * `createClient` is injectable for tests.
 */
export function LiveProvider({
  children,
  createClient = createLiveClient,
}: {
  children: ReactNode;
  createClient?: (csrfToken: string) => LiveClient;
}) {
  const me = useMe();
  const access = useAccess();
  const queryClient = useQueryClient();
  const available = access.has(P.devicesRead);
  const [state, setState] = useState<LiveState>('offline');
  const [client, setClient] = useState<LiveClient | null>(null);
  const csrfToken = me.csrfToken;

  useEffect(() => {
    if (!available) {
      return;
    }
    const live = createClient(csrfToken);
    let deviceTimer: ReturnType<typeof setTimeout> | undefined;
    let alertTimer: ReturnType<typeof setTimeout> | undefined;
    // The connection is handed to features once it starts connecting (its first state change).
    const offState = live.onState((next) => {
      setState(next);
      setClient(live);
    });
    const offDevice = live.on('device', (payload) => {
      if (applyDeviceEvent(queryClient, payload)) {
        // Bursts (many agents reconnecting) collapse into one refetch; a steady stream still refreshes regularly.
        deviceTimer ??= setTimeout(() => {
          deviceTimer = undefined;
          refreshAfterDeviceEvents(queryClient);
        }, REFRESH_DELAY_MS);
      }
    });
    const offAlert = live.on('alert', () => {
      alertTimer ??= setTimeout(() => {
        alertTimer = undefined;
        refreshAfterAlertEvent(queryClient);
      }, REFRESH_DELAY_MS);
    });
    void live.start();
    return () => {
      clearTimeout(deviceTimer);
      clearTimeout(alertTimer);
      offState();
      offDevice();
      offAlert();
      void live.stop();
      setClient(null);
      setState('offline');
    };
  }, [available, csrfToken, createClient, queryClient]);

  const value = useMemo(() => ({ state, available, client }), [state, available, client]);
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useLive(): LiveContextValue {
  return useContext(LiveContext);
}
