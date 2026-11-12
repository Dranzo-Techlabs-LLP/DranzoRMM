import { HubConnectionBuilder, HubConnectionState, LogLevel, type HubConnection } from '@microsoft/signalr';
import { CSRF_HEADER } from '@/lib/api';
import type { DeviceEvent } from '@/lib/api';

export const LIVE_HUB_URL = '/hubs/live';

export type LiveState = 'connecting' | 'live' | 'reconnecting' | 'offline';

/** `alert`: an alert opened, was acknowledged or resolved on a device the caller can see. */
export interface AlertEvent {
  id: string;
  deviceId: string;
  type: string;
  severity: string;
  title: string;
  state: string;
}

/** `sessionState`: a remote session the caller joined changed state (docs/PROTOCOL.md section 6.5). */
export interface SessionStateEvent {
  sessionId: string;
  state: string;
  reason?: string | null;
  consentResult?: string | null;
}

/** `terminalOutput`: bytes from the device's terminal, base64. `seq` increases by one per frame. */
export interface TerminalOutputEvent {
  sessionId: string;
  seq: number;
  data: string;
}

/** Events pushed by the server's `LiveNotifier`. */
export interface LiveEvents {
  device: DeviceEvent;
  run: unknown;
  runOutput: unknown;
  runSummary: unknown;
  alert: AlertEvent;
  sessionState: SessionStateEvent;
  terminalOutput: TerminalOutputEvent;
}

export interface LiveClient {
  start: () => Promise<void>;
  stop: () => Promise<void>;
  on: <K extends keyof LiveEvents>(event: K, handler: (payload: LiveEvents[K]) => void) => () => void;
  onState: (handler: (state: LiveState) => void) => () => void;
  state: () => LiveState;
  /**
   * Calls a hub method (`JoinSession`, `TerminalInput`, `SubscribeRun`, ...). Rejects when the connection is not
   * live. Group membership is per connection: after a reconnect, join or subscribe again.
   */
  invoke: <T = unknown>(method: string, ...args: unknown[]) => Promise<T>;
}

/**
 * SignalR connection to `/hubs/live`. Authenticated by the session cookie (same origin). The negotiate request is a
 * POST, so it carries the CSRF header like every other unsafe request.
 */
export function createLiveClient(csrfToken: string): LiveClient {
  const connection: HubConnection = new HubConnectionBuilder()
    .withUrl(LIVE_HUB_URL, { headers: { [CSRF_HEADER]: csrfToken }, withCredentials: true })
    .withAutomaticReconnect({
      // Keep trying with a capped backoff; the dashboard is often left open all day.
      nextRetryDelayInMilliseconds: (ctx) => Math.min(30_000, 1000 * 2 ** Math.min(ctx.previousRetryCount, 5)),
    })
    .configureLogging(LogLevel.Error)
    .build();

  let current: LiveState = 'offline';
  let stopped = false;
  let starting: Promise<void> | null = null;
  const listeners = new Set<(state: LiveState) => void>();
  const setState = (next: LiveState) => {
    if (next !== current) {
      current = next;
      listeners.forEach((l) => l(next));
    }
  };

  connection.onreconnecting(() => setState('reconnecting'));
  connection.onreconnected(() => setState('live'));
  connection.onclose(() => setState('offline'));

  return {
    async start() {
      if (stopped || connection.state !== HubConnectionState.Disconnected) {
        return;
      }
      setState('connecting');
      starting = connection.start();
      try {
        await starting;
        setState('live');
      } catch {
        // The hub refuses callers without devices.read, and the server may be restarting. Lists still refresh by polling.
        setState('offline');
      } finally {
        starting = null;
      }
    },
    async stop() {
      stopped = true;
      // Let an in-flight negotiation finish first; stopping mid-negotiation makes SignalR log an error.
      await starting?.catch(() => undefined);
      await connection.stop();
    },
    on(event, handler) {
      const wrapped = (payload: unknown) => {
        handler(payload as LiveEvents[typeof event]);
      };
      connection.on(event, wrapped);
      return () => {
        connection.off(event, wrapped);
      };
    },
    onState(handler) {
      listeners.add(handler);
      return () => listeners.delete(handler);
    },
    state: () => current,
    invoke<T>(method: string, ...args: unknown[]) {
      if (connection.state !== HubConnectionState.Connected) {
        return Promise.reject(new Error('Live connection is not available.'));
      }
      return connection.invoke<T>(method, ...args);
    },
  };
}
