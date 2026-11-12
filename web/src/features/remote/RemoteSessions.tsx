import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { api, CSRF_HEADER, errorMessage, isApiError, type ConsentMode, type Id } from '@/lib/api';
import {
  normalizeSessionState,
  remoteApi,
  SESSION_KINDS,
  type SessionCreated,
  type SessionKind,
  type TerminalRunAs,
} from '@/lib/api/remote';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { useLive } from '@/lib/live/LiveProvider';
import { notifyError } from '@/lib/notify';
import { IDLE_SESSION, isOpen, sessionReducer, type SessionEvent, type SessionState } from './session-machine';
import { base64ToBytes, clampTerminalSize, toInputFrames } from './terminal-bytes';

type Sessions = Record<SessionKind, SessionState>;

const INITIAL: Sessions = { terminal: IDLE_SESSION, files: IDLE_SESSION, desktop: IDLE_SESSION };

function reducer(state: Sessions, action: { kind: SessionKind; event: SessionEvent }): Sessions {
  const next = sessionReducer(state[action.kind], action.event);
  return next === state[action.kind] ? state : { ...state, [action.kind]: next };
}

/** Output kept while no terminal view is mounted (another device tab is showing). Oldest data is dropped first. */
const MAX_PENDING_BYTES = 2 * 1024 * 1024;
const DEFAULT_SIZE = { cols: 120, rows: 30 };
const POLL_MS = 3000;

/**
 * The link between the session and the terminal emulator. It outlives the terminal view, so switching device tabs
 * does not lose the screen contents: the emulator instance stays attached to this object.
 */
export interface TerminalChannel {
  readonly runAs: TerminalRunAs;
  /** Output that arrived before a view attached. */
  pending: Uint8Array[];
  /** Set by the terminal view once the emulator exists. */
  sink: ((bytes: Uint8Array) => void) | null;
  /** Set by the terminal view; frees the emulator. */
  dispose: (() => void) | null;
  /** Keyboard and paste input, as bytes. Dropped unless the session is active. */
  input: (bytes: Uint8Array) => void;
  /** The emulator's size changed. */
  resize: (cols: number, rows: number) => void;
}

interface RemoteSessionsValue {
  deviceId: Id;
  sessions: Sessions;
  start: (kind: SessionKind, options?: { runAs?: TerminalRunAs }) => void;
  end: (kind: SessionKind) => void;
  /** Forgets a finished session so a new one can be started. */
  reset: (kind: SessionKind) => void;
  terminal: TerminalChannel | null;
  /** The hub accepted this session's subscription: state changes and terminal output arrive live. */
  joined: (kind: SessionKind) => boolean;
  /** A keystroke could not be delivered since the session became active. */
  inputFailed: boolean;
}

const RemoteSessionsContext = createContext<RemoteSessionsValue | null>(null);

/** Best-effort end that survives the page being closed (`keepalive`). Ending is always the safe direction. */
function endQuietly(sessionId: Id): void {
  const csrf = api.getCsrfToken();
  void fetch(`/api/v1/sessions/${sessionId}/end`, {
    method: 'POST',
    credentials: 'same-origin',
    keepalive: true,
    headers: csrf ? { [CSRF_HEADER]: csrf } : {},
  }).catch(() => undefined);
}

function kindOf(sessions: Sessions, sessionId: Id): SessionKind | undefined {
  return SESSION_KINDS.find((k) => sessions[k].sessionId === sessionId);
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Owns the remote sessions of one device page: starts them, follows their state (hub events, with polling as the
 * fallback), carries terminal bytes, and ends whatever is still open when the technician leaves the page.
 */
export function RemoteSessionsProvider({
  deviceId,
  online,
  children,
}: {
  deviceId: Id;
  online: boolean;
  children: ReactNode;
}) {
  const access = useAccess();
  const { client, state: liveState } = useLive();
  const [sessions, dispatch] = useReducer(reducer, INITIAL);
  const [terminal, setTerminal] = useState<TerminalChannel | null>(null);
  const [joinedIds, setJoinedIds] = useState<ReadonlySet<Id>>(new Set());
  const [inputFailed, setInputFailed] = useState(false);

  const sessionsRef = useRef(sessions);
  const terminalRef = useRef<TerminalChannel | null>(null);
  const clientRef = useRef(client);
  const sizeRef = useRef(DEFAULT_SIZE);
  const resizeTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => {
    sessionsRef.current = sessions;
    clientRef.current = client;
  });
  const canPoll = access.has(P.sessionsRead);

  /** Reads the session from the server: covers state changes that happened before the hub subscription existed. */
  const sync = useCallback(
    async (kind: SessionKind, sessionId: Id) => {
      if (!canPoll) {
        return;
      }
      try {
        const detail = await remoteApi.get(sessionId);
        const state = normalizeSessionState(detail.state);
        if (state) {
          dispatch({
            kind,
            event: {
              type: 'server_state',
              sessionId,
              state,
              reason: detail.endReason,
              consentResult: detail.consentResult,
              at: Date.now(),
            },
          });
        }
      } catch {
        // Polling is a fallback; the hub events and the next poll cover a failed read.
      }
    },
    [canPoll],
  );

  const join = useCallback(async (sessionId: Id) => {
    for (let attempt = 0; attempt < 5; attempt++) {
      const live = clientRef.current;
      if (!live) {
        return;
      }
      try {
        // `false` means the session is already over (or not ours); retrying cannot change that.
        if (await live.invoke<boolean>('JoinSession', sessionId)) {
          setJoinedIds((ids) => new Set(ids).add(sessionId));
        }
        return;
      } catch {
        await sleep(600 * (attempt + 1));
        if (kindOf(sessionsRef.current, sessionId) === undefined) {
          return;
        }
      }
    }
  }, []);

  const sendResize = useCallback(() => {
    const session = sessionsRef.current.terminal;
    if (session.phase === 'active' && session.sessionId) {
      const { cols, rows } = sizeRef.current;
      void clientRef.current?.invoke('TerminalResize', session.sessionId, cols, rows).catch(() => undefined);
    }
  }, []);

  const createChannel = useCallback(
    (runAs: TerminalRunAs): TerminalChannel => ({
      runAs,
      pending: [],
      sink: null,
      dispose: null,
      input: (bytes) => {
        const session = sessionsRef.current.terminal;
        const live = clientRef.current;
        if (session.phase !== 'active' || !session.sessionId || !live) {
          return;
        }
        // Frames are sent in call order over one socket, so the device receives them in order.
        for (const frame of toInputFrames(bytes)) {
          live
            .invoke<boolean>('TerminalInput', session.sessionId, frame)
            .then((ok) => {
              setInputFailed(!ok);
            })
            .catch(() => {
              setInputFailed(true);
            });
        }
      },
      resize: (cols, rows) => {
        sizeRef.current = clampTerminalSize(cols, rows);
        clearTimeout(resizeTimer.current);
        resizeTimer.current = setTimeout(sendResize, 150);
      },
    }),
    [sendResize],
  );

  const start = useCallback(
    (kind: SessionKind, options: { runAs?: TerminalRunAs } = {}) => {
      const current = sessionsRef.current[kind];
      if (current.phase === 'starting' || isOpen(current.phase)) {
        return;
      }
      dispatch({ kind, event: { type: 'start', kind } });
      if (kind === 'terminal') {
        terminalRef.current?.dispose?.();
        const channel = createChannel(options.runAs ?? 'system');
        terminalRef.current = channel;
        setTerminal(channel);
        setInputFailed(false);
      }
      void (async () => {
        let created: SessionCreated;
        try {
          created =
            kind === 'terminal'
              ? await remoteApi.startTerminal(deviceId, { ...sizeRef.current, runAs: options.runAs ?? 'system' })
              : kind === 'files'
                ? await remoteApi.startFiles(deviceId)
                : await remoteApi.startDesktop(deviceId);
        } catch (error) {
          dispatch({ kind, event: { type: 'start_failed', message: errorMessage(error) } });
          if (isApiError(error) && error.code === 'step_up_cancelled') {
            // Nothing was started; go back to the start button instead of showing a failure.
            dispatch({ kind, event: { type: 'reset' } });
          }
          return;
        }
        const consent = (['none', 'notify', 'require'] as const).find((c) => c === created.consent) ?? null;
        dispatch({
          kind,
          event: {
            type: 'created',
            sessionId: created.sessionId,
            consent: consent satisfies ConsentMode | null,
            at: Date.now(),
          },
        });
        await join(created.sessionId);
        await sync(kind, created.sessionId);
      })();
    },
    [createChannel, deviceId, join, sync],
  );

  const end = useCallback((kind: SessionKind) => {
    const session = sessionsRef.current[kind];
    if (!isOpen(session.phase) || !session.sessionId || session.ending) {
      return;
    }
    const sessionId = session.sessionId;
    dispatch({ kind, event: { type: 'end_requested' } });
    remoteApi
      .end(sessionId)
      .then(() => {
        dispatch({
          kind,
          event: { type: 'server_state', sessionId, state: 'ended', reason: 'ended by technician', at: Date.now() },
        });
      })
      .catch((error: unknown) => {
        dispatch({ kind, event: { type: 'end_failed' } });
        notifyError(error);
      });
  }, []);

  const reset = useCallback((kind: SessionKind) => {
    const session = sessionsRef.current[kind];
    if (isOpen(session.phase) || session.phase === 'starting') {
      return;
    }
    if (kind === 'terminal') {
      terminalRef.current?.dispose?.();
      terminalRef.current = null;
      setTerminal(null);
    }
    dispatch({ kind, event: { type: 'reset' } });
  }, []);

  // Hub events for the sessions of this page.
  useEffect(() => {
    if (!client) {
      return;
    }
    const offState = client.on('sessionState', (payload) => {
      const kind = kindOf(sessionsRef.current, payload.sessionId);
      const state = normalizeSessionState(payload.state);
      if (kind && state) {
        dispatch({
          kind,
          event: {
            type: 'server_state',
            sessionId: payload.sessionId,
            state,
            reason: payload.reason,
            consentResult: payload.consentResult,
            at: Date.now(),
          },
        });
      }
    });
    const offOutput = client.on('terminalOutput', (payload) => {
      const channel = terminalRef.current;
      if (!channel || payload.sessionId !== sessionsRef.current.terminal.sessionId) {
        return;
      }
      const bytes = base64ToBytes(payload.data);
      if (channel.sink) {
        channel.sink(bytes);
        return;
      }
      channel.pending.push(bytes);
      let total = channel.pending.reduce((n, chunk) => n + chunk.length, 0);
      while (total > MAX_PENDING_BYTES && channel.pending.length > 1) {
        total -= channel.pending.shift()?.length ?? 0;
      }
    });
    return () => {
      offState();
      offOutput();
    };
  }, [client]);

  // Subscriptions belong to one connection: after a reconnect, join the open sessions again.
  useEffect(() => {
    if (liveState !== 'live') {
      return;
    }
    for (const kind of SESSION_KINDS) {
      const session = sessionsRef.current[kind];
      if (isOpen(session.phase) && session.sessionId) {
        void join(session.sessionId).then(() => sync(kind, session.sessionId ?? ''));
      }
    }
  }, [liveState, join, sync]);

  // Fallback while a session is open: read its state every few seconds in case a hub event was missed.
  const openIds = SESSION_KINDS.filter((k) => isOpen(sessions[k].phase))
    .map((k) => `${k}:${sessions[k].sessionId ?? ''}`)
    .join(',');
  useEffect(() => {
    if (!openIds || !canPoll) {
      return;
    }
    const timer = setInterval(() => {
      for (const kind of SESSION_KINDS) {
        const session = sessionsRef.current[kind];
        if (isOpen(session.phase) && session.sessionId) {
          void sync(kind, session.sessionId);
        }
      }
    }, POLL_MS);
    return () => {
      clearInterval(timer);
    };
  }, [openIds, canPoll, sync]);

  // The emulator's real size is known only once it is on screen; tell the device as soon as the session is active.
  const terminalActive = sessions.terminal.phase === 'active';
  useEffect(() => {
    if (terminalActive) {
      sendResize();
    }
  }, [terminalActive, sendResize]);

  // The server closes a device's sessions when its connection drops; reflect that at once.
  useEffect(() => {
    if (!online) {
      for (const kind of SESSION_KINDS) {
        dispatch({ kind, event: { type: 'device_offline' } });
      }
    }
  }, [online]);

  // Leaving the device page (or closing the tab) ends what is still open: a session must not linger unattended.
  useEffect(() => {
    const endAll = () => {
      for (const kind of SESSION_KINDS) {
        const session = sessionsRef.current[kind];
        if (isOpen(session.phase) && session.sessionId) {
          endQuietly(session.sessionId);
        }
      }
    };
    window.addEventListener('pagehide', endAll);
    return () => {
      window.removeEventListener('pagehide', endAll);
      endAll();
      clearTimeout(resizeTimer.current);
      terminalRef.current?.dispose?.();
      terminalRef.current = null;
    };
  }, []);

  const value = useMemo<RemoteSessionsValue>(
    () => ({
      deviceId,
      sessions,
      start,
      end,
      reset,
      terminal,
      joined: (kind) => {
        const id = sessions[kind].sessionId;
        return id !== null && joinedIds.has(id);
      },
      inputFailed,
    }),
    [deviceId, sessions, start, end, reset, terminal, joinedIds, inputFailed],
  );

  return <RemoteSessionsContext.Provider value={value}>{children}</RemoteSessionsContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useRemoteSessions(): RemoteSessionsValue {
  const ctx = useContext(RemoteSessionsContext);
  if (!ctx) {
    throw new Error('useRemoteSessions() needs <RemoteSessionsProvider>');
  }
  return ctx;
}
