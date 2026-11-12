import type { ConsentMode } from '@/lib/api';
import type { SessionKind, SessionStateName } from '@/lib/api/remote';

/**
 * State of one remote session as this browser tab sees it. Driven by the start request, `sessionState` hub events,
 * polling of `GET /sessions/{id}` and the device going offline. Pure: no timers, no network.
 *
 *   idle → starting → requested → (pending_consent) → active → ended
 *                         ↘ denied / failed                ↘ failed
 */
export type SessionPhase = 'idle' | 'starting' | SessionStateName;

export interface SessionState {
  phase: SessionPhase;
  kind: SessionKind | null;
  sessionId: string | null;
  /** The organization's consent mode, as the server applied it to this session. */
  consent: ConsentMode | null;
  /** `accepted`, `notified`, `not_required`, `no_user_logged_in`, `denied` or `timeout`. */
  consentResult: string | null;
  /** Why the session ended, was denied or failed (server or device wording), or why it could not start. */
  reason: string | null;
  /** When the device started waiting for the person's answer (ms since epoch); drives the countdown hint. */
  consentAskedAt: number | null;
  startedAt: number | null;
  /** The technician asked to end the session and the server has not confirmed yet. */
  ending: boolean;
}

export type SessionEvent =
  | { type: 'start'; kind: SessionKind }
  | { type: 'start_failed'; message: string }
  | { type: 'created'; sessionId: string; consent: ConsentMode | null; at: number }
  /** From a `sessionState` hub event or from `GET /sessions/{id}`. */
  | {
      type: 'server_state';
      sessionId: string;
      state: SessionStateName;
      reason?: string | null;
      consentResult?: string | null;
      at: number;
    }
  /** The live `device` event reported the device offline. The server ends its sessions ("connection lost"). */
  | { type: 'device_offline' }
  | { type: 'end_requested' }
  | { type: 'end_failed' }
  | { type: 'reset' };

/** The device waits this long for an answer before it treats the request as declined (`consentTimeoutSeconds`). */
export const CONSENT_TIMEOUT_SECONDS = 60;

export const IDLE_SESSION: SessionState = {
  phase: 'idle',
  kind: null,
  sessionId: null,
  consent: null,
  consentResult: null,
  reason: null,
  consentAskedAt: null,
  startedAt: null,
  ending: false,
};

const ORDER: Record<SessionPhase, number> = {
  idle: 0,
  starting: 1,
  requested: 2,
  pending_consent: 3,
  active: 4,
  ended: 5,
  denied: 5,
  failed: 5,
};

export function isOver(phase: SessionPhase): boolean {
  return phase === 'ended' || phase === 'denied' || phase === 'failed';
}

/** A session exists on the server and has not finished. */
export function isOpen(phase: SessionPhase): boolean {
  return phase === 'requested' || phase === 'pending_consent' || phase === 'active';
}

export function sessionReducer(state: SessionState, event: SessionEvent): SessionState {
  switch (event.type) {
    case 'start':
      // One session per kind at a time: ignore a second start while one is being opened or is open.
      if (state.phase === 'starting' || isOpen(state.phase)) {
        return state;
      }
      return { ...IDLE_SESSION, phase: 'starting', kind: event.kind };

    case 'start_failed':
      return state.phase === 'starting' ? { ...state, phase: 'failed', reason: event.message } : state;

    case 'created':
      if (state.phase !== 'starting') {
        return state;
      }
      return { ...state, phase: 'requested', sessionId: event.sessionId, consent: event.consent };

    case 'server_state': {
      // Late events of an earlier session, and anything after the end, change nothing.
      if (event.sessionId !== state.sessionId || isOver(state.phase) || !isOpen(state.phase)) {
        return state;
      }
      // Events can arrive out of order (hub versus polling); the state never moves backwards.
      if (ORDER[event.state] < ORDER[state.phase] || event.state === state.phase) {
        return state;
      }
      switch (event.state) {
        case 'pending_consent':
          return { ...state, phase: 'pending_consent', consentAskedAt: event.at };
        case 'active':
          return {
            ...state,
            phase: 'active',
            startedAt: event.at,
            consentResult: event.consentResult ?? state.consentResult,
          };
        case 'denied':
          return {
            ...state,
            phase: 'denied',
            ending: false,
            reason: event.reason ?? 'user_denied',
            consentResult: event.consentResult ?? (event.reason === 'timeout' ? 'timeout' : 'denied'),
          };
        case 'failed':
          return { ...state, phase: 'failed', ending: false, reason: event.reason ?? 'failed' };
        case 'ended':
          return { ...state, phase: 'ended', ending: false, reason: event.reason ?? 'ended' };
        default:
          return state;
      }
    }

    case 'device_offline':
      if (!isOpen(state.phase)) {
        return state;
      }
      // Before the session was active it never started; afterwards it ended.
      return {
        ...state,
        phase: state.phase === 'active' ? 'ended' : 'failed',
        ending: false,
        reason: 'device_offline',
      };

    case 'end_requested':
      return isOpen(state.phase) ? { ...state, ending: true } : state;

    case 'end_failed':
      return state.ending ? { ...state, ending: false } : state;

    case 'reset':
      // A running session cannot be forgotten; it has to be ended first.
      return isOpen(state.phase) || state.phase === 'starting' ? state : IDLE_SESSION;
  }
}

/** Seconds left for the person at the computer to answer; `null` when no prompt is showing. */
export function consentSecondsLeft(state: SessionState, now: number): number | null {
  if (state.phase !== 'pending_consent' || state.consentAskedAt === null) {
    return null;
  }
  return Math.max(0, CONSENT_TIMEOUT_SECONDS - Math.floor((now - state.consentAskedAt) / 1000));
}

const REASONS: Record<string, string> = {
  user_denied: 'The person at the computer declined the request.',
  denied: 'The person at the computer declined the request.',
  timeout: 'Nobody answered the request in time, so it was treated as declined.',
  device_offline: 'The device went offline.',
  'connection lost': 'The device lost its connection to the server, so the session was closed.',
  'ended by technician': 'You ended the session.',
  ended: 'The session ended.',
  'ended locally': 'The session was ended at the computer.',
  ended_locally: 'The session was ended at the computer (from the on-screen indicator).',
  consent_unavailable: 'The computer could not show the consent prompt, so the session did not start.',
  consent_prompt_failed: 'The consent prompt failed on the computer, so the session did not start.',
  indicator_unavailable: 'The computer could not show the on-screen indicator, so the session did not start.',
  too_many_sessions: 'The computer already has the maximum number of remote sessions open.',
  ended_by_server: 'The session was ended.',
  terminal_exited: 'The shell on the computer exited.',
  max_duration: 'The session reached its maximum length and was closed.',
  connection_lost: 'The device lost its connection to the server, so the session was closed.',
  no_user_logged_in: 'Nobody is logged in at the computer.',
  'idle timeout': 'The session was closed after 30 minutes without activity.',
  'maximum session length reached': 'The session reached the 12-hour limit and was closed.',
  'no response from the device': 'The device did not respond to the request.',
  'server restarted': 'The server restarted, which closes every session.',
  failed: 'The device could not start the session.',
};

/**
 * Sentence for the reason a session is over. Known reasons are reworded; anything else is the device's or
 * server's own text and is shown as it came (as text, never as markup).
 */
export function describeReason(reason: string | null): string {
  if (!reason) {
    return 'The session is over.';
  }
  const known = REASONS[reason] ?? REASONS[reason.toLowerCase()];
  if (known) {
    return known;
  }
  const text = reason.trim();
  return /[.!?]$/.test(text) ? text : `${text}.`;
}

/** What the person at the computer experienced when the session started. */
export function describeConsentResult(result: string | null): string | null {
  switch (result) {
    case 'accepted':
      return 'The person at the computer allowed this session.';
    case 'notified':
      return 'The person at the computer was notified.';
    case 'not_required':
      return 'This organization does not ask before a session starts.';
    case 'no_user_logged_in':
      return 'Nobody is logged in at the computer, so there was nobody to ask.';
    case 'denied':
      return 'The person at the computer declined.';
    case 'timeout':
      return 'Nobody answered the request.';
    default:
      return null;
  }
}

export const PHASE_LABEL: Record<SessionPhase, string> = {
  idle: 'Not started',
  starting: 'Starting',
  requested: 'Contacting the device',
  pending_consent: 'Waiting for the person at the computer',
  active: 'Connected',
  ended: 'Ended',
  denied: 'Declined',
  failed: 'Failed',
};
