import { describe, expect, it } from 'vitest';
import {
  consentSecondsLeft,
  describeReason,
  IDLE_SESSION,
  sessionReducer,
  type SessionEvent,
  type SessionState,
} from './session-machine';

const run = (events: SessionEvent[], from: SessionState = IDLE_SESSION) => events.reduce(sessionReducer, from);
const created: SessionEvent[] = [
  { type: 'start', kind: 'terminal' },
  { type: 'created', sessionId: 's1', consent: 'require', at: 0 },
];
type ServerState = Extract<SessionEvent, { type: 'server_state' }>;
const state = (s: ServerState['state'], extra: Partial<ServerState> = {}): ServerState => ({
  type: 'server_state',
  sessionId: 's1',
  state: s,
  at: 1000,
  ...extra,
});

describe('remote session state machine', () => {
  it('goes requested → waiting for consent → active → ended', () => {
    let s = run(created);
    expect(s).toMatchObject({ phase: 'requested', sessionId: 's1', consent: 'require' });
    s = sessionReducer(s, state('pending_consent', { at: 5000 }));
    expect(s).toMatchObject({ phase: 'pending_consent', consentAskedAt: 5000 });
    s = sessionReducer(s, state('active', { consentResult: 'accepted', at: 9000 }));
    expect(s).toMatchObject({ phase: 'active', consentResult: 'accepted', startedAt: 9000 });
    s = sessionReducer(s, { type: 'end_requested' });
    expect(s.ending).toBe(true);
    s = sessionReducer(s, state('ended', { reason: 'ended by technician' }));
    expect(s).toMatchObject({ phase: 'ended', reason: 'ended by technician', ending: false });
  });

  it('skips consent when the organization does not ask', () => {
    const s = run([...created, state('active', { consentResult: 'not_required' })]);
    expect(s).toMatchObject({ phase: 'active', consentResult: 'not_required' });
  });

  it('records a decline and a timeout as denied with the right consent result', () => {
    const denied = run([...created, state('pending_consent'), state('denied', { reason: 'user_denied' })]);
    expect(denied).toMatchObject({ phase: 'denied', consentResult: 'denied', reason: 'user_denied' });
    const timeout = run([...created, state('pending_consent'), state('denied', { reason: 'timeout' })]);
    expect(timeout).toMatchObject({ phase: 'denied', consentResult: 'timeout' });
    expect(describeReason(timeout.reason)).toMatch(/Nobody answered/);
  });

  it('shows device failures with the device’s own text', () => {
    const s = run([...created, state('failed', { reason: 'not supported in this build' })]);
    expect(s).toMatchObject({ phase: 'failed', reason: 'not supported in this build' });
    expect(describeReason(s.reason)).toBe('not supported in this build.');
  });

  it('fails a start that the server refused', () => {
    const s = run([
      { type: 'start', kind: 'files' },
      { type: 'start_failed', message: 'The device is offline.' },
    ]);
    expect(s).toMatchObject({ phase: 'failed', reason: 'The device is offline.' });
  });

  it('handles the device going offline: not started → failed, active → ended', () => {
    expect(run([...created, { type: 'device_offline' }])).toMatchObject({ phase: 'failed', reason: 'device_offline' });
    expect(run([...created, state('active'), { type: 'device_offline' }])).toMatchObject({
      phase: 'ended',
      reason: 'device_offline',
    });
    // Offline with nothing open changes nothing.
    expect(sessionReducer(IDLE_SESSION, { type: 'device_offline' })).toBe(IDLE_SESSION);
  });

  it('never moves backwards and ignores events of other sessions or after the end', () => {
    const active = run([...created, state('active')]);
    expect(sessionReducer(active, state('pending_consent'))).toBe(active);
    expect(sessionReducer(active, { ...state('ended'), sessionId: 'other' })).toBe(active);
    const ended = sessionReducer(active, state('ended'));
    expect(sessionReducer(ended, state('active'))).toBe(ended);
    expect(sessionReducer(ended, state('failed'))).toBe(ended);
  });

  it('allows one session per kind at a time and resets only when it is over', () => {
    const open = run(created);
    expect(sessionReducer(open, { type: 'start', kind: 'terminal' })).toBe(open);
    expect(sessionReducer(open, { type: 'reset' })).toBe(open);
    const over = sessionReducer(open, state('ended'));
    expect(sessionReducer(over, { type: 'reset' })).toEqual(IDLE_SESSION);
  });

  it('clears the ending flag when ending failed', () => {
    const s = run([...created, state('active'), { type: 'end_requested' }, { type: 'end_failed' }]);
    expect(s).toMatchObject({ phase: 'active', ending: false });
  });

  it('counts down the consent prompt', () => {
    const waiting = run([...created, state('pending_consent', { at: 10_000 })]);
    expect(consentSecondsLeft(waiting, 10_000)).toBe(60);
    expect(consentSecondsLeft(waiting, 40_500)).toBe(30);
    expect(consentSecondsLeft(waiting, 200_000)).toBe(0);
    expect(consentSecondsLeft(run(created), 0)).toBeNull();
  });
});
