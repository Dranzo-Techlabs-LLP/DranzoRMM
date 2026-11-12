import { Ban, CircleCheck, CircleX, Hourglass, LoaderCircle, Square, type LucideIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { Tone } from '@/components/status';
import { cn } from '@/lib/utils';
import { INDICATOR_NOTICE } from './consent';
import {
  consentSecondsLeft,
  describeConsentResult,
  describeReason,
  PHASE_LABEL,
  type SessionPhase,
  type SessionState,
} from './session-machine';

const LOOK: Record<SessionPhase, { tone: Tone; icon: LucideIcon; spin?: boolean }> = {
  idle: { tone: 'idle', icon: Square },
  starting: { tone: 'info', icon: LoaderCircle, spin: true },
  requested: { tone: 'info', icon: LoaderCircle, spin: true },
  pending_consent: { tone: 'warn', icon: Hourglass },
  active: { tone: 'ok', icon: CircleCheck },
  ended: { tone: 'idle', icon: Square },
  denied: { tone: 'danger', icon: Ban },
  failed: { tone: 'danger', icon: CircleX },
};

const SURFACE: Record<Tone, string> = {
  ok: 'bg-ok-surface text-ok',
  warn: 'bg-warn-surface text-warn',
  danger: 'bg-danger-surface text-danger',
  idle: 'bg-idle-surface text-idle',
  info: 'bg-info-surface text-info',
};

function useNow(enabled: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) {
      return;
    }
    const timer = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      clearInterval(timer);
    };
  }, [enabled]);
  return now;
}

function detail(session: SessionState): string {
  switch (session.phase) {
    case 'starting':
      return 'Sending the request to the server.';
    case 'requested':
      return 'Waiting for the device to answer.';
    case 'pending_consent':
      return 'A prompt is showing on the computer. The session starts only if the person there allows it.';
    case 'active':
      return [describeConsentResult(session.consentResult), INDICATOR_NOTICE].filter(Boolean).join(' ');
    case 'ended':
    case 'denied':
    case 'failed':
      return describeReason(session.reason);
    default:
      return '';
  }
}

/**
 * The state of a session in words, with an icon whose shape differs per state. It is a polite live region, so
 * screen readers announce each change (waiting for consent, connected, declined, ended and why).
 */
export function SessionStatus({ session, className }: { session: SessionState; className?: string }) {
  const waiting = session.phase === 'pending_consent';
  const now = useNow(waiting);
  const left = consentSecondsLeft(session, now);
  const { tone, icon: Icon, spin } = LOOK[session.phase];
  if (session.phase === 'idle') {
    return <div role="status" aria-live="polite" className="sr-only" />;
  }
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn('flex items-start gap-2 rounded-md px-3 py-2 text-sm', SURFACE[tone], className)}
    >
      <Icon aria-hidden="true" className={cn('mt-0.5 size-4 shrink-0', spin && 'motion-safe:animate-spin')} />
      <div className="min-w-0">
        <p className="font-semibold">{PHASE_LABEL[session.phase]}</p>
        <p className="text-foreground">{detail(session)}</p>
        {/* The countdown changes every second; it is kept out of the announcement so it does not interrupt. */}
        {left !== null ? (
          <p className="text-foreground" aria-live="off">
            {left > 0
              ? `If nobody answers, the request is declined in about ${left} ${left === 1 ? 'second' : 'seconds'}.`
              : 'The time to answer has passed. Waiting for the device to confirm.'}
          </p>
        ) : null}
      </div>
    </div>
  );
}
