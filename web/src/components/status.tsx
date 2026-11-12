import { Ban, CircleAlert, RotateCw, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/utils';

export type Tone = 'ok' | 'warn' | 'danger' | 'idle' | 'info';

const TONE_TEXT: Record<Tone, string> = {
  ok: 'text-ok',
  warn: 'text-warn',
  danger: 'text-danger',
  idle: 'text-idle',
  info: 'text-info',
};

const TONE_SURFACE: Record<Tone, string> = {
  ok: 'bg-ok-surface text-ok',
  warn: 'bg-warn-surface text-warn',
  danger: 'bg-danger-surface text-danger',
  idle: 'bg-idle-surface text-idle',
  info: 'bg-info-surface text-info',
};

/**
 * Status is never colour alone: each state has its own glyph shape and a text label.
 * Online = solid disc, offline = hollow ring, revoked = barred circle.
 */
function Glyph({ shape, className }: { shape: 'solid' | 'ring'; className?: string }) {
  return (
    <svg viewBox="0 0 10 10" aria-hidden="true" className={cn('size-2.5 shrink-0', className)}>
      {shape === 'solid' ? (
        <circle cx="5" cy="5" r="4.5" fill="currentColor" />
      ) : (
        <circle cx="5" cy="5" r="3.5" fill="none" stroke="currentColor" strokeWidth="2" />
      )}
    </svg>
  );
}

export function StatusPill({
  tone,
  icon: Icon,
  children,
  className,
}: {
  tone: Tone;
  icon?: LucideIcon;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-sm px-1.5 py-0.5 text-xs font-medium whitespace-nowrap',
        TONE_SURFACE[tone],
        className,
      )}
    >
      {Icon ? <Icon aria-hidden="true" className="size-3 shrink-0" /> : null}
      {children}
    </span>
  );
}

function deviceState(device: { isOnline: boolean; status: string }): {
  label: string;
  tone: Tone;
} {
  if (device.status === 'revoked') {
    return { label: 'Revoked', tone: 'danger' };
  }
  return device.isOnline ? { label: 'Online', tone: 'ok' } : { label: 'Offline', tone: 'idle' };
}

export function DeviceStatus({
  device,
  className,
}: {
  device: { isOnline: boolean; status: string };
  className?: string;
}) {
  const { label, tone } = deviceState(device);
  return (
    <span className={cn('inline-flex items-center gap-1.5 font-medium whitespace-nowrap', TONE_TEXT[tone], className)}>
      {tone === 'danger' ? (
        <Ban aria-hidden="true" className="size-3 shrink-0" />
      ) : (
        <Glyph shape={tone === 'ok' ? 'solid' : 'ring'} className={tone === 'ok' ? 'text-ok-mark' : 'text-idle-mark'} />
      )}
      {label}
    </span>
  );
}

export function PendingRebootBadge() {
  return (
    <StatusPill tone="warn" icon={RotateCw}>
      Restart pending
    </StatusPill>
  );
}

export function InlineAlert({
  tone = 'danger',
  title,
  children,
  className,
  live = true,
}: {
  tone?: Tone;
  title?: string;
  children?: ReactNode;
  className?: string;
  /** Announce to assistive technology when it appears (async errors). */
  live?: boolean;
}) {
  return (
    <div
      role={live ? (tone === 'danger' ? 'alert' : 'status') : undefined}
      className={cn('flex items-start gap-2 rounded-md px-3 py-2 text-sm', TONE_SURFACE[tone], className)}
    >
      <CircleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      <div className="min-w-0">
        {title ? <p className="font-semibold">{title}</p> : null}
        {children ? <div className="text-foreground">{children}</div> : null}
      </div>
    </div>
  );
}
