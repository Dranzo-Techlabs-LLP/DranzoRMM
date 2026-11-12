import {
  Ban,
  CircleCheck,
  CircleDashed,
  CircleSlash,
  Clock,
  LoaderCircle,
  Send,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react';
import { StatusPill } from '@/components/status';
import { runStatus } from './run-model';

const ICONS: Record<string, LucideIcon> = {
  pending: CircleDashed,
  dispatched: Send,
  running: LoaderCircle,
  succeeded: CircleCheck,
  failed: TriangleAlert,
  timedout: Clock,
  cancelled: Ban,
  rejected: CircleSlash,
  unsupported: CircleSlash,
  expired: Clock,
};

/** Run status with its own icon shape and a text label, so it never depends on colour alone. */
export function RunStatusChip({ status, className }: { status: string; className?: string }) {
  const s = runStatus(status);
  return (
    <span title={s.explain || undefined}>
      <StatusPill tone={s.tone} icon={ICONS[status]} className={className}>
        {s.label}
      </StatusPill>
    </span>
  );
}

/** "12 succeeded · 1 failed · 3 active" for job rows; zero counts are left out. */
export function RunCountsSummary({
  succeeded,
  failed,
  active,
  other = 0,
}: {
  succeeded: number;
  failed: number;
  active: number;
  other?: number;
}) {
  if (succeeded + failed + active + other === 0) {
    return <span className="text-muted-foreground">No runs yet</span>;
  }
  return (
    <span className="inline-flex flex-wrap gap-1">
      {active > 0 ? (
        <StatusPill tone="info" icon={LoaderCircle}>
          {active} active
        </StatusPill>
      ) : null}
      {succeeded > 0 ? (
        <StatusPill tone="ok" icon={CircleCheck}>
          {succeeded} succeeded
        </StatusPill>
      ) : null}
      {failed > 0 ? (
        <StatusPill tone="danger" icon={TriangleAlert}>
          {failed} failed
        </StatusPill>
      ) : null}
      {other > 0 ? (
        <StatusPill tone="idle" icon={Ban}>
          {other} other
        </StatusPill>
      ) : null}
    </span>
  );
}
