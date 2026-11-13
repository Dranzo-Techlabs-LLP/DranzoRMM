import { CircleCheck, CircleHelp, CircleX, ShieldAlert } from 'lucide-react';
import { StatusPill, type Tone } from '@/components/status';
import type { TriState } from '@/lib/api/security';
import { nvdUrl, scoreTone } from './posture-model';
import { cn } from '@/lib/utils';

/**
 * A posture answer with three outcomes. Each has its own icon shape and its own word, so it reads the same without
 * colour: tick "OK", cross "Problem", question mark "Unknown".
 */
export function TriStateMark({
  value,
  okLabel = 'OK',
  issueLabel = 'Problem',
  unknownLabel = 'Unknown',
  className,
}: {
  value: TriState | undefined;
  okLabel?: string;
  issueLabel?: string;
  unknownLabel?: string;
  className?: string;
}) {
  const [Icon, label, tone] =
    value === true
      ? ([CircleCheck, okLabel, 'text-ok'] as const)
      : value === false
        ? ([CircleX, issueLabel, 'text-danger'] as const)
        : ([CircleHelp, unknownLabel, 'text-idle'] as const);
  return (
    <span className={cn('inline-flex items-center gap-1 font-medium whitespace-nowrap', tone, className)}>
      <Icon aria-hidden="true" className="size-3.5 shrink-0" />
      {label}
    </span>
  );
}

const VULN_SEVERITY: Record<string, { label: string; tone: Tone }> = {
  critical: { label: 'Critical', tone: 'danger' },
  high: { label: 'High', tone: 'danger' },
  medium: { label: 'Medium', tone: 'warn' },
  low: { label: 'Low', tone: 'idle' },
};
export function VulnSeverity({ severity }: { severity: string }) {
  const look = VULN_SEVERITY[severity.toLowerCase()];
  return look ? (
    <StatusPill tone={look.tone}>{look.label}</StatusPill>
  ) : (
    <span className="text-muted-foreground">{severity || 'Not rated'}</span>
  );
}

export function KnownExploitedBadge() {
  return (
    <StatusPill tone="danger" icon={ShieldAlert}>
      Known exploited
    </StatusPill>
  );
}

export function CveLink({ cveId }: { cveId: string }) {
  const url = nvdUrl(cveId);
  return url ? (
    <a href={url} target="_blank" rel="noopener noreferrer" className="ident text-link font-medium hover:underline">
      {cveId}
      <span className="sr-only"> (opens the NVD page in a new tab)</span>
    </a>
  ) : (
    <span className="ident font-medium">{cveId}</span>
  );
}

/** Score with its grade, for tables. Colour is never the only signal: the number and letter are always shown. */
export function ScoreBadge({ score, grade }: { score: number | null; grade: string }) {
  return <StatusPill tone={scoreTone(score)}>{score === null ? 'No score' : `${score} · ${grade}`}</StatusPill>;
}
