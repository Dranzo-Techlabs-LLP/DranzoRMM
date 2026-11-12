import type { Tone } from '@/components/status';
import { isActiveRun, type JobListItem, type JobRunRow } from '@/lib/api/jobs';

/** Labels, tones and small calculations for jobs and runs. */

export const RUN_STATUS: Record<string, { label: string; tone: Tone; explain: string }> = {
  pending: {
    label: 'Waiting',
    tone: 'idle',
    explain: 'Not sent yet. The device gets it when it is connected and free.',
  },
  dispatched: { label: 'Sent', tone: 'info', explain: 'Sent to the device; waiting for it to start.' },
  running: { label: 'Running', tone: 'info', explain: 'The device is running it now.' },
  succeeded: { label: 'Succeeded', tone: 'ok', explain: 'Finished with exit code 0.' },
  failed: { label: 'Failed', tone: 'danger', explain: 'Finished with an error or a non-zero exit code.' },
  timedout: { label: 'Timed out', tone: 'danger', explain: 'Stopped because it ran longer than the time limit.' },
  cancelled: { label: 'Cancelled', tone: 'idle', explain: 'Cancelled before it finished.' },
  rejected: {
    label: 'Rejected',
    tone: 'danger',
    explain: 'The device refused it (failed validation or signature check).',
  },
  unsupported: { label: 'Not supported', tone: 'warn', explain: 'The device’s operating system cannot do this.' },
  expired: { label: 'Expired', tone: 'warn', explain: 'The device did not come online in time.' },
};

export function runStatus(status: string) {
  return RUN_STATUS[status] ?? { label: status, tone: 'idle' as Tone, explain: '' };
}

export const JOB_KINDS: readonly { id: string; label: string }[] = [
  { id: 'script', label: 'Script' },
  { id: 'software.install', label: 'Software install' },
  { id: 'software.uninstall', label: 'Software uninstall' },
  { id: 'package.install', label: 'Package install' },
  { id: 'package.uninstall', label: 'Package uninstall' },
  { id: 'patch.scan', label: 'Update scan' },
  { id: 'patch.install', label: 'Update install' },
  { id: 'reboot', label: 'Restart' },
  { id: 'software.scan', label: 'Software scan' },
  { id: 'inventory.refresh', label: 'Inventory refresh' },
  { id: 'posture.scan', label: 'Security scan' },
  { id: 'policy.evaluate', label: 'Policy check' },
];

export function kindLabel(kind: string): string {
  return JOB_KINDS.find((k) => k.id === kind)?.label ?? kind;
}

/** Seconds between start and finish (or now, while running); `null` before the run started. */
export function runDurationSeconds(
  run: { startedAt: string | null; finishedAt: string | null; status: string },
  now: number = Date.now(),
): number | null {
  if (!run.startedAt) {
    return null;
  }
  const start = Date.parse(run.startedAt);
  const end = run.finishedAt ? Date.parse(run.finishedAt) : isActiveRun(run.status) ? now : NaN;
  if (Number.isNaN(start) || Number.isNaN(end)) {
    return null;
  }
  return Math.max(0, (end - start) / 1000);
}

/** "0.4 s", "12 s", "3 min 05 s", "2 h 10 min". */
export function formatRunDuration(seconds: number | null): string {
  if (seconds === null) {
    return '';
  }
  if (seconds < 10) {
    return `${seconds.toFixed(1)} s`;
  }
  if (seconds < 60) {
    return `${Math.round(seconds)} s`;
  }
  const total = Math.round(seconds);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return h > 0 ? `${h} h ${String(m).padStart(2, '0')} min` : `${m} min ${String(s).padStart(2, '0')} s`;
}

export interface RunCounts {
  total: number;
  succeeded: number;
  failed: number;
  active: number;
  other: number;
}

const FAILED = new Set(['failed', 'timedout', 'rejected']);

/** Same grouping as the server's job list: failed = failed, timed out or rejected. */
export function countRuns(runs: readonly Pick<JobRunRow, 'status'>[]): RunCounts {
  const counts: RunCounts = { total: runs.length, succeeded: 0, failed: 0, active: 0, other: 0 };
  for (const r of runs) {
    if (r.status === 'succeeded') {
      counts.succeeded += 1;
    } else if (FAILED.has(r.status)) {
      counts.failed += 1;
    } else if (isActiveRun(r.status)) {
      counts.active += 1;
    } else {
      counts.other += 1;
    }
  }
  return counts;
}

export function jobOtherCount(job: Pick<JobListItem, 'total' | 'succeeded' | 'failed' | 'active'>): number {
  return Math.max(0, job.total - job.succeeded - job.failed - job.active);
}
