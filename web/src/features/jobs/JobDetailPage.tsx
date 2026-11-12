import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CalendarClock, CircleStop, ListChecks } from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { OsIcon } from '@/components/os';
import { EmptyState, ErrorState, LoadingRows, PageHeader, Panel } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { isActiveRun, jobKeys, jobsApi, type JobDetail } from '@/lib/api/jobs';
import { useAccess } from '@/lib/auth/session';
import { formatBytes, formatDateTime, formatLogTime } from '@/lib/format';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { describeCron } from '../scripts/cron';
import { useRunFeed } from './live';
import { AP } from './permissions';
import { RunCountsSummary, RunStatusChip } from './RunStatusChip';
import { countRuns, formatRunDuration, kindLabel, RUN_STATUS, runDurationSeconds } from './run-model';

const PAGE_SIZE = 100;

export default function JobDetailPage() {
  const { jobId = '' } = useParams();
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: jobKeys.detail(jobId),
    queryFn: () => jobsApi.get(jobId),
  });
  const job = query.data;
  useDocumentTitle(job?.name ?? 'Job');

  const anyActive = job?.runs.some((r) => isActiveRun(r.status)) ?? false;
  // Scheduled jobs get new runs when they fire, so they stay subscribed while enabled.
  const follow = Boolean(job) && (anyActive || Boolean(job?.cron && job.enabled));
  // A big job sends many `jobChanged` events; they collapse into at most one refetch per second.
  const refetchTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const refetchSoon = () => {
    refetchTimer.current ??= setTimeout(() => {
      refetchTimer.current = undefined;
      void queryClient.invalidateQueries({ queryKey: jobKeys.detail(jobId) });
    }, 1000);
  };
  useEffect(
    () => () => {
      clearTimeout(refetchTimer.current);
    },
    [],
  );
  const feed = useRunFeed({
    jobId,
    enabled: follow,
    // The hub only says that the job changed; the details come from the tenant-filtered job endpoint.
    onJobChanged: () => {
      refetchSoon();
    },
    onResync: () => {
      void queryClient.invalidateQueries({ queryKey: jobKeys.detail(jobId) });
    },
  });
  const refetch = query.refetch;
  useEffect(() => {
    if (!follow) {
      return;
    }
    // Live `jobChanged` events trigger refetches; the interval is the fallback without a hub.
    // A schedule waiting for its next run needs no fast polling.
    const t = setInterval(() => void refetch(), !anyActive ? 30_000 : feed === 'live' ? 20_000 : 4_000);
    return () => {
      clearInterval(t);
    };
  }, [follow, feed, refetch, anyActive]);

  if (query.isPending) {
    return <LoadingRows label="job" rows={8} />;
  }
  if (query.isError) {
    return <ErrorState error={query.error} what="this job" onRetry={() => void query.refetch()} />;
  }
  return <JobView job={query.data} live={follow ? feed : null} />;
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className="mt-0.5 break-words">{children}</dd>
    </div>
  );
}

function JobView({ job, live }: { job: JobDetail; live: string | null }) {
  const access = useAccess();
  const queryClient = useQueryClient();
  const [status, setStatus] = useState('');
  const [page, setPage] = useState(1);
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const counts = countRuns(job.runs);
  const cron = job.cron ? describeCron(job.cron) : null;

  useEffect(() => {
    if (counts.active === 0) {
      return;
    }
    const t = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      clearInterval(t);
    };
  }, [counts.active]);

  const cancel = useMutation({
    mutationFn: () => jobsApi.cancel(job.id),
    onSuccess: async (result) => {
      notifySuccess(
        result.cancelled === 0
          ? 'Nothing left to cancel; every run had already finished'
          : `Cancellation sent for ${result.cancelled} ${result.cancelled === 1 ? 'run' : 'runs'}`,
      );
      setConfirmCancel(false);
      await queryClient.invalidateQueries({ queryKey: jobKeys.all });
    },
    onError: notifyError,
  });

  // Newest batch first (a schedule adds a batch each time it fires), then by hostname as the server sorted them.
  const sorted = job.cron
    ? [...job.runs].sort(
        (a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt) || a.hostname.localeCompare(b.hostname),
      )
    : job.runs;
  const filtered = status ? sorted.filter((r) => r.status === status) : sorted;
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pages);
  const rows = filtered.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);
  const statuses = [...new Set(job.runs.map((r) => r.status))];

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Jobs', to: '/jobs' }, { label: job.name }]}
        title={job.name}
        description={`${kindLabel(job.kind)} ${job.isSystem ? 'started by the system' : `requested by ${job.requestedByName || 'an unknown user'}`} on ${formatDateTime(job.createdAt)}.`}
        actions={
          access.has(AP.jobsCancel) && counts.active > 0 ? (
            <Button
              variant="outline"
              onClick={() => {
                setConfirmCancel(true);
              }}
            >
              <CircleStop aria-hidden="true" />
              Cancel job
            </Button>
          ) : undefined
        }
      />

      <dl className="bg-card mb-4 grid grid-cols-2 gap-x-6 gap-y-3 rounded-lg border px-4 py-3 md:grid-cols-4">
        <Fact label="Runs">
          <RunCountsSummary
            succeeded={counts.succeeded}
            failed={counts.failed}
            active={counts.active}
            other={counts.other}
          />
        </Fact>
        <Fact label="Schedule">
          {job.cron ? (
            <>
              <StatusPill tone={job.enabled ? 'info' : 'idle'} icon={CalendarClock}>
                {job.enabled ? 'Scheduled' : 'Paused'}
              </StatusPill>
              <span className="mt-1 block">{cron?.ok ? cron.text : 'Custom schedule'}</span>
              <span className="text-muted-foreground block text-xs">
                <span className="ident">{job.cron}</span> · {job.timeZone ?? 'UTC'}
                {job.enabled && job.nextRunAt ? ` · next ${formatDateTime(job.nextRunAt)} (your time)` : ''}
              </span>
            </>
          ) : (
            <span className="text-muted-foreground">One-off</span>
          )}
        </Fact>
        <Fact label={job.scriptId ? 'Script' : 'Limits'}>
          {job.scriptId ? (
            access.has(AP.scriptsRead) ? (
              <Link
                to={`/scripts/${job.scriptId}?version=${job.scriptVersion ?? ''}`}
                className="text-link hover:underline"
              >
                Version {job.scriptVersion}
              </Link>
            ) : (
              `Version ${job.scriptVersion ?? ''}`
            )
          ) : null}
          <span className="text-muted-foreground block text-xs">
            Time limit {formatRunDuration(job.timeoutSeconds)} · output limit {formatBytes(job.maxOutputBytes)}
          </span>
        </Fact>
        <Fact label="Content SHA-256">
          {job.contentSha256 ? (
            <span className="ident text-xs break-all">{job.contentSha256}</span>
          ) : (
            <span className="text-muted-foreground">Not applicable</span>
          )}
        </Fact>
      </dl>

      <Panel
        flush
        title="Runs per device"
        description={
          live === null
            ? `${counts.total} ${counts.total === 1 ? 'run' : 'runs'}.`
            : live === 'live'
              ? 'Updating live.'
              : live === 'polling'
                ? counts.active > 0
                  ? 'Refreshing every few seconds.'
                  : 'Refreshing every 30 seconds.'
                : 'Connecting for live updates…'
        }
        actions={
          statuses.length > 1 ? (
            <>
              <Label htmlFor="run-status" className="text-xs">
                Status
              </Label>
              <NativeSelect
                id="run-status"
                size="sm"
                value={status}
                onChange={(e) => {
                  setStatus(e.target.value);
                  setPage(1);
                }}
              >
                <NativeSelectOption value="">All ({job.runs.length})</NativeSelectOption>
                {statuses.map((s) => (
                  <NativeSelectOption key={s} value={s}>
                    {RUN_STATUS[s]?.label ?? s} ({job.runs.filter((r) => r.status === s).length})
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            </>
          ) : undefined
        }
      >
        {job.runs.length === 0 ? (
          <EmptyState icon={ListChecks} title="No runs yet">
            {job.cron
              ? 'This schedule has not fired yet. Runs appear here when it does.'
              : 'This job has no runs on devices you can reach.'}
          </EmptyState>
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Device</TableHead>
                  <TableHead scope="col">Status</TableHead>
                  <TableHead scope="col" className="text-right">
                    Exit code
                  </TableHead>
                  <TableHead scope="col" className="text-right">
                    Duration
                  </TableHead>
                  <TableHead scope="col" className="hidden md:table-cell">
                    Started
                  </TableHead>
                  <TableHead scope="col" className="hidden lg:table-cell">
                    Message
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.id}>
                    <TableHead scope="row" className="text-foreground h-auto py-2 font-medium">
                      <Link
                        to={`/jobs/${job.id}/runs/${r.id}`}
                        className="text-link inline-flex items-center gap-1.5 hover:underline"
                      >
                        <OsIcon os={r.os} className="text-muted-foreground" />
                        <span className="ident">{r.hostname}</span>
                      </Link>
                    </TableHead>
                    <TableCell>
                      <RunStatusChip status={r.status} />
                      {r.attempt > 1 ? (
                        <span className="text-muted-foreground ml-1.5 text-xs">attempt {r.attempt}</span>
                      ) : null}
                    </TableCell>
                    <TableCell className="ident text-right">
                      {r.exitCode ?? <span className="text-muted-foreground">–</span>}
                    </TableCell>
                    <TableCell className="text-right">
                      {formatRunDuration(runDurationSeconds(r, now)) || (
                        <span className="text-muted-foreground">–</span>
                      )}
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      {r.startedAt ? (
                        <time dateTime={r.startedAt} title={formatDateTime(r.startedAt, true)}>
                          {formatLogTime(r.startedAt)}
                        </time>
                      ) : (
                        <span className="text-muted-foreground">Not started</span>
                      )}
                    </TableCell>
                    <TableCell className="hidden max-w-96 truncate lg:table-cell" title={r.message ?? undefined}>
                      {r.message}
                      {r.truncated ? (
                        <span className="text-warn ml-1.5 text-xs font-medium">Output truncated</span>
                      ) : null}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {filtered.length > PAGE_SIZE ? (
              <Pagination
                page={current}
                pageSize={PAGE_SIZE}
                total={filtered.length}
                noun="runs"
                onPageChange={setPage}
              />
            ) : null}
          </>
        )}
      </Panel>

      <ConfirmDialog
        open={confirmCancel}
        onOpenChange={setConfirmCancel}
        title={`Cancel ${counts.active} ${counts.active === 1 ? 'run' : 'runs'} of “${job.name}”?`}
        description={
          <>
            <p>
              Runs that have not started are cancelled at once. Runs already in progress are told to stop; a device
              confirms when it has stopped. Finished runs are not affected.
            </p>
            {job.cron ? <p>The schedule itself stays. Pause or delete it under Jobs, Schedules.</p> : null}
          </>
        }
        confirmLabel={`Cancel ${counts.active} ${counts.active === 1 ? 'run' : 'runs'}`}
        destructive
        pending={cancel.isPending}
        onConfirm={() => {
          cancel.mutate();
        }}
      />
    </>
  );
}
