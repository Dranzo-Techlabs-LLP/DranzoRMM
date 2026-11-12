import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CircleStop } from 'lucide-react';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link, useParams } from 'react-router';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { CopyButton } from '@/components/copy-button';
import { ErrorState, LoadingRows, PageHeader, Panel } from '@/components/page';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { isActiveRun, jobKeys, runsApi, type RunDetail } from '@/lib/api/jobs';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { formatBytes, formatDateTime } from '@/lib/format';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { useRunFeed, type RunFeedState } from './live';
import { EMPTY_OUTPUT, mergeOutput, outputFileName, type OutputState } from './output';
import { OutputViewer } from './OutputViewer';
import { AP } from './permissions';
import { RunStatusChip } from './RunStatusChip';
import { formatRunDuration, kindLabel, runDurationSeconds, runStatus } from './run-model';

export default function RunDetailPage() {
  const { runId = '' } = useParams();
  // Keyed so live output of one run can never leak into another when navigating between runs.
  return <RunPage key={runId} runId={runId} />;
}

function RunPage({ runId }: { runId: string }) {
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: jobKeys.run(runId), queryFn: () => runsApi.get(runId) });
  const run = query.data;
  useDocumentTitle(run ? `${run.jobName} on ${run.hostname}` : 'Run');
  const [live, setLive] = useState<OutputState>(EMPTY_OUTPUT);
  const active = run ? isActiveRun(run.status) : false;
  const refetch = query.refetch;

  const feed = useRunFeed({
    runId,
    enabled: active,
    onOutput: (event) => {
      setLive((prev) => mergeOutput(prev, [event]));
    },
    onRun: (event) => {
      queryClient.setQueryData<RunDetail>(jobKeys.run(runId), (prev) =>
        prev
          ? {
              ...prev,
              status: event.status,
              exitCode: event.exitCode,
              message: event.message,
              truncated: prev.truncated || event.truncated,
              finishedAt: event.finishedAt ?? prev.finishedAt,
            }
          : prev,
      );
      // The stored run has the final hash, byte count and timings.
      void refetch();
    },
    // Chunks sent before the subscription was in place are only in the stored output.
    onResync: () => void refetch(),
  });

  useEffect(() => {
    if (!active) {
      return;
    }
    const t = setInterval(() => void refetch(), feed === 'live' ? 15_000 : 2_500);
    return () => {
      clearInterval(t);
    };
  }, [active, feed, refetch]);

  // Stored chunks first, then whatever arrived live; duplicates are dropped by sequence number.
  const output = useMemo(
    () => mergeOutput(mergeOutput(EMPTY_OUTPUT, run?.output ?? []), live.chunks),
    [run?.output, live.chunks],
  );

  if (query.isPending) {
    return <LoadingRows label="run" rows={8} />;
  }
  if (query.isError) {
    return <ErrorState error={query.error} what="this run" onRetry={() => void query.refetch()} />;
  }
  return <RunView run={query.data} output={output} feed={active ? feed : null} />;
}

function Fact({ label, children, wide = false }: { label: string; children: ReactNode; wide?: boolean }) {
  return (
    <div className={wide ? 'col-span-2 min-w-0' : 'min-w-0'}>
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className="mt-0.5 break-words">{children}</dd>
    </div>
  );
}

function Time({ value, fallback }: { value: string | null; fallback: string }) {
  return value ? (
    <time dateTime={value}>{formatDateTime(value, true)}</time>
  ) : (
    <span className="text-muted-foreground">{fallback}</span>
  );
}

function RunView({ run, output, feed }: { run: RunDetail; output: OutputState; feed: RunFeedState | null }) {
  const access = useAccess();
  const queryClient = useQueryClient();
  const [confirmCancel, setConfirmCancel] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const active = isActiveRun(run.status);
  const status = runStatus(run.status);

  useEffect(() => {
    if (!active) {
      return;
    }
    const t = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      clearInterval(t);
    };
  }, [active]);

  const cancel = useMutation({
    mutationFn: () => runsApi.cancel(run.id),
    onSuccess: async () => {
      notifySuccess('Cancellation sent');
      setConfirmCancel(false);
      await queryClient.invalidateQueries({ queryKey: jobKeys.run(run.id) });
      await queryClient.invalidateQueries({ queryKey: jobKeys.detail(run.jobId) });
    },
    onError: async (error) => {
      notifyError(error);
      setConfirmCancel(false);
      await queryClient.invalidateQueries({ queryKey: jobKeys.run(run.id) });
    },
  });

  const statusText = !active
    ? `${status.label}. ${output.chunks.length === 0 ? 'No output.' : 'Complete output.'}`
    : run.status === 'pending'
      ? 'Waiting for the device.'
      : feed === 'live'
        ? 'Receiving output live.'
        : feed === 'reconnecting' || feed === 'connecting'
          ? 'Connecting for live output…'
          : 'Refreshing output every few seconds.';
  const result = run.result === null || run.result === undefined ? null : JSON.stringify(run.result, null, 2);

  return (
    <>
      <PageHeader
        crumbs={[
          { label: 'Jobs', to: '/jobs' },
          { label: run.jobName, to: `/jobs/${run.jobId}` },
          { label: run.hostname },
        ]}
        title={
          <>
            {run.jobName} <span className="text-muted-foreground font-normal">on</span>{' '}
            <span className="ident">{run.hostname}</span>
          </>
        }
        description={`${kindLabel(run.kind)} requested by ${run.requestedBy || 'the system'}.`}
        actions={
          access.has(AP.jobsCancel) && active ? (
            <Button
              variant="outline"
              onClick={() => {
                setConfirmCancel(true);
              }}
            >
              <CircleStop aria-hidden="true" />
              Cancel run
            </Button>
          ) : undefined
        }
      />

      <dl className="bg-card mb-4 grid grid-cols-2 gap-x-6 gap-y-3 rounded-lg border px-4 py-3 md:grid-cols-4">
        <Fact label="Status">
          <span role="status" aria-live="polite">
            <RunStatusChip status={run.status} />
          </span>
          {status.explain ? <span className="text-muted-foreground mt-1 block text-xs">{status.explain}</span> : null}
        </Fact>
        <Fact label="Exit code">
          {run.exitCode !== null ? (
            <span className="ident text-base font-semibold">{run.exitCode}</span>
          ) : (
            <span className="text-muted-foreground">{active ? 'Not finished' : 'None reported'}</span>
          )}
        </Fact>
        <Fact label="Duration">
          {formatRunDuration(runDurationSeconds(run, now)) || (
            <span className="text-muted-foreground">Not started</span>
          )}
          {run.maxAttempts > 1 ? (
            <span className="text-muted-foreground block text-xs">
              Attempt {run.attempt} of {run.maxAttempts}
            </span>
          ) : null}
        </Fact>
        <Fact label="Device">
          {access.has(P.devicesRead) ? (
            <Link to={`/devices/${run.deviceId}?tab=scripts`} className="text-link ident hover:underline">
              {run.hostname}
            </Link>
          ) : (
            <span className="ident">{run.hostname}</span>
          )}
        </Fact>
        <Fact label="Requested">
          <Time value={run.createdAt} fallback="" />
        </Fact>
        <Fact label="Sent to device">
          <Time value={run.dispatchedAt} fallback="Not yet" />
        </Fact>
        <Fact label="Started">
          <Time value={run.startedAt} fallback="Not yet" />
        </Fact>
        <Fact label="Finished">
          <Time value={run.finishedAt} fallback="Not yet" />
        </Fact>
        <Fact label="Output size">
          {formatBytes(run.outputBytes)}
          {run.truncated ? <span className="text-warn ml-1.5 text-xs font-medium">truncated</span> : null}
        </Fact>
        <Fact label="SHA-256 of output" wide>
          {run.outputSha256 ? (
            <span className="flex items-start gap-2">
              <span className="ident min-w-0 text-xs break-all">{run.outputSha256}</span>
              <CopyButton value={run.outputSha256} label="Copy hash" size="xs" variant="ghost" />
            </span>
          ) : (
            <span className="text-muted-foreground">{active ? 'Reported when the run finishes' : 'Not reported'}</span>
          )}
        </Fact>
      </dl>

      {run.message ? (
        <InlineAlert
          tone={status.tone === 'ok' ? 'info' : status.tone}
          live={false}
          className="mb-4"
          title="Message from the device"
        >
          <span className="break-words whitespace-pre-wrap">{run.message}</span>
        </InlineAlert>
      ) : null}

      <OutputViewer
        chunks={output.chunks}
        active={active}
        truncated={run.truncated}
        fileName={outputFileName(run.hostname, run.jobName, run.id)}
        statusText={statusText}
      />

      {result ? (
        <Panel title="Result details" description="Structured result reported by the agent." className="mt-4">
          <pre className="ident bg-muted/50 max-h-72 overflow-auto rounded-md px-3 py-2 whitespace-pre-wrap">
            {result}
          </pre>
        </Panel>
      ) : null}

      <ConfirmDialog
        open={confirmCancel}
        onOpenChange={setConfirmCancel}
        title={`Cancel this run on ${run.hostname}?`}
        description={
          <p>
            {run.status === 'pending'
              ? 'It has not been sent yet and will be cancelled at once.'
              : 'The device is told to stop. Anything the run already changed on the device stays changed.'}
          </p>
        }
        confirmLabel="Cancel run"
        destructive
        pending={cancel.isPending}
        onConfirm={() => {
          cancel.mutate();
        }}
      />
    </>
  );
}
