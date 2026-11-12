import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { Play, SquareTerminal } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { EmptyState, ErrorState, LoadingRows, Panel } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { AP } from '@/features/jobs/permissions';
import { formatRunDuration, JOB_KINDS, kindLabel, runDurationSeconds } from '@/features/jobs/run-model';
import { RunStatusChip } from '@/features/jobs/RunStatusChip';
import { RunScriptDialog } from '@/features/scripts/RunScriptDialog';
import { isActiveRun, jobKeys, runsApi, type RunListFilter } from '@/lib/api/jobs';
import { useAccess } from '@/lib/auth/session';
import { formatDateTime, formatLogTime } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { DeviceTabProps } from './registry';

const PAGE_SIZE = 25;

/** Run a script on this device, and everything that has been run on it (`GET /runs?deviceId=`). */
export function ScriptsTab({ device }: DeviceTabProps) {
  const access = useAccess();
  const [running, setRunning] = useState(false);
  const [kind, setKind] = useState('script');
  const [page, setPage] = useState(1);
  const canSeeRuns = access.has(AP.jobsRead);
  const canRun = access.has(AP.scriptsRun) && device.status !== 'revoked';
  const filter: RunListFilter = { deviceId: device.id, kind: kind || undefined, page, pageSize: PAGE_SIZE };
  const query = useQuery({
    queryKey: jobKeys.runList(filter),
    queryFn: () => runsApi.list(filter),
    enabled: canSeeRuns,
    placeholderData: keepPreviousData,
    refetchInterval: (q) => (q.state.data?.items.some((r) => isActiveRun(r.status)) ? 3_000 : 30_000),
  });

  return (
    <div className="grid gap-4">
      <Panel
        title="Run a script"
        description={
          device.isOnline
            ? 'The device is connected, so a script starts right away and its output streams back live.'
            : 'The device is offline. A script you start now waits and runs when the device next connects.'
        }
        actions={
          canRun ? (
            <Button
              size="sm"
              onClick={() => {
                setRunning(true);
              }}
            >
              <Play aria-hidden="true" />
              Run a script
            </Button>
          ) : undefined
        }
      >
        <p className="text-muted-foreground">
          {device.status === 'revoked'
            ? 'This device is revoked and no longer accepts jobs.'
            : canRun
              ? 'Pick a script from the library that supports this device’s operating system. Everything that runs is recorded in the audit log.'
              : 'Your role can view script history but not run scripts.'}
        </p>
      </Panel>

      {canSeeRuns ? (
        <Panel
          flush
          title="History on this device"
          actions={
            <>
              <Label htmlFor="device-run-kind" className="text-xs">
                Show
              </Label>
              <NativeSelect
                id="device-run-kind"
                size="sm"
                value={kind}
                onChange={(e) => {
                  setKind(e.target.value);
                  setPage(1);
                }}
              >
                <NativeSelectOption value="script">Scripts</NativeSelectOption>
                <NativeSelectOption value="">Everything</NativeSelectOption>
                {JOB_KINDS.filter((k) => k.id !== 'script').map((k) => (
                  <NativeSelectOption key={k.id} value={k.id}>
                    {k.label}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            </>
          }
        >
          {query.isPending ? (
            <LoadingRows label="run history" rows={5} />
          ) : query.isError ? (
            <ErrorState error={query.error} what="the run history" onRetry={() => void query.refetch()} />
          ) : query.data.items.length === 0 ? (
            <EmptyState
              icon={SquareTerminal}
              title={kind === 'script' ? 'No scripts have run on this device' : 'Nothing to show'}
            >
              {kind === 'script' ? 'Runs appear here with their status, exit code and output.' : null}
            </EmptyState>
          ) : (
            <>
              <div className={cn(query.isPlaceholderData && 'opacity-60')} aria-busy={query.isFetching}>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead scope="col">Job</TableHead>
                      <TableHead scope="col">Status</TableHead>
                      <TableHead scope="col" className="text-right">
                        Exit code
                      </TableHead>
                      <TableHead scope="col" className="hidden text-right md:table-cell">
                        Duration
                      </TableHead>
                      <TableHead scope="col">Requested</TableHead>
                      <TableHead scope="col" className="hidden lg:table-cell">
                        By
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {query.data.items.map((r) => (
                      <TableRow key={r.id}>
                        <TableHead
                          scope="row"
                          className="text-foreground h-auto max-w-80 py-2 font-medium whitespace-normal"
                        >
                          <Link to={`/jobs/${r.jobId}/runs/${r.id}`} className="text-link hover:underline">
                            {r.jobName}
                          </Link>
                          {kind !== 'script' ? (
                            <span className="text-muted-foreground block text-xs font-normal">{kindLabel(r.kind)}</span>
                          ) : null}
                        </TableHead>
                        <TableCell>
                          <RunStatusChip status={r.status} />
                        </TableCell>
                        <TableCell className="ident text-right">
                          {r.exitCode ?? <span className="text-muted-foreground">–</span>}
                        </TableCell>
                        <TableCell className="hidden text-right md:table-cell">
                          {formatRunDuration(runDurationSeconds(r)) || <span className="text-muted-foreground">–</span>}
                        </TableCell>
                        <TableCell>
                          <time dateTime={r.createdAt} title={formatDateTime(r.createdAt, true)}>
                            {formatLogTime(r.createdAt)}
                          </time>
                        </TableCell>
                        <TableCell className="hidden lg:table-cell">{r.requestedBy}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <Pagination
                page={query.data.page}
                pageSize={query.data.pageSize || PAGE_SIZE}
                total={query.data.total}
                noun="runs"
                onPageChange={setPage}
              />
            </>
          )}
        </Panel>
      ) : null}

      {running ? (
        <RunScriptDialog
          device={{ id: device.id, hostname: device.hostname, os: device.os, organizationId: device.organizationId }}
          onClose={() => {
            setRunning(false);
          }}
        />
      ) : null}
    </div>
  );
}
