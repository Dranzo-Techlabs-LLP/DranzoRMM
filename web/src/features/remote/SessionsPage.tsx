import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { MonitorUp, X } from 'lucide-react';
import { Link, useSearchParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { EmptyState, ErrorState, LoadingRows, PageHeader, Panel } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { StatusPill, type Tone } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import {
  normalizeSessionState,
  OPEN_SESSION_STATES,
  remoteApi,
  remoteKeys,
  type RemoteSession,
  type SessionFilter,
  type SessionStateName,
} from '@/lib/api/remote';
import { formatBytes, formatLogTime } from '@/lib/format';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { cn } from '@/lib/utils';
import { CONSENT_MODE_LABEL, CONSENT_RESULT_LABEL, KIND_LABEL } from './consent';
import { describeReason } from './session-machine';

const PAGE_SIZE = 50;

const STATE: Record<SessionStateName, { label: string; tone: Tone; filter: string }> = {
  requested: { label: 'Requested', tone: 'info', filter: 'requested' },
  pending_consent: { label: 'Waiting for the user', tone: 'warn', filter: 'pendingconsent' },
  active: { label: 'Active', tone: 'ok', filter: 'active' },
  ended: { label: 'Ended', tone: 'idle', filter: 'ended' },
  denied: { label: 'Declined', tone: 'danger', filter: 'denied' },
  failed: { label: 'Failed', tone: 'danger', filter: 'failed' },
};

/** "4m 12s" for a finished session, "so far" for one that is still open. */
// eslint-disable-next-line react-refresh/only-export-components
export function sessionDuration(
  session: Pick<RemoteSession, 'startedAt' | 'endedAt'>,
  now: number = Date.now(),
): string {
  if (!session.startedAt) {
    return '';
  }
  const start = Date.parse(session.startedAt);
  const end = session.endedAt ? Date.parse(session.endedAt) : now;
  if (Number.isNaN(start) || Number.isNaN(end)) {
    return '';
  }
  const seconds = Math.max(0, Math.round((end - start) / 1000));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const text = h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;
  return session.endedAt ? text : `${text} so far`;
}

export default function SessionsPage() {
  useDocumentTitle('Remote sessions');
  const queryClient = useQueryClient();
  const { orgId, organizations, available: orgsAvailable } = useOrgFilter();
  const [params, setParams] = useSearchParams();
  const deviceId = params.get('deviceId') ?? '';
  const stateParam = normalizeSessionState(params.get('state'));
  const page = Math.max(1, Number.parseInt(params.get('page') ?? '1', 10) || 1);
  const orgName = new Map(organizations.map((o) => [o.id, o.name]));

  const update = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    next.delete('page');
    for (const [key, value] of Object.entries(patch)) {
      if (value) {
        next.set(key, value);
      } else {
        next.delete(key);
      }
    }
    setParams(next, { replace: true });
  };

  const filter: SessionFilter = {
    organizationId: orgId ?? undefined,
    deviceId: deviceId || undefined,
    state: stateParam ? STATE[stateParam].filter : undefined,
    page,
    pageSize: PAGE_SIZE,
  };
  const query = useQuery({
    queryKey: remoteKeys.list(filter),
    queryFn: ({ signal }) => remoteApi.list(filter, signal),
    placeholderData: keepPreviousData,
    // Open sessions change state without this page hearing about it.
    refetchInterval: 15_000,
  });

  const end = useMutation({
    mutationFn: (id: string) => remoteApi.end(id),
    onSuccess: async () => {
      notifySuccess('Session ended');
      await queryClient.invalidateQueries({ queryKey: remoteKeys.all });
    },
    onError: notifyError,
  });

  const filtered = Boolean(deviceId || stateParam);
  const deviceName = deviceId ? query.data?.items.find((s) => s.deviceId === deviceId)?.hostname : undefined;

  return (
    <>
      <PageHeader
        title="Remote sessions"
        description="Every terminal, file and desktop session: who connected, how the person at the computer answered, and why it ended. Start a session from a device's Remote tab."
      />
      <Panel flush>
        <form
          role="search"
          aria-label="Filter sessions"
          className="flex flex-wrap items-end gap-x-3 gap-y-2 border-b px-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
          }}
        >
          <div className="grid gap-1">
            <Label htmlFor="session-state" className="text-xs">
              State
            </Label>
            <NativeSelect
              id="session-state"
              size="sm"
              value={stateParam ?? ''}
              onChange={(e) => {
                update({ state: e.target.value });
              }}
            >
              <NativeSelectOption value="">Any</NativeSelectOption>
              {(Object.keys(STATE) as SessionStateName[]).map((s) => (
                <NativeSelectOption key={s} value={s}>
                  {STATE[s].label}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
          {deviceId ? (
            <p className="pb-1.5 text-sm">
              Device: <span className="ident font-medium">{deviceName ?? 'selected device'}</span>
            </p>
          ) : null}
          {filtered ? (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                setParams(new URLSearchParams(), { replace: true });
              }}
            >
              <X aria-hidden="true" />
              Clear filters
            </Button>
          ) : null}
        </form>

        {query.isPending ? (
          <LoadingRows label="sessions" rows={8} />
        ) : query.isError ? (
          <ErrorState error={query.error} what="remote sessions" onRetry={() => void query.refetch()} />
        ) : query.data.total === 0 ? (
          <EmptyState icon={MonitorUp} title={filtered || orgId ? 'No sessions match' : 'No remote sessions yet'}>
            {filtered || orgId
              ? 'Try other filters, or another organization in the top bar.'
              : 'Sessions appear here as soon as someone opens a terminal, the file browser or a remote desktop.'}
          </EmptyState>
        ) : (
          <>
            <div
              className={cn('overflow-x-auto', query.isPlaceholderData && 'opacity-60')}
              aria-busy={query.isFetching}
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Requested</TableHead>
                    <TableHead scope="col">Technician</TableHead>
                    <TableHead scope="col">Device</TableHead>
                    <TableHead scope="col">Kind</TableHead>
                    <TableHead scope="col">State</TableHead>
                    <TableHead scope="col">Consent</TableHead>
                    <TableHead scope="col">Duration</TableHead>
                    <TableHead scope="col">How it ended</TableHead>
                    <TableHead scope="col" className="text-right">
                      Data in / out
                    </TableHead>
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {query.data.items.map((s) => {
                    const state = normalizeSessionState(s.state);
                    const look = state ? STATE[state] : { label: s.state, tone: 'idle' as Tone };
                    const open = state !== null && OPEN_SESSION_STATES.includes(state);
                    return (
                      <TableRow key={s.id}>
                        <TableCell className="whitespace-nowrap">
                          <time dateTime={s.requestedAt}>{formatLogTime(s.requestedAt)}</time>
                        </TableCell>
                        <TableCell>{s.userName}</TableCell>
                        <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-normal">
                          <Link to={`/devices/${s.deviceId}?tab=remote`} className="ident font-medium hover:underline">
                            {s.hostname}
                          </Link>
                          {orgsAvailable && !orgId ? (
                            <div className="text-muted-foreground text-xs">{orgName.get(s.organizationId)}</div>
                          ) : null}
                        </TableHead>
                        <TableCell>{KIND_LABEL[s.kind] ?? s.kind}</TableCell>
                        <TableCell>
                          <StatusPill tone={look.tone}>{look.label}</StatusPill>
                        </TableCell>
                        <TableCell className="whitespace-normal">
                          <div>{CONSENT_MODE_LABEL[s.consent] ?? s.consent}</div>
                          <div className="text-muted-foreground text-xs">
                            {s.consentResult
                              ? (CONSENT_RESULT_LABEL[s.consentResult] ?? s.consentResult)
                              : 'No answer yet'}
                          </div>
                        </TableCell>
                        <TableCell className="whitespace-nowrap">
                          {sessionDuration(s) || <span className="text-muted-foreground">Did not start</span>}
                        </TableCell>
                        <TableCell className="max-w-64 whitespace-normal">
                          {s.endReason ? (
                            describeReason(s.endReason)
                          ) : (
                            <span className="text-muted-foreground">Still open</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right whitespace-nowrap">
                          {formatBytes(s.bytesIn)} / {formatBytes(s.bytesOut)}
                        </TableCell>
                        <TableCell className="py-1 text-right">
                          {open ? (
                            <Button
                              variant="outline"
                              size="sm"
                              className="text-destructive hover:text-destructive"
                              disabled={end.isPending}
                              onClick={() => {
                                end.mutate(s.id);
                              }}
                            >
                              End<span className="sr-only"> session on {s.hostname}</span>
                            </Button>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
            <Pagination
              page={query.data.page}
              pageSize={query.data.pageSize || PAGE_SIZE}
              total={query.data.total}
              noun="sessions"
              onPageChange={(next) => {
                const copy = new URLSearchParams(params);
                copy.set('page', String(next));
                setParams(copy, { replace: true });
              }}
            />
          </>
        )}
      </Panel>
    </>
  );
}
