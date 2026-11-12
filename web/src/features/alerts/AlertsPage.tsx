import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { BellOff, Check, CheckCheck } from 'lucide-react';
import { Link, useSearchParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { EmptyState, ErrorState, LoadingRows, PageHeader, Panel } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { RelativeTime } from '@/components/relative-time';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ALERT_STATES, alertKeys, alertsApi, type Alert, type AlertFilter, type AlertState } from '@/lib/api/alerts';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { cn } from '@/lib/utils';
import { ChannelsTab } from './ChannelsTab';
import { alertTypeLabel, SEVERITY, severityLook } from './rule-params';
import { RulesTab } from './RulesTab';

const PAGE_SIZE = 50;

const STATE_LABEL: Record<AlertState, string> = { open: 'Open', acknowledged: 'Acknowledged', resolved: 'Resolved' };

type Section = 'alerts' | 'rules' | 'channels';

export default function AlertsPage() {
  useDocumentTitle('Alerts');
  const access = useAccess();
  const [params, setParams] = useSearchParams();
  const sections: { id: Section; label: string }[] = [
    { id: 'alerts', label: 'Alerts' },
    { id: 'rules', label: 'Rules' },
    ...(access.has(P.notificationsManage) ? [{ id: 'channels' as const, label: 'Notification channels' }] : []),
  ];
  const section = sections.find((s) => s.id === params.get('tab'))?.id ?? 'alerts';

  return (
    <>
      <PageHeader
        title="Alerts"
        description="Problems found on devices, the rules that raise them and where notifications are sent."
      />
      <Tabs
        value={section}
        onValueChange={(next) => {
          setParams(next === 'alerts' ? {} : { tab: next }, { replace: true });
        }}
      >
        <TabsList variant="line" className="mb-4 w-full justify-start border-b">
          {sections.map((s) => (
            <TabsTrigger key={s.id} value={s.id} className="flex-none px-3">
              {s.label}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="alerts">
          <AlertList />
        </TabsContent>
        <TabsContent value="rules">
          <RulesTab />
        </TabsContent>
        {access.has(P.notificationsManage) ? (
          <TabsContent value="channels">
            <ChannelsTab />
          </TabsContent>
        ) : null}
      </Tabs>
    </>
  );
}

function StateCount({ state, organizationId }: { state: AlertState; organizationId?: string }) {
  const filter: AlertFilter = { state, organizationId, page: 1, pageSize: 1 };
  const count = useQuery({
    queryKey: alertKeys.list(filter),
    queryFn: ({ signal }) => alertsApi.list(filter, signal),
    refetchInterval: 60_000,
  });
  return count.data ? (
    <span className="bg-muted text-muted-foreground ml-1 rounded-sm px-1.5 text-xs tabular-nums">
      {count.data.total.toLocaleString('en')}
    </span>
  ) : null;
}

function AlertList() {
  const access = useAccess();
  const queryClient = useQueryClient();
  const { orgId, organization, organizations, available: orgsAvailable } = useOrgFilter();
  const [params, setParams] = useSearchParams();
  const state = ALERT_STATES.find((s) => s === params.get('state')) ?? 'open';
  const severity = params.get('severity') ?? '';
  const page = Math.max(1, Number.parseInt(params.get('page') ?? '1', 10) || 1);
  const canManage = access.has(P.alertsManage);
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

  const filter: AlertFilter = {
    state,
    organizationId: orgId ?? undefined,
    severity: severity || undefined,
    page,
    pageSize: PAGE_SIZE,
  };
  const query = useQuery({
    queryKey: alertKeys.list(filter),
    queryFn: ({ signal }) => alertsApi.list(filter, signal),
    placeholderData: keepPreviousData,
    refetchInterval: 60_000,
  });

  const act = useMutation({
    mutationFn: async ({ alert, action }: { alert: Alert; action: 'acknowledge' | 'resolve' }) => {
      await (action === 'acknowledge' ? alertsApi.acknowledge(alert.id) : alertsApi.resolve(alert.id));
      return action;
    },
    onSuccess: async (action) => {
      notifySuccess(action === 'acknowledge' ? 'Alert acknowledged' : 'Alert resolved');
      await queryClient.invalidateQueries({ queryKey: alertKeys.all });
    },
    onError: notifyError,
  });

  return (
    <Panel flush>
      <Tabs
        value={state}
        onValueChange={(next) => {
          update({ state: next === 'open' ? '' : next });
        }}
        className="gap-0"
      >
        <div className="flex flex-wrap items-end justify-between gap-x-4 gap-y-2 border-b px-4 py-3">
          <TabsList aria-label="Alert state">
            {ALERT_STATES.map((s) => (
              <TabsTrigger key={s} value={s}>
                {STATE_LABEL[s]}
                <StateCount state={s} organizationId={orgId ?? undefined} />
              </TabsTrigger>
            ))}
          </TabsList>
          <div className="grid gap-1">
            <Label htmlFor="alert-severity" className="text-xs">
              Severity
            </Label>
            <NativeSelect
              id="alert-severity"
              size="sm"
              value={severity}
              onChange={(e) => {
                update({ severity: e.target.value });
              }}
            >
              <NativeSelectOption value="">Any</NativeSelectOption>
              {Object.entries(SEVERITY).map(([id, { label }]) => (
                <NativeSelectOption key={id} value={id}>
                  {label}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
        </div>

        <TabsContent value={state}>
          {query.isPending ? (
            <LoadingRows label="alerts" rows={8} />
          ) : query.isError ? (
            <ErrorState error={query.error} what="alerts" onRetry={() => void query.refetch()} />
          ) : query.data.total === 0 ? (
            <EmptyState
              icon={BellOff}
              title={
                state === 'open'
                  ? 'No open alerts'
                  : state === 'acknowledged'
                    ? 'No acknowledged alerts'
                    : 'No resolved alerts'
              }
            >
              {organization ? `Showing ${organization.name} only. ` : ''}
              {state === 'open' ? 'New alerts appear here as soon as a rule finds a problem.' : ''}
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
                      <TableHead scope="col">Severity</TableHead>
                      <TableHead scope="col">Alert</TableHead>
                      <TableHead scope="col">Type</TableHead>
                      <TableHead scope="col">Device</TableHead>
                      <TableHead scope="col">Opened</TableHead>
                      {state !== 'open' ? (
                        <TableHead scope="col">{state === 'resolved' ? 'Resolved' : 'Acknowledged'}</TableHead>
                      ) : null}
                      {canManage && state !== 'resolved' ? (
                        <TableHead scope="col">
                          <span className="sr-only">Actions</span>
                        </TableHead>
                      ) : null}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {query.data.items.map((a) => {
                      const look = severityLook(a.severity);
                      return (
                        <TableRow key={a.id}>
                          <TableCell>
                            <StatusPill tone={look.tone}>{look.label}</StatusPill>
                          </TableCell>
                          <TableHead
                            scope="row"
                            className="text-foreground h-auto max-w-md py-2 text-sm font-normal whitespace-normal"
                          >
                            <div className="font-medium">{a.title}</div>
                            {a.detail ? (
                              <div className="text-muted-foreground text-xs break-words">{a.detail}</div>
                            ) : null}
                          </TableHead>
                          <TableCell>{alertTypeLabel(a.type)}</TableCell>
                          <TableCell>
                            <Link to={`/devices/${a.deviceId}`} className="ident font-medium hover:underline">
                              {a.hostname}
                            </Link>
                            {orgsAvailable && !orgId ? (
                              <div className="text-muted-foreground text-xs">{orgName.get(a.organizationId)}</div>
                            ) : null}
                          </TableCell>
                          <TableCell>
                            <RelativeTime value={a.openedAt} />
                          </TableCell>
                          {state !== 'open' ? (
                            <TableCell>
                              <RelativeTime value={state === 'resolved' ? a.resolvedAt : a.acknowledgedAt} />
                            </TableCell>
                          ) : null}
                          {canManage && state !== 'resolved' ? (
                            <TableCell className="py-1 text-right">
                              <div className="flex justify-end gap-1">
                                {a.state === 'open' ? (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    disabled={act.isPending}
                                    onClick={() => {
                                      act.mutate({ alert: a, action: 'acknowledge' });
                                    }}
                                  >
                                    <Check aria-hidden="true" />
                                    Acknowledge<span className="sr-only">: {a.title}</span>
                                  </Button>
                                ) : null}
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  disabled={act.isPending}
                                  onClick={() => {
                                    act.mutate({ alert: a, action: 'resolve' });
                                  }}
                                >
                                  <CheckCheck aria-hidden="true" />
                                  Resolve<span className="sr-only">: {a.title}</span>
                                </Button>
                              </div>
                            </TableCell>
                          ) : null}
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
                noun="alerts"
                onPageChange={(next) => {
                  const copy = new URLSearchParams(params);
                  copy.set('page', String(next));
                  setParams(copy, { replace: true });
                }}
              />
            </>
          )}
        </TabsContent>
      </Tabs>
      {state !== 'resolved' ? (
        <p className="text-muted-foreground border-t px-4 py-2 text-xs">
          Most alerts resolve themselves when the problem goes away. If you resolve one by hand while the problem is
          still there, it opens again at the next check.
        </p>
      ) : null}
    </Panel>
  );
}
