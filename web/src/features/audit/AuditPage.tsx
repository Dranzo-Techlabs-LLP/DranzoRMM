import { keepPreviousData, useMutation, useQuery } from '@tanstack/react-query';
import {
  ChevronDown,
  ChevronRight,
  CircleCheck,
  Download,
  ScrollText,
  ShieldCheck,
  TriangleAlert,
  X,
} from 'lucide-react';
import { Fragment, useState } from 'react';
import { useOrgFilter } from '@/app/org-filter';
import { EmptyState, ErrorState, LoadingRows, PageHeader, Panel } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { InlineAlert, StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { auditApi, errorMessage, qk, type AuditEvent, type AuditFilter } from '@/lib/api';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { formatDateTime, formatLogTime, localInputToIso } from '@/lib/format';
import { useDebounced, useDocumentTitle } from '@/lib/hooks';
import { cn } from '@/lib/utils';
import { formatAuditDetail, resultTone } from './detail';

const PAGE_SIZE = 50;

export default function AuditPage() {
  useDocumentTitle('Audit log');
  const access = useAccess();
  const { orgId, organization, organizations } = useOrgFilter();
  const [action, setAction] = useState('');
  const [actor, setActor] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());

  const debouncedAction = useDebounced(action.trim());
  const debouncedActor = useDebounced(actor.trim());

  const baseFilter: AuditFilter = {
    organizationId: orgId ?? undefined,
    action: debouncedAction || undefined,
    actor: debouncedActor || undefined,
    from: localInputToIso(from),
    to: localInputToIso(to),
  };
  const filter: AuditFilter = { ...baseFilter, page, pageSize: PAGE_SIZE };

  const query = useQuery({
    queryKey: qk.audit(filter),
    queryFn: () => auditApi.list(filter),
    placeholderData: keepPreviousData,
  });

  // Verifying walks the whole chain on the server; it runs only when asked.
  const verify = useMutation({ mutationFn: auditApi.verify });
  const canVerify = access.hasPartnerWide(P.auditRead);

  const filtered = Boolean(action || actor || from || to);
  const resetPage = () => {
    setPage(1);
    setExpanded(new Set());
  };
  const clear = () => {
    setAction('');
    setActor('');
    setFrom('');
    setTo('');
    resetPage();
  };
  const orgName = new Map(organizations.map((o) => [o.id, o.name]));
  const rangeInvalid = Boolean(from && to && from > to);

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every sign-in and administrative action. Entries cannot be changed or deleted, and each one is chained to the one before it so tampering can be detected."
        actions={
          <>
            {canVerify ? (
              <Button
                variant="outline"
                size="sm"
                disabled={verify.isPending}
                onClick={() => {
                  verify.mutate();
                }}
              >
                <ShieldCheck aria-hidden="true" />
                {verify.isPending ? 'Verifying…' : 'Verify integrity'}
              </Button>
            ) : null}
            <Button asChild variant="outline" size="sm">
              {/* Plain same-origin download: the browser sends the session cookie; no token ever appears in the URL. */}
              <a href={auditApi.exportUrl(baseFilter)} download="audit-log.csv">
                <Download aria-hidden="true" />
                Export CSV
              </a>
            </Button>
          </>
        }
      />

      <div aria-live="polite" className="empty:hidden">
        {verify.isSuccess ? (
          verify.data.ok ? (
            <div className="bg-ok-surface text-ok mb-4 flex items-start gap-2 rounded-md px-3 py-2">
              <CircleCheck aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              <p className="text-foreground">
                <span className="text-ok font-semibold">Log is intact.</span> All{' '}
                {verify.data.count.toLocaleString('en')} entries were checked and the chain is unbroken.
              </p>
            </div>
          ) : (
            <div className="bg-danger-surface text-danger mb-4 flex items-start gap-2 rounded-md px-3 py-2">
              <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
              <p className="text-foreground">
                <span className="text-danger font-semibold">Integrity check failed.</span>{' '}
                {verify.data.firstBadSequence !== null
                  ? `The first entry that does not verify is number ${verify.data.firstBadSequence}. `
                  : ''}
                {verify.data.problem ?? ''} Treat entries from that point on as untrustworthy and investigate.
              </p>
            </div>
          )
        ) : verify.isError ? (
          <InlineAlert live={false} className="mb-4" title="Could not verify the log">
            {errorMessage(verify.error)}
          </InlineAlert>
        ) : null}
      </div>

      <Panel flush>
        <form
          role="search"
          aria-label="Filter audit log"
          className="flex flex-wrap items-end gap-x-3 gap-y-2 border-b px-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
          }}
        >
          <div className="grid w-44 gap-1">
            <Label htmlFor="audit-action" className="text-xs">
              Action starts with
            </Label>
            <Input
              id="audit-action"
              className="ident h-8"
              placeholder="device."
              value={action}
              maxLength={64}
              spellCheck={false}
              autoCapitalize="none"
              onChange={(e) => {
                setAction(e.target.value);
                resetPage();
              }}
            />
          </div>
          <div className="grid w-48 gap-1">
            <Label htmlFor="audit-actor" className="text-xs">
              Actor contains
            </Label>
            <Input
              id="audit-actor"
              className="h-8"
              placeholder="Email or key name"
              value={actor}
              maxLength={254}
              spellCheck={false}
              autoCapitalize="none"
              onChange={(e) => {
                setActor(e.target.value);
                resetPage();
              }}
            />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="audit-from" className="text-xs">
              From
            </Label>
            <Input
              id="audit-from"
              type="datetime-local"
              className="h-8"
              value={from}
              max={to || undefined}
              onChange={(e) => {
                setFrom(e.target.value);
                resetPage();
              }}
            />
          </div>
          <div className="grid gap-1">
            <Label htmlFor="audit-to" className="text-xs">
              To
            </Label>
            <Input
              id="audit-to"
              type="datetime-local"
              className="h-8"
              value={to}
              min={from || undefined}
              aria-invalid={rangeInvalid || undefined}
              onChange={(e) => {
                setTo(e.target.value);
                resetPage();
              }}
            />
          </div>
          {filtered ? (
            <Button type="button" variant="ghost" size="sm" onClick={clear}>
              <X aria-hidden="true" />
              Clear filters
            </Button>
          ) : null}
          <p className="text-muted-foreground ml-auto self-center text-xs">
            {organization ? `Showing ${organization.name} only.` : 'Showing all organizations.'} Times are in your local
            time zone.
          </p>
        </form>
        {rangeInvalid ? (
          <p role="alert" className="text-danger border-b px-4 py-2 text-xs font-medium">
            “From” is later than “To”, so nothing can match.
          </p>
        ) : null}

        {query.isPending ? (
          <LoadingRows label="audit log" rows={10} />
        ) : query.isError ? (
          <ErrorState error={query.error} what="the audit log" onRetry={() => void query.refetch()} />
        ) : query.data.total === 0 ? (
          <EmptyState
            icon={ScrollText}
            title={filtered || orgId ? 'No entries match these filters' : 'No audit entries yet'}
            action={
              filtered ? (
                <Button variant="outline" size="sm" onClick={clear}>
                  Clear filters
                </Button>
              ) : undefined
            }
          >
            {orgId && !filtered
              ? 'Sign-ins and partner-level actions are not tied to an organization. Switch the top bar to all organizations to see them.'
              : null}
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
                    <TableHead scope="col" className="w-8">
                      <span className="sr-only">Details</span>
                    </TableHead>
                    <TableHead scope="col" className="text-right">
                      No.
                    </TableHead>
                    <TableHead scope="col">Time</TableHead>
                    <TableHead scope="col">Actor</TableHead>
                    <TableHead scope="col">Action</TableHead>
                    <TableHead scope="col" className="hidden lg:table-cell">
                      Target
                    </TableHead>
                    <TableHead scope="col" className="hidden xl:table-cell">
                      Organization
                    </TableHead>
                    <TableHead scope="col">Result</TableHead>
                    <TableHead scope="col" className="hidden xl:table-cell">
                      IP address
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {query.data.items.map((e) => (
                    <AuditRow
                      key={e.sequence}
                      event={e}
                      organizationName={e.organizationId ? (orgName.get(e.organizationId) ?? null) : null}
                      open={expanded.has(e.sequence)}
                      onToggle={() => {
                        setExpanded((prev) => {
                          const next = new Set(prev);
                          if (next.has(e.sequence)) {
                            next.delete(e.sequence);
                          } else {
                            next.add(e.sequence);
                          }
                          return next;
                        });
                      }}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>
            <Pagination
              page={query.data.page}
              pageSize={query.data.pageSize || PAGE_SIZE}
              total={query.data.total}
              noun="entries"
              onPageChange={(p) => {
                setPage(p);
                setExpanded(new Set());
              }}
            />
          </>
        )}
      </Panel>
    </>
  );
}

function AuditRow({
  event,
  organizationName,
  open,
  onToggle,
}: {
  event: AuditEvent;
  organizationName: string | null;
  open: boolean;
  onToggle: () => void;
}) {
  const detailId = `audit-detail-${event.sequence}`;
  const detail = formatAuditDetail(event.detail);
  const tone = resultTone(event.result);
  const organizationLabel =
    organizationName ??
    (event.organizationId ? <span className="text-muted-foreground">Deleted or hidden</span> : null);
  return (
    <Fragment>
      <TableRow data-state={open ? 'selected' : undefined}>
        <TableCell className="py-1 pr-0">
          <Button
            variant="ghost"
            size="icon-xs"
            aria-expanded={open}
            aria-controls={detailId}
            aria-label={`${open ? 'Hide' : 'Show'} details of entry ${event.sequence}`}
            onClick={onToggle}
          >
            {open ? <ChevronDown aria-hidden="true" /> : <ChevronRight aria-hidden="true" />}
          </Button>
        </TableCell>
        <TableCell className="text-muted-foreground text-right">{event.sequence}</TableCell>
        <TableCell>
          <time dateTime={event.occurredAt} title={formatDateTime(event.occurredAt, true)}>
            {formatLogTime(event.occurredAt)}
          </time>
        </TableCell>
        <TableCell>{event.actorName || <span className="text-muted-foreground">{event.actorType}</span>}</TableCell>
        <TableHead scope="row" className="ident text-foreground h-auto py-2 font-medium">
          {event.action}
        </TableHead>
        <TableCell className="hidden lg:table-cell">
          {event.targetType ? (
            <span>
              {event.targetType}
              {event.targetId ? (
                <span className="ident text-muted-foreground ml-1.5 text-xs" title={event.targetId}>
                  {event.targetId.slice(0, 8)}
                </span>
              ) : null}
            </span>
          ) : null}
        </TableCell>
        <TableCell className="hidden xl:table-cell">{organizationLabel}</TableCell>
        <TableCell>
          <StatusPill tone={tone} icon={tone === 'ok' ? CircleCheck : tone === 'danger' ? TriangleAlert : undefined}>
            {event.result}
          </StatusPill>
        </TableCell>
        <TableCell className="ident hidden xl:table-cell">{event.ip}</TableCell>
      </TableRow>
      {open ? (
        <TableRow id={detailId} className="bg-muted/40 hover:bg-muted/40">
          <TableCell />
          <TableCell colSpan={8} className="whitespace-normal">
            <dl className="grid grid-cols-[9rem_1fr] gap-x-4 gap-y-1.5 py-1">
              <dt className="text-muted-foreground">Detail</dt>
              <dd>
                {detail ? (
                  <pre className="ident bg-card max-h-72 overflow-auto rounded-md border px-3 py-2 whitespace-pre-wrap">
                    {detail}
                  </pre>
                ) : (
                  <span className="text-muted-foreground">No extra detail recorded.</span>
                )}
              </dd>
              <dt className="text-muted-foreground">Actor</dt>
              <dd>
                {event.actorType}
                {event.actorId ? <span className="ident text-muted-foreground ml-2">{event.actorId}</span> : null}
              </dd>
              {event.organizationId ? (
                <>
                  <dt className="text-muted-foreground">Organization</dt>
                  <dd>{organizationLabel}</dd>
                </>
              ) : null}
              {event.ip ? (
                <>
                  <dt className="text-muted-foreground">IP address</dt>
                  <dd className="ident">{event.ip}</dd>
                </>
              ) : null}
              {event.targetType ? (
                <>
                  <dt className="text-muted-foreground">Target</dt>
                  <dd>
                    {event.targetType}
                    {event.targetId ? <span className="ident ml-2 break-all">{event.targetId}</span> : null}
                  </dd>
                </>
              ) : null}
              {event.deviceId ? (
                <>
                  <dt className="text-muted-foreground">Device ID</dt>
                  <dd className="ident break-all">{event.deviceId}</dd>
                </>
              ) : null}
              {event.contentSha256 ? (
                <>
                  <dt className="text-muted-foreground">Content SHA-256</dt>
                  <dd className="ident break-all">{event.contentSha256}</dd>
                </>
              ) : null}
              <dt className="text-muted-foreground">Entry hash</dt>
              <dd className="ident break-all">{event.hash}</dd>
            </dl>
          </TableCell>
        </TableRow>
      ) : null}
    </Fragment>
  );
}
