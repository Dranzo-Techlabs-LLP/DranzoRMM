import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { CalendarClock, ListChecks } from 'lucide-react';
import { Link, useSearchParams } from 'react-router';
import { EmptyState, ErrorState, LoadingRows, PageHeader, Panel } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { RelativeTime } from '@/components/relative-time';
import { StatusPill } from '@/components/status';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { jobKeys, jobsApi, type JobListFilter } from '@/lib/api/jobs';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { cn } from '@/lib/utils';
import { describeCron } from '../scripts/cron';
import { RunCountsSummary } from './RunStatusChip';
import { JOB_KINDS, jobOtherCount, kindLabel } from './run-model';
import { SavedFiltersPanel } from './SavedFiltersPanel';
import { SchedulesPanel } from './SchedulesPanel';

const PAGE_SIZE = 50;
const VIEWS = ['jobs', 'schedules', 'filters'] as const;
type View = (typeof VIEWS)[number];

export default function JobsPage() {
  useDocumentTitle('Jobs');
  const access = useAccess();
  const [params, setParams] = useSearchParams();
  const requested = params.get('view');
  const views = VIEWS.filter((v) => v !== 'filters' || access.has(P.devicesRead));
  const view: View = views.find((v) => v === requested) ?? 'jobs';

  return (
    <>
      <PageHeader
        title="Jobs"
        description="Everything sent to devices: script runs, software and update installs, scans and restarts. Each job has one run per device."
      />
      <Tabs
        value={view}
        onValueChange={(next) => {
          setParams(next === 'jobs' ? {} : { view: next }, { replace: true });
        }}
      >
        <TabsList variant="line" className="mb-4 w-full justify-start border-b">
          <TabsTrigger value="jobs" className="flex-none px-3">
            Jobs
          </TabsTrigger>
          <TabsTrigger value="schedules" className="flex-none px-3">
            Schedules
          </TabsTrigger>
          {views.includes('filters') ? (
            <TabsTrigger value="filters" className="flex-none px-3">
              Saved filters
            </TabsTrigger>
          ) : null}
        </TabsList>
        <TabsContent value="jobs">
          <JobList />
        </TabsContent>
        <TabsContent value="schedules">
          <SchedulesPanel />
        </TabsContent>
        {views.includes('filters') ? (
          <TabsContent value="filters">
            <SavedFiltersPanel />
          </TabsContent>
        ) : null}
      </Tabs>
    </>
  );
}

function JobList() {
  const [params, setParams] = useSearchParams();
  const kind = params.get('kind') ?? '';
  const page = Math.max(1, Number.parseInt(params.get('page') ?? '1', 10) || 1);
  const filter: JobListFilter = { kind: kind || undefined, page, pageSize: PAGE_SIZE };
  const query = useQuery({
    queryKey: jobKeys.list(filter),
    queryFn: () => jobsApi.list(filter),
    placeholderData: keepPreviousData,
    // Counts change while runs are in flight; refresh faster then.
    refetchInterval: (q) => (q.state.data?.items.some((j) => j.active > 0) ? 5_000 : 30_000),
  });
  const update = (patch: { kind?: string; page?: number }) => {
    const next = new URLSearchParams();
    const k = patch.kind ?? kind;
    const p = patch.page ?? 1;
    if (k) {
      next.set('kind', k);
    }
    if (p > 1) {
      next.set('page', String(p));
    }
    setParams(next, { replace: true });
  };

  return (
    <Panel flush>
      <form
        role="search"
        aria-label="Filter jobs"
        className="flex flex-wrap items-end gap-3 border-b px-4 py-3"
        onSubmit={(e) => {
          e.preventDefault();
        }}
      >
        <div className="grid gap-1">
          <Label htmlFor="job-kind" className="text-xs">
            Kind
          </Label>
          <NativeSelect
            id="job-kind"
            size="sm"
            value={kind}
            onChange={(e) => {
              update({ kind: e.target.value, page: 1 });
            }}
          >
            <NativeSelectOption value="">All kinds</NativeSelectOption>
            {JOB_KINDS.map((k) => (
              <NativeSelectOption key={k.id} value={k.id}>
                {k.label}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        </div>
        <p className="text-muted-foreground ml-auto self-center text-xs">
          Newest activity first. You see the jobs that include devices you can reach.
        </p>
      </form>
      {query.isPending ? (
        <LoadingRows label="jobs" rows={8} />
      ) : query.isError ? (
        <ErrorState error={query.error} what="jobs" onRetry={() => void query.refetch()} />
      ) : query.data.items.length === 0 ? (
        <EmptyState icon={ListChecks} title={kind ? `No ${kindLabel(kind).toLowerCase()} jobs` : 'No jobs yet'}>
          {kind
            ? 'Nothing of this kind has been sent to devices you can reach.'
            : 'Run a script, deploy software or scan for updates and it will appear here with a run per device.'}
        </EmptyState>
      ) : (
        <>
          <div className={cn(query.isPlaceholderData && 'opacity-60')} aria-busy={query.isFetching}>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Job</TableHead>
                  <TableHead scope="col">Kind</TableHead>
                  <TableHead scope="col" className="hidden md:table-cell">
                    Requested by
                  </TableHead>
                  <TableHead scope="col">Runs</TableHead>
                  <TableHead scope="col" className="hidden lg:table-cell">
                    Schedule
                  </TableHead>
                  <TableHead scope="col">Last activity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {query.data.items.map((job) => {
                  const cron = job.cron ? describeCron(job.cron) : null;
                  return (
                    <TableRow key={job.id}>
                      <TableHead
                        scope="row"
                        className="text-foreground h-auto max-w-80 py-2 font-medium whitespace-normal"
                      >
                        <Link to={`/jobs/${job.id}`} className="text-link hover:underline">
                          {job.name}
                        </Link>
                      </TableHead>
                      <TableCell>{kindLabel(job.kind)}</TableCell>
                      <TableCell className="hidden md:table-cell">
                        {job.isSystem ? (
                          <span className="text-muted-foreground">System</span>
                        ) : (
                          job.requestedByName || <span className="text-muted-foreground">Unknown</span>
                        )}
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        <RunCountsSummary
                          succeeded={job.succeeded}
                          failed={job.failed}
                          active={job.active}
                          other={jobOtherCount(job)}
                        />
                      </TableCell>
                      <TableCell className="hidden lg:table-cell">
                        {job.cron ? (
                          <span title={`${job.cron}${job.timeZone ? ` (${job.timeZone})` : ''}`}>
                            <StatusPill tone={job.enabled ? 'info' : 'idle'} icon={CalendarClock}>
                              {job.enabled ? (cron?.ok && cron.exact ? cron.text : 'Scheduled') : 'Schedule paused'}
                            </StatusPill>
                          </span>
                        ) : (
                          <span className="text-muted-foreground">One-off</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <RelativeTime value={job.lastRunAt} />
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
            noun="jobs"
            onPageChange={(p) => {
              update({ page: p });
            }}
          />
        </>
      )}
    </Panel>
  );
}
