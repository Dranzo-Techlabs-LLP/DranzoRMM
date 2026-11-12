import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CalendarClock, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { EmptyState, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { describeStoredTarget } from '@/components/target-picker/target';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useGroups, useSites } from '@/features/tenants/queries';
import { jobKeys, jobsApi, type Schedule } from '@/lib/api/jobs';
import { useAccess } from '@/lib/auth/session';
import { formatDateTime } from '@/lib/format';
import { notifyError, notifySuccess } from '@/lib/notify';
import { describeCron } from '../scripts/cron';
import { AP } from './permissions';
import { kindLabel } from './run-model';

/** Scheduled jobs: when they run next, pause / resume, delete. */
export function SchedulesPanel() {
  const access = useAccess();
  const queryClient = useQueryClient();
  const { organizations } = useOrgFilter();
  const sites = useSites();
  const groups = useGroups();
  const canEdit = access.has(AP.scriptsRun);
  const [deleting, setDeleting] = useState<Schedule | null>(null);
  const query = useQuery({ queryKey: jobKeys.schedules, queryFn: jobsApi.schedules, refetchInterval: 60_000 });
  const names = { organizations, sites: sites.data, groups: groups.data };

  const invalidate = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: jobKeys.schedules }),
      queryClient.invalidateQueries({ queryKey: jobKeys.lists }),
    ]);

  const toggle = useMutation({
    mutationFn: ({ schedule, enabled }: { schedule: Schedule; enabled: boolean }) =>
      jobsApi.setScheduleEnabled(schedule.id, enabled),
    onSuccess: async (_, { schedule, enabled }) => {
      notifySuccess(enabled ? `“${schedule.name}” resumed` : `“${schedule.name}” paused`);
      await invalidate();
    },
    onError: notifyError,
  });

  const remove = useMutation({
    mutationFn: (schedule: Schedule) => jobsApi.removeSchedule(schedule.id),
    onSuccess: async (_, schedule) => {
      notifySuccess(`Schedule “${schedule.name}” deleted`);
      setDeleting(null);
      await invalidate();
    },
    onError: notifyError,
  });

  return (
    <>
      <Panel
        flush
        title="Schedules"
        description="Jobs that repeat. Times follow the time zone shown, normally the organization’s."
      >
        <QueryView
          query={query}
          what="schedules"
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyState icon={CalendarClock} title="Nothing is scheduled">
              To repeat a script, open it under Scripts, choose Run and turn on “Run on a schedule”.
            </EmptyState>
          }
        >
          {(schedules) => (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Job</TableHead>
                  <TableHead scope="col" className="hidden lg:table-cell">
                    Runs on
                  </TableHead>
                  <TableHead scope="col">When</TableHead>
                  <TableHead scope="col">Next run</TableHead>
                  <TableHead scope="col" className="hidden md:table-cell">
                    Created by
                  </TableHead>
                  <TableHead scope="col">Enabled</TableHead>
                  {canEdit ? (
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  ) : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {schedules.map((s) => {
                  const cron = describeCron(s.cron);
                  const busy = toggle.isPending && toggle.variables.schedule.id === s.id;
                  return (
                    <TableRow key={s.id}>
                      <TableHead
                        scope="row"
                        className="text-foreground h-auto max-w-72 py-2 font-medium whitespace-normal"
                      >
                        <Link to={`/jobs/${s.id}`} className="text-link hover:underline">
                          {s.name}
                        </Link>
                        <span className="text-muted-foreground block text-xs font-normal">{kindLabel(s.kind)}</span>
                      </TableHead>
                      <TableCell className="hidden max-w-64 whitespace-normal lg:table-cell">
                        {describeStoredTarget(s.targetJson, names)}
                      </TableCell>
                      <TableCell className="max-w-72 whitespace-normal">
                        {cron.ok ? cron.text : 'Custom schedule'}
                        <span className="text-muted-foreground block text-xs">
                          <span className="ident">{s.cron}</span> · {s.timeZone ?? 'UTC'}
                        </span>
                      </TableCell>
                      <TableCell>
                        {s.enabled && s.nextRunAt ? (
                          <time dateTime={s.nextRunAt} title={formatDateTime(s.nextRunAt, true)}>
                            {formatDateTime(s.nextRunAt)}
                            <span className="text-muted-foreground block text-xs">
                              <RelativeTime value={s.nextRunAt} /> (your time)
                            </span>
                          </time>
                        ) : (
                          <span className="text-muted-foreground">{s.enabled ? 'Not planned' : 'Paused'}</span>
                        )}
                      </TableCell>
                      <TableCell className="hidden md:table-cell">{s.requestedByName}</TableCell>
                      <TableCell>
                        <Switch
                          checked={s.enabled}
                          disabled={!canEdit || busy}
                          aria-label={`${s.name}: ${s.enabled ? 'enabled, switch off to pause' : 'paused, switch on to resume'}`}
                          onCheckedChange={(enabled) => {
                            toggle.mutate({ schedule: s, enabled });
                          }}
                        />
                      </TableCell>
                      {canEdit ? (
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setDeleting(s);
                            }}
                          >
                            <Trash2 aria-hidden="true" />
                            Delete<span className="sr-only"> schedule {s.name}</span>
                          </Button>
                        </TableCell>
                      ) : null}
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </QueryView>
      </Panel>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
          }
        }}
        title={`Delete the schedule “${deleting?.name ?? ''}”?`}
        description={
          <p>
            It will not run again. Runs that already happened stay in the job history and the audit log. To stop it only
            for a while, pause it instead.
          </p>
        }
        confirmLabel="Delete schedule"
        destructive
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) {
            remove.mutate(deleting);
          }
        }}
      />
    </>
  );
}
