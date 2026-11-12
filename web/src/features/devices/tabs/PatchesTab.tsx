import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Ban, CircleCheck, Download, Power, Radar, Wrench } from 'lucide-react';
import { useId, useState } from 'react';
import { useNavigate } from 'react-router';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { EmptyState, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { PendingRebootBadge, StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { AP } from '@/features/jobs/permissions';
import { InstallUpdatesDialog } from '@/features/patches/InstallUpdatesDialog';
import { KnownLimits } from '@/features/patches/KnownLimits';
import { patchSourceLabel, patchStatus, severity } from '@/features/patches/patch-model';
import { qk } from '@/lib/api';
import { jobKeys } from '@/lib/api/jobs';
import { patchesApi, patchKeys, type DevicePatchItem, type PatchDecision } from '@/lib/api/patches';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { notifyError, notifySuccess } from '@/lib/notify';
import type { DeviceTabProps } from './registry';

/** Updates of one device (`GET /devices/{id}/patches`): decide per update, scan, install, restart. */
export function PatchesTab({ device }: DeviceTabProps) {
  const access = useAccess();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const ids = useId();
  const [installing, setInstalling] = useState(false);
  const [rebooting, setRebooting] = useState(false);
  const [delay, setDelay] = useState('5');
  const active = device.status !== 'revoked';
  const canApprove = access.has(AP.patchesApprove);
  const canInstall = access.has(AP.patchesInstall) && active;
  const canReboot = access.has(P.devicesManage) && active;
  const query = useQuery({
    queryKey: patchKeys.device(device.id),
    queryFn: () => patchesApi.forDevice(device.id),
    refetchInterval: 60_000,
  });
  const invalidate = async () => {
    await queryClient.invalidateQueries({ queryKey: patchKeys.all });
    await queryClient.invalidateQueries({ queryKey: jobKeys.all });
  };

  const decide = useMutation({
    mutationFn: ({ item, status }: { item: DevicePatchItem; status: PatchDecision }) =>
      patchesApi.decide({ catalogEntryIds: [item.id], status, deviceIds: [device.id] }),
    onSuccess: async (_, { item, status }) => {
      notifySuccess(`${item.title}: ${patchStatus(status).label.toLowerCase()}`);
      await invalidate();
    },
    onError: notifyError,
  });
  const scan = useMutation({
    mutationFn: () => patchesApi.scan({ deviceIds: [device.id] }),
    onSuccess: async () => {
      notifySuccess(device.isOnline ? 'Scan started' : 'Scan queued; it runs when the device connects');
      await invalidate();
    },
    onError: notifyError,
  });
  const delayMinutes = /^\d+$/.test(delay) && Number(delay) <= 1440 ? Number(delay) : null;
  const reboot = useMutation({
    mutationFn: () => patchesApi.rebootDevice(device.id, { delaySeconds: (delayMinutes ?? 5) * 60, notifyUser: true }),
    onSuccess: async (created) => {
      notifySuccess(`Restart of ${device.hostname} requested`);
      setRebooting(false);
      await queryClient.invalidateQueries({ queryKey: qk.deviceDetail(device.id) });
      await navigate(`/jobs/${created.jobId}`);
    },
    onError: (error) => {
      notifyError(error);
      setRebooting(false);
    },
  });

  return (
    <div className="grid gap-4">
      <QueryView query={query} what="updates of this device" rows={6}>
        {(data) => {
          const open = data.items.filter((i) => i.status !== 'installed');
          const approved = data.items.filter((i) => i.status === 'approved').length;
          return (
            <>
              <dl className="bg-card grid grid-cols-2 gap-x-6 gap-y-3 rounded-lg border px-4 py-3 md:grid-cols-4">
                <div>
                  <dt className="text-muted-foreground text-xs">Missing updates</dt>
                  <dd className="mt-0.5 text-lg font-semibold">{open.filter((i) => i.status !== 'rejected').length}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground text-xs">Last scan</dt>
                  <dd className="mt-0.5">
                    <RelativeTime value={data.lastPatchScanAt} fallback="Never" />
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground text-xs">Last install</dt>
                  <dd className="mt-0.5">
                    <RelativeTime value={data.lastPatchInstallAt} fallback="Never" />
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground text-xs">Restart</dt>
                  <dd className="mt-0.5">
                    {data.pendingReboot ? (
                      <PendingRebootBadge />
                    ) : (
                      <span className="text-muted-foreground">Not needed</span>
                    )}
                  </dd>
                </div>
              </dl>
              <Panel
                flush
                title="Updates"
                description="As reported by the device at its last scan. Installed updates are kept for reference."
                actions={
                  <>
                    {canInstall ? (
                      <>
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={scan.isPending}
                          onClick={() => {
                            scan.mutate();
                          }}
                        >
                          <Radar aria-hidden="true" />
                          {scan.isPending ? 'Starting…' : 'Scan now'}
                        </Button>
                        <Button
                          size="sm"
                          disabled={approved === 0}
                          title={approved === 0 ? 'Approve at least one update first.' : undefined}
                          onClick={() => {
                            setInstalling(true);
                          }}
                        >
                          <Download aria-hidden="true" />
                          Install approved ({approved})
                        </Button>
                      </>
                    ) : null}
                    {canReboot ? (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => {
                          setRebooting(true);
                        }}
                      >
                        <Power aria-hidden="true" />
                        Restart device
                      </Button>
                    ) : null}
                  </>
                }
              >
                {data.items.length === 0 ? (
                  <EmptyState icon={Wrench} title={data.lastPatchScanAt ? 'Up to date' : 'Not scanned yet'}>
                    {data.lastPatchScanAt
                      ? 'The last scan found no missing updates.'
                      : 'The device has not reported its updates yet. Start a scan to check now.'}
                  </EmptyState>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead scope="col">Update</TableHead>
                        <TableHead scope="col">Severity</TableHead>
                        <TableHead scope="col">Status</TableHead>
                        <TableHead scope="col" className="hidden lg:table-cell">
                          Version
                        </TableHead>
                        <TableHead scope="col" className="hidden md:table-cell">
                          First seen
                        </TableHead>
                        {canApprove ? (
                          <TableHead scope="col">
                            <span className="sr-only">Decision</span>
                          </TableHead>
                        ) : null}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.items.map((item) => {
                        const st = patchStatus(item.status);
                        const sev = severity(item.severity);
                        const busy = decide.isPending && decide.variables.item.id === item.id;
                        return (
                          <TableRow key={item.id}>
                            <TableHead
                              scope="row"
                              className="text-foreground h-auto max-w-[30rem] py-2 font-medium whitespace-normal"
                            >
                              {item.title}
                              <span className="text-muted-foreground block text-xs font-normal">
                                {patchSourceLabel(item.source)}
                                {item.kb ? (
                                  <>
                                    {' · '}
                                    <span className="ident">{item.kb}</span>
                                  </>
                                ) : null}
                                {item.category ? ` · ${item.category}` : ''}
                                {item.requiresReboot ? ' · needs a restart' : ''}
                              </span>
                              {item.error ? (
                                <span className="text-danger block text-xs font-normal break-words">{item.error}</span>
                              ) : null}
                            </TableHead>
                            <TableCell>
                              <StatusPill tone={sev.tone}>{sev.label}</StatusPill>
                            </TableCell>
                            <TableCell>
                              <span title={st.explain}>
                                <StatusPill tone={st.tone}>{st.label}</StatusPill>
                              </span>
                            </TableCell>
                            <TableCell className="ident hidden text-xs lg:table-cell">
                              {item.currentVersion || item.newVersion
                                ? `${item.currentVersion ?? '?'} → ${item.newVersion ?? '?'}`
                                : '–'}
                            </TableCell>
                            <TableCell className="hidden md:table-cell">
                              <RelativeTime value={item.firstSeenAt} />
                            </TableCell>
                            {canApprove ? (
                              <TableCell className="text-right">
                                {item.status === 'installed' ? null : (
                                  <span className="inline-flex gap-1">
                                    {item.status !== 'approved' ? (
                                      <Button
                                        variant="outline"
                                        size="xs"
                                        disabled={busy}
                                        onClick={() => {
                                          decide.mutate({ item, status: 'approved' });
                                        }}
                                      >
                                        <CircleCheck aria-hidden="true" />
                                        Approve<span className="sr-only"> {item.title}</span>
                                      </Button>
                                    ) : null}
                                    {item.status !== 'rejected' ? (
                                      <Button
                                        variant="ghost"
                                        size="xs"
                                        disabled={busy}
                                        onClick={() => {
                                          decide.mutate({ item, status: 'rejected' });
                                        }}
                                      >
                                        <Ban aria-hidden="true" />
                                        Reject<span className="sr-only"> {item.title}</span>
                                      </Button>
                                    ) : (
                                      <Button
                                        variant="ghost"
                                        size="xs"
                                        disabled={busy}
                                        onClick={() => {
                                          decide.mutate({ item, status: 'pending' });
                                        }}
                                      >
                                        Undo<span className="sr-only"> rejection of {item.title}</span>
                                      </Button>
                                    )}
                                  </span>
                                )}
                              </TableCell>
                            ) : null}
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                )}
              </Panel>
            </>
          );
        }}
      </QueryView>
      <KnownLimits />
      {installing ? (
        <InstallUpdatesDialog
          device={{ id: device.id, hostname: device.hostname, os: device.os }}
          label={`approved updates on ${device.hostname}`}
          onClose={() => {
            setInstalling(false);
          }}
        />
      ) : null}
      <ConfirmDialog
        open={rebooting}
        onOpenChange={setRebooting}
        title={`Restart ${device.hostname}?`}
        description={
          <>
            <p>
              The signed-in user is told and the device restarts after the delay below. Unsaved work on the device may
              be lost.
            </p>
            <div className="grid gap-1.5">
              <label htmlFor={`${ids}-delay`} className="text-foreground text-sm font-medium">
                Delay (minutes, 0 to 1440)
              </label>
              <Input
                id={`${ids}-delay`}
                inputMode="numeric"
                className="w-32"
                value={delay}
                maxLength={4}
                aria-invalid={delayMinutes === null ? true : undefined}
                onChange={(e) => {
                  setDelay(e.target.value);
                }}
              />
            </div>
          </>
        }
        confirmLabel="Restart device"
        destructive
        pending={reboot.isPending}
        onConfirm={() => {
          if (delayMinutes !== null) {
            reboot.mutate();
          }
        }}
      />
    </div>
  );
}
