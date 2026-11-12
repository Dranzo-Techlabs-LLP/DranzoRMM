import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Pause, Play, Plus, Rocket, Undo2 } from 'lucide-react';
import { useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useGroups } from '@/features/tenants/queries';
import { releaseKeys, releasesApi, type AgentRelease, type ReleaseRing } from '@/lib/api/releases';
import { formatBytes } from '@/lib/format';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import { CreateReleaseWizard } from './CreateReleaseWizard';
import { groupsReached, KIND_LABEL, RING_LABEL, RING_ORDER, UPDATE_STATE_LABEL } from './release-model';

type RolloutChange = { release: AgentRelease; ring?: ReleaseRing; paused?: boolean };

export default function ReleasesPage() {
  useDocumentTitle('Agent releases');
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [change, setChange] = useState<RolloutChange | null>(null);
  const [details, setDetails] = useState<AgentRelease | null>(null);
  const releases = useQuery({ queryKey: releaseKeys.list, queryFn: releasesApi.list, refetchInterval: 30_000 });
  const groups = useGroups();

  const rollout = useMutation({
    mutationFn: (c: RolloutChange) => releasesApi.rollout(c.release.id, { ring: c.ring, paused: c.paused }),
    onSuccess: async (_, c) => {
      notifySuccess(
        c.paused === true
          ? `Rollout of ${c.release.version} paused`
          : c.paused === false
            ? `Rollout of ${c.release.version} resumed`
            : `${c.release.version}: ${RING_LABEL[c.ring ?? 'none']}`,
      );
      setChange(null);
      await queryClient.invalidateQueries({ queryKey: releaseKeys.list });
    },
    onError: notifyError,
  });

  const reach = (ring: string) => {
    if (ring === 'none') {
      return 'No device is offered this version.';
    }
    const reached = groups.data ? groupsReached(ring, groups.data) : undefined;
    if (reached === null) {
      return 'Every enrolled device is offered this version, including devices that are not in a group.';
    }
    if (reached === undefined) {
      return 'Devices in the groups of this ring are offered this version.';
    }
    return reached.length === 0
      ? 'No device group is in this ring yet, so no device is offered this version. Set a group’s update ring on its organization page.'
      : `Devices in ${reached.length} ${reached.length === 1 ? 'group' : 'groups'} are offered this version: ${reached
          .slice(0, 6)
          .map((g) => g.name)
          .join(
            ', ',
          )}${reached.length > 6 ? ` and ${reached.length - 6} more` : ''}. Devices outside any group wait for “every device”.`;
  };

  return (
    <>
      <PageHeader
        title="Agent releases"
        description="Signed agent versions and how far each has been rolled out. Devices update ring by ring (test, then pilot, then everyone) and roll back automatically if the new version cannot connect."
        actions={
          <Button
            size="sm"
            onClick={() => {
              setCreating(true);
            }}
          >
            <Plus aria-hidden="true" />
            New release
          </Button>
        }
      />
      <QueryView query={releases} what="agent releases">
        {(data) => (
          <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
            <Panel title="Installed versions" description="Active devices by the agent version they run.">
              {data.installedVersions.length === 0 ? (
                <p className="text-muted-foreground">No devices enrolled.</p>
              ) : (
                <ul className="flex flex-wrap gap-2">
                  {[...data.installedVersions]
                    .sort((a, b) => b.devices - a.devices)
                    .map((v) => (
                      <li key={v.version || 'unknown'} className="bg-muted rounded-md px-2.5 py-1 text-sm">
                        <span className="ident font-medium">{v.version || 'unknown'}</span>{' '}
                        <span className="text-muted-foreground">
                          {v.devices} {v.devices === 1 ? 'device' : 'devices'}
                        </span>
                      </li>
                    ))}
                </ul>
              )}
            </Panel>
            <Panel title="Releases" flush>
              {data.items.length === 0 ? (
                <EmptyState icon={Rocket} title="No releases yet">
                  Upload signed agent builds to publish a version. It is offered to no device until you choose a ring.
                </EmptyState>
              ) : (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead scope="col">Version</TableHead>
                        <TableHead scope="col">Offered to</TableHead>
                        <TableHead scope="col">Progress</TableHead>
                        <TableHead scope="col">Files</TableHead>
                        <TableHead scope="col">Created</TableHead>
                        <TableHead scope="col">
                          <span className="sr-only">Actions</span>
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.items.map((r) => {
                        const index = RING_ORDER.indexOf(r.ring as ReleaseRing);
                        const next = index >= 0 && index < RING_ORDER.length - 1 ? RING_ORDER[index + 1] : undefined;
                        const previous = index > 0 ? RING_ORDER[index - 1] : undefined;
                        const failures = (r.progress.rolled_back ?? 0) + (r.progress.failed ?? 0);
                        return (
                          <TableRow key={r.id}>
                            <TableHead
                              scope="row"
                              className="text-foreground h-auto max-w-64 py-2 text-sm font-normal whitespace-normal"
                            >
                              <span className="ident font-semibold">{r.version}</span>
                              {r.notes ? (
                                <div className="text-muted-foreground line-clamp-2 text-xs">{r.notes}</div>
                              ) : null}
                            </TableHead>
                            <TableCell>
                              <div className="flex flex-col items-start gap-1">
                                <span>{RING_LABEL[r.ring] ?? r.ring}</span>
                                {r.paused ? (
                                  <StatusPill tone="warn" icon={Pause}>
                                    Paused
                                  </StatusPill>
                                ) : null}
                              </div>
                            </TableCell>
                            <TableCell className="whitespace-normal">
                              {Object.keys(r.progress).length === 0 ? (
                                <span className="text-muted-foreground">Not offered yet</span>
                              ) : (
                                <ul className="flex flex-wrap gap-x-3 gap-y-0.5 text-xs">
                                  {Object.entries(r.progress).map(([state, n]) => (
                                    <li
                                      key={state}
                                      className={
                                        state === 'rolled_back' || state === 'failed'
                                          ? 'text-danger font-semibold'
                                          : undefined
                                      }
                                    >
                                      {UPDATE_STATE_LABEL[state] ?? state}: {n}
                                    </li>
                                  ))}
                                </ul>
                              )}
                              {failures > 0 ? (
                                <StatusPill tone="danger" icon={Undo2} className="mt-1">
                                  {failures} did not update
                                </StatusPill>
                              ) : null}
                            </TableCell>
                            <TableCell className="text-xs whitespace-normal">
                              {r.binaries.filter((b) => b.kind === 'binary').length} binaries,{' '}
                              {r.binaries.filter((b) => b.kind !== 'binary').length} installers
                            </TableCell>
                            <TableCell>
                              <RelativeTime value={r.createdAt} />
                            </TableCell>
                            <TableCell className="py-1 text-right">
                              <div className="flex flex-wrap justify-end gap-1">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => {
                                    setDetails(r);
                                  }}
                                >
                                  Devices<span className="sr-only"> for {r.version}</span>
                                </Button>
                                {r.ring !== 'none' ? (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => {
                                      setChange({ release: r, paused: !r.paused });
                                    }}
                                  >
                                    {r.paused ? <Play aria-hidden="true" /> : <Pause aria-hidden="true" />}
                                    {r.paused ? 'Resume' : 'Pause'}
                                  </Button>
                                ) : null}
                                {previous ? (
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => {
                                      setChange({ release: r, ring: previous });
                                    }}
                                  >
                                    Back to {previous === 'none' ? 'not offered' : previous}
                                  </Button>
                                ) : null}
                                {next ? (
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => {
                                      setChange({ release: r, ring: next });
                                    }}
                                  >
                                    <Rocket aria-hidden="true" />
                                    Offer to {next === 'all' ? 'everyone' : `${next} ring`}
                                  </Button>
                                ) : null}
                              </div>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
              )}
            </Panel>
          </div>
        )}
      </QueryView>

      <Dialog open={creating} onOpenChange={setCreating}>
        <DialogContent
          className="max-h-[92dvh] overflow-y-auto sm:max-w-3xl"
          onInteractOutside={(e) => {
            e.preventDefault();
          }}
        >
          {creating ? (
            <CreateReleaseWizard
              existingVersions={releases.data?.items.map((r) => r.version) ?? []}
              onDone={() => {
                setCreating(false);
              }}
            />
          ) : null}
        </DialogContent>
      </Dialog>

      <Dialog open={details !== null} onOpenChange={(open) => !open && setDetails(null)}>
        <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-3xl">
          {details ? <ReleaseDetails release={details} /> : null}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={change !== null}
        onOpenChange={(open) => {
          if (!open) {
            setChange(null);
          }
        }}
        title={
          change?.paused === true
            ? `Pause the rollout of ${change.release.version}?`
            : change?.paused === false
              ? `Resume the rollout of ${change.release.version}?`
              : `Offer ${change?.release.version ?? ''} to: ${RING_LABEL[change?.ring ?? 'none']}?`
        }
        description={
          change?.paused === true ? (
            <p>No more devices are offered this version. Devices that already updated keep it.</p>
          ) : change?.paused === false ? (
            <p>{reach(change.release.ring)}</p>
          ) : (
            <>
              <p>{reach(change?.ring ?? 'none')}</p>
              <p>
                Devices update when they are online, at most 50 per minute. You will be asked for your authenticator
                code.
              </p>
            </>
          )
        }
        confirmLabel={change?.paused === true ? 'Pause' : change?.paused === false ? 'Resume' : 'Change rollout'}
        pending={rollout.isPending}
        onConfirm={() => {
          if (change) {
            rollout.mutate(change);
          }
        }}
      />
    </>
  );
}

function ReleaseDetails({ release }: { release: AgentRelease }) {
  const devices = useQuery({
    queryKey: releaseKeys.devices(release.id),
    queryFn: () => releasesApi.devices(release.id),
    refetchInterval: 15_000,
  });
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <DialogHeader>
        <DialogTitle>Release {release.version}</DialogTitle>
        <DialogDescription>Signed files and the update state of each device it was offered to.</DialogDescription>
      </DialogHeader>
      <div className="overflow-x-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead scope="col">File</TableHead>
              <TableHead scope="col" className="text-right">
                Size
              </TableHead>
              <TableHead scope="col">SHA-256</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {release.binaries.map((b) => (
              <TableRow key={b.id}>
                <TableHead scope="row" className="text-foreground h-auto py-1.5 text-sm font-normal">
                  {osLabel(b.os)} {b.arch}
                  <div className="text-muted-foreground text-xs">{KIND_LABEL[b.kind] ?? b.kind}</div>
                </TableHead>
                <TableCell className="text-right">{formatBytes(b.sizeBytes)}</TableCell>
                <TableCell className="ident text-xs break-all whitespace-normal">{b.sha256}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <QueryView
        query={devices}
        what="device update states"
        isEmpty={(d) => d.length === 0}
        empty={<p className="text-muted-foreground py-4 text-center">No device has been offered this version yet.</p>}
        rows={3}
      >
        {(list) => (
          <div className="overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Device</TableHead>
                  <TableHead scope="col">State</TableHead>
                  <TableHead scope="col">Running now</TableHead>
                  <TableHead scope="col">Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {[...list]
                  .sort(
                    (a, b) =>
                      Number(b.state === 'rolled_back' || b.state === 'failed') -
                      Number(a.state === 'rolled_back' || a.state === 'failed'),
                  )
                  .map((d) => {
                    const bad = d.state === 'rolled_back' || d.state === 'failed';
                    return (
                      <TableRow key={d.deviceId} className={bad ? 'bg-danger-surface/50' : undefined}>
                        <TableHead scope="row" className="ident text-foreground h-auto py-1.5 text-sm font-medium">
                          {d.hostname ?? 'Removed device'}
                        </TableHead>
                        <TableCell className="whitespace-normal">
                          <StatusPill
                            tone={bad ? 'danger' : d.state === 'installed' ? 'ok' : 'info'}
                            icon={d.state === 'rolled_back' ? Undo2 : undefined}
                          >
                            {UPDATE_STATE_LABEL[d.state] ?? d.state}
                          </StatusPill>
                          {d.error ? <span className="mt-1 block text-xs break-words">{d.error}</span> : null}
                        </TableCell>
                        <TableCell className="ident">{d.currentVersion}</TableCell>
                        <TableCell>
                          <RelativeTime value={d.updatedAt} />
                        </TableCell>
                      </TableRow>
                    );
                  })}
              </TableBody>
            </Table>
          </div>
        )}
      </QueryView>
    </div>
  );
}
