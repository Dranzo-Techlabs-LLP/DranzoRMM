import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Ban, CircleCheck, Clock, Download, Pencil, Plus, Radar, ShieldCheck, Trash2, Wrench } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { OsIcon } from '@/components/os';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { PendingRebootBadge, StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AP } from '@/features/jobs/permissions';
import { describeCron } from '@/features/scripts/cron';
import { type Id } from '@/lib/api';
import {
  PATCH_SEVERITIES,
  PATCH_SOURCES,
  patchesApi,
  patchKeys,
  patchPoliciesApi,
  type PatchCatalogFilter,
  type PatchCatalogRow,
  type PatchDecision,
  type PatchPolicy,
} from '@/lib/api/patches';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { formatDateTime } from '@/lib/format';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { InstallUpdatesDialog } from './InstallUpdatesDialog';
import { KnownLimits } from './KnownLimits';
import { COMPLIANCE, describePolicy, formatMinutes, patchSourceLabel, REBOOT_MODE_TEXT, severity } from './patch-model';
import { PolicyDialog } from './PolicyDialog';
import { ScanUpdatesDialog } from './ScanUpdatesDialog';

const VIEWS = ['updates', 'compliance', 'policies'] as const;

export default function PatchesPage() {
  useDocumentTitle('Patches');
  const [params, setParams] = useSearchParams();
  const requested = params.get('view');
  const view = VIEWS.find((v) => v === requested) ?? 'updates';
  return (
    <>
      <PageHeader
        title="Patches"
        description="Operating system and application updates your devices report as missing, which ones are approved, and how each device stands."
      />
      <KnownLimits className="mb-4" />
      <Tabs
        value={view}
        onValueChange={(next) => {
          setParams(next === 'updates' ? {} : { view: next }, { replace: true });
        }}
      >
        <TabsList variant="line" className="mb-4 w-full justify-start border-b">
          <TabsTrigger value="updates" className="flex-none px-3">
            Updates
          </TabsTrigger>
          <TabsTrigger value="compliance" className="flex-none px-3">
            Compliance
          </TabsTrigger>
          <TabsTrigger value="policies" className="flex-none px-3">
            Policies
          </TabsTrigger>
        </TabsList>
        <TabsContent value="updates">
          <CatalogPanel />
        </TabsContent>
        <TabsContent value="compliance">
          <CompliancePanel />
        </TabsContent>
        <TabsContent value="policies">
          <PoliciesPanel />
        </TabsContent>
      </Tabs>
    </>
  );
}

const DECISIONS: { status: PatchDecision; label: string; icon: typeof CircleCheck; verb: string }[] = [
  { status: 'approved', label: 'Approve', icon: CircleCheck, verb: 'approved' },
  { status: 'rejected', label: 'Reject', icon: Ban, verb: 'rejected' },
  { status: 'deferred', label: 'Defer', icon: Clock, verb: 'deferred' },
];

function CatalogPanel() {
  const access = useAccess();
  const queryClient = useQueryClient();
  const { orgId, organization } = useOrgFilter();
  const [status, setStatus] = useState('');
  const [sev, setSev] = useState('');
  const [source, setSource] = useState('');
  const [selected, setSelected] = useState<Set<Id>>(() => new Set());
  const [deciding, setDeciding] = useState<PatchDecision | null>(null);
  const [installing, setInstalling] = useState(false);
  const [scanning, setScanning] = useState(false);
  const filter: PatchCatalogFilter = {
    organizationId: orgId ?? undefined,
    status: status || undefined,
    severity: sev || undefined,
    source: source || undefined,
  };
  const query = useQuery({ queryKey: patchKeys.catalog(filter), queryFn: () => patchesApi.catalog(filter) });
  const rows = query.data ?? [];
  const chosen = rows.filter((r) => selected.has(r.id));
  const canApprove = access.has(AP.patchesApprove);
  const canInstall = access.has(AP.patchesInstall);
  const affected = chosen.reduce((n, r) => n + r.devices, 0);

  const decide = useMutation({
    mutationFn: (decision: PatchDecision) =>
      patchesApi.decide({
        catalogEntryIds: chosen.map((r) => r.id),
        status: decision,
        organizationId: orgId ?? undefined,
      }),
    onSuccess: async (result, decision) => {
      notifySuccess(
        `${DECISIONS.find((d) => d.status === decision)?.label ?? 'Updated'}: ${result.updated} device ${result.updated === 1 ? 'entry' : 'entries'} changed`,
      );
      setDeciding(null);
      setSelected(new Set());
      await queryClient.invalidateQueries({ queryKey: patchKeys.all });
    },
    onError: (error) => {
      notifyError(error);
      setDeciding(null);
    },
  });

  const toggleAll = (on: boolean) => {
    setSelected(on ? new Set(rows.map((r) => r.id)) : new Set());
  };
  const decision = DECISIONS.find((d) => d.status === deciding);

  return (
    <>
      <Panel flush>
        <form
          role="search"
          aria-label="Filter updates"
          className="flex flex-wrap items-end gap-3 border-b px-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
          }}
        >
          <FilterSelect id="patch-status" label="Status" value={status} onChange={setStatus}>
            <NativeSelectOption value="">Not installed yet</NativeSelectOption>
            <NativeSelectOption value="pending">Needs decision</NativeSelectOption>
            <NativeSelectOption value="approved">Approved</NativeSelectOption>
            <NativeSelectOption value="failed">Failed</NativeSelectOption>
            <NativeSelectOption value="deferred">Deferred</NativeSelectOption>
            <NativeSelectOption value="rejected">Rejected</NativeSelectOption>
            <NativeSelectOption value="installed">Installed</NativeSelectOption>
          </FilterSelect>
          <FilterSelect id="patch-severity" label="Severity" value={sev} onChange={setSev}>
            <NativeSelectOption value="">Any</NativeSelectOption>
            {PATCH_SEVERITIES.map((s) => (
              <NativeSelectOption key={s} value={s}>
                {severity(s).label}
              </NativeSelectOption>
            ))}
          </FilterSelect>
          <FilterSelect id="patch-source" label="Source" value={source} onChange={setSource}>
            <NativeSelectOption value="">Any</NativeSelectOption>
            {PATCH_SOURCES.map((s) => (
              <NativeSelectOption key={s} value={s}>
                {patchSourceLabel(s)}
              </NativeSelectOption>
            ))}
          </FilterSelect>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            {canInstall ? (
              <>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setScanning(true);
                  }}
                >
                  <Radar aria-hidden="true" />
                  Scan devices
                </Button>
                <Button
                  type="button"
                  size="sm"
                  onClick={() => {
                    setInstalling(true);
                  }}
                >
                  <Download aria-hidden="true" />
                  {chosen.length > 0 ? `Install ${chosen.length} selected…` : 'Install approved…'}
                </Button>
              </>
            ) : null}
          </div>
        </form>
        {canApprove && chosen.length > 0 ? (
          <div
            role="region"
            aria-label="Selected updates"
            className="bg-muted/50 flex flex-wrap items-center gap-2 border-b px-4 py-2"
          >
            <p className="mr-2 text-sm" aria-live="polite">
              {chosen.length} selected, on {affected.toLocaleString('en')} device {affected === 1 ? 'entry' : 'entries'}
              {organization ? ` in ${organization.name}` : ''}
            </p>
            {DECISIONS.map((d) => (
              <Button
                key={d.status}
                variant="outline"
                size="sm"
                onClick={() => {
                  setDeciding(d.status);
                }}
              >
                <d.icon aria-hidden="true" />
                {d.label}
              </Button>
            ))}
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setSelected(new Set());
              }}
            >
              Clear selection
            </Button>
          </div>
        ) : null}
        <QueryView
          query={query}
          what="updates"
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyState
              icon={Wrench}
              title={status || sev || source ? 'No updates match these filters' : 'No missing updates reported'}
            >
              {status || sev || source
                ? null
                : 'Devices report the updates they are missing after each update scan. Run a scan if this is unexpected.'}
            </EmptyState>
          }
        >
          {(data) => (
            <Table>
              <TableHeader>
                <TableRow>
                  {canApprove ? (
                    <TableHead scope="col" className="w-8">
                      <Checkbox
                        aria-label="Select all updates"
                        checked={chosen.length === data.length ? true : chosen.length > 0 ? 'indeterminate' : false}
                        onCheckedChange={(c) => {
                          toggleAll(c === true);
                        }}
                      />
                    </TableHead>
                  ) : null}
                  <TableHead scope="col">Update</TableHead>
                  <TableHead scope="col">Severity</TableHead>
                  <TableHead scope="col" className="hidden md:table-cell">
                    Source
                  </TableHead>
                  <TableHead scope="col" className="text-right">
                    Devices
                  </TableHead>
                  <TableHead scope="col">By status</TableHead>
                  <TableHead scope="col" className="hidden xl:table-cell">
                    First seen
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.map((r) => (
                  <CatalogRow
                    key={r.id}
                    row={r}
                    status={status}
                    selectable={canApprove}
                    selected={selected.has(r.id)}
                    onSelect={(on) => {
                      const next = new Set(selected);
                      if (on) {
                        next.add(r.id);
                      } else {
                        next.delete(r.id);
                      }
                      setSelected(next);
                    }}
                  />
                ))}
              </TableBody>
            </Table>
          )}
        </QueryView>
      </Panel>
      <ConfirmDialog
        open={deciding !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeciding(null);
          }
        }}
        title={`${decision?.label ?? ''} ${chosen.length} ${chosen.length === 1 ? 'update' : 'updates'}?`}
        description={
          <>
            <p>
              This changes {affected.toLocaleString('en')} device {affected === 1 ? 'entry' : 'entries'}
              {organization ? ` in ${organization.name}` : ' across all organizations you can manage'}. Updates already
              installed are not touched.
            </p>
            {deciding === 'approved' ? (
              <p>Approved updates install in the next maintenance window, or when someone starts an install.</p>
            ) : deciding === 'rejected' ? (
              <p>Rejected updates are never installed and no longer count as missing.</p>
            ) : (
              <p>Deferred updates are not installed until someone approves them.</p>
            )}
          </>
        }
        confirmLabel={`${decision?.label ?? 'Apply'} ${chosen.length}`}
        destructive={deciding === 'rejected'}
        pending={decide.isPending}
        onConfirm={() => {
          if (deciding) {
            decide.mutate(deciding);
          }
        }}
      />
      {installing ? (
        <InstallUpdatesDialog
          catalogEntryIds={chosen.length > 0 ? chosen.map((r) => r.id) : undefined}
          label={
            chosen.length > 0 ? `${chosen.length} selected ${chosen.length === 1 ? 'update' : 'updates'}` : undefined
          }
          onClose={() => {
            setInstalling(false);
          }}
        />
      ) : null}
      {scanning ? (
        <ScanUpdatesDialog
          onClose={() => {
            setScanning(false);
          }}
        />
      ) : null}
    </>
  );
}

function CatalogRow({
  row,
  status,
  selectable,
  selected,
  onSelect,
}: {
  row: PatchCatalogRow;
  /** The status filter: rows outside the four counted statuses are deferred, or installed with that filter. */
  status: string;
  selectable: boolean;
  selected: boolean;
  onSelect: (on: boolean) => void;
}) {
  const s = severity(row.severity);
  return (
    <TableRow data-state={selected ? 'selected' : undefined}>
      {selectable ? (
        <TableCell>
          <Checkbox
            aria-label={`Select ${row.title}`}
            checked={selected}
            onCheckedChange={(c) => {
              onSelect(c === true);
            }}
          />
        </TableCell>
      ) : null}
      <TableHead scope="row" className="text-foreground h-auto max-w-[32rem] py-2 font-medium whitespace-normal">
        {row.title}
        <span className="text-muted-foreground block text-xs font-normal">
          {row.kb ? <span className="ident">{row.kb}</span> : null}
          {row.kb && row.category ? ' · ' : ''}
          {row.category}
        </span>
      </TableHead>
      <TableCell>
        <StatusPill tone={s.tone}>{s.label}</StatusPill>
      </TableCell>
      <TableCell className="hidden md:table-cell">{patchSourceLabel(row.source)}</TableCell>
      <TableCell className="text-right">{row.devices.toLocaleString('en')}</TableCell>
      <TableCell className="whitespace-normal">
        <span className="inline-flex flex-wrap gap-1">
          {row.pending > 0 ? <StatusPill tone="warn">{row.pending} need decision</StatusPill> : null}
          {row.approved > 0 ? <StatusPill tone="info">{row.approved} approved</StatusPill> : null}
          {row.failed > 0 ? <StatusPill tone="danger">{row.failed} failed</StatusPill> : null}
          {row.rejected > 0 ? <StatusPill tone="idle">{row.rejected} rejected</StatusPill> : null}
          {row.devices - row.pending - row.approved - row.failed - row.rejected > 0 ? (
            <StatusPill tone="idle">
              {row.devices - row.pending - row.approved - row.failed - row.rejected}{' '}
              {status === 'installed' ? 'installed' : 'deferred'}
            </StatusPill>
          ) : null}
        </span>
      </TableCell>
      <TableCell className="hidden xl:table-cell">
        <RelativeTime value={row.firstSeenAt} />
      </TableCell>
    </TableRow>
  );
}

function FilterSelect({
  id,
  label,
  value,
  onChange,
  children,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  children: ReactNode;
}) {
  return (
    <div className="grid gap-1">
      <Label htmlFor={id} className="text-xs">
        {label}
      </Label>
      <NativeSelect
        id={id}
        size="sm"
        value={value}
        onChange={(e) => {
          onChange(e.target.value);
        }}
      >
        {children}
      </NativeSelect>
    </div>
  );
}

function CompliancePanel() {
  const access = useAccess();
  const { orgId, organization, organizations } = useOrgFilter();
  const [state, setState] = useState('');
  const query = useQuery({
    queryKey: patchKeys.compliance(orgId),
    queryFn: () => patchesApi.compliance(orgId ?? undefined),
    refetchInterval: 60_000,
  });
  const orgName = (id: string) => organizations.find((o) => o.id === id)?.name ?? '';
  return (
    <QueryView query={query} what="patch compliance" rows={8}>
      {(data) => {
        const items = state ? data.items.filter((i) => i.state === state) : data.items;
        const pct = data.total > 0 ? Math.round((data.patched / data.total) * 100) : 0;
        return (
          <div className="grid gap-4">
            <dl className="bg-card grid grid-cols-2 gap-x-6 gap-y-3 rounded-lg border px-4 py-3 md:grid-cols-4">
              <Total label="Devices" value={data.total} hint={organization ? organization.name : 'All organizations'} />
              <Total
                label="Patched"
                value={data.patched}
                hint={data.total > 0 ? `${pct}% of devices` : undefined}
                tone="text-ok"
              />
              <Total
                label="Missing updates"
                value={data.unpatched}
                tone={data.unpatched > 0 ? 'text-warn' : undefined}
              />
              <Total label="Not scanned yet" value={data.unknown} />
            </dl>
            <Panel
              flush
              title="Per device"
              description="Patched means the last scan found no missing updates (rejected updates do not count)."
              actions={
                <>
                  <Label htmlFor="compliance-state" className="text-xs">
                    Show
                  </Label>
                  <NativeSelect
                    id="compliance-state"
                    size="sm"
                    value={state}
                    onChange={(e) => {
                      setState(e.target.value);
                    }}
                  >
                    <NativeSelectOption value="">All devices</NativeSelectOption>
                    <NativeSelectOption value="unpatched">Missing updates</NativeSelectOption>
                    <NativeSelectOption value="patched">Patched</NativeSelectOption>
                    <NativeSelectOption value="unknown">Not scanned</NativeSelectOption>
                  </NativeSelect>
                </>
              }
            >
              {items.length === 0 ? (
                <EmptyState
                  icon={ShieldCheck}
                  title={data.total === 0 ? 'No active devices' : 'No devices in this state'}
                />
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead scope="col">Device</TableHead>
                      <TableHead scope="col">State</TableHead>
                      <TableHead scope="col" className="text-right">
                        Missing
                      </TableHead>
                      <TableHead scope="col" className="text-right">
                        Critical or important
                      </TableHead>
                      <TableHead scope="col" className="text-right">
                        Failed
                      </TableHead>
                      <TableHead scope="col" className="hidden md:table-cell">
                        Restart
                      </TableHead>
                      <TableHead scope="col" className="hidden lg:table-cell">
                        Last scan
                      </TableHead>
                      <TableHead scope="col" className="hidden xl:table-cell">
                        Last install
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {items.map((d) => {
                      const c = COMPLIANCE[d.state] ?? { label: d.state, tone: 'idle' as const };
                      return (
                        <TableRow key={d.id}>
                          <TableHead scope="row" className="text-foreground h-auto py-2 font-medium">
                            <span className="inline-flex items-center gap-1.5">
                              <OsIcon os={d.os} labelled className="text-muted-foreground" />
                              {access.has(P.devicesRead) ? (
                                <Link to={`/devices/${d.id}?tab=patches`} className="text-link ident hover:underline">
                                  {d.hostname}
                                </Link>
                              ) : (
                                <span className="ident">{d.hostname}</span>
                              )}
                            </span>
                            {orgId ? null : (
                              <span className="text-muted-foreground block text-xs font-normal">
                                {orgName(d.organizationId)}
                              </span>
                            )}
                          </TableHead>
                          <TableCell>
                            <StatusPill tone={c.tone}>{c.label}</StatusPill>
                          </TableCell>
                          <TableCell className="text-right">{d.missing}</TableCell>
                          <TableCell
                            className={d.missingCritical > 0 ? 'text-danger text-right font-semibold' : 'text-right'}
                          >
                            {d.missingCritical}
                          </TableCell>
                          <TableCell className={d.failed > 0 ? 'text-danger text-right font-semibold' : 'text-right'}>
                            {d.failed}
                          </TableCell>
                          <TableCell className="hidden md:table-cell">
                            {d.pendingReboot ? (
                              <PendingRebootBadge />
                            ) : (
                              <span className="text-muted-foreground">Not needed</span>
                            )}
                          </TableCell>
                          <TableCell className="hidden lg:table-cell">
                            <RelativeTime value={d.lastPatchScanAt} fallback="Never" />
                          </TableCell>
                          <TableCell className="hidden xl:table-cell">
                            <RelativeTime value={d.lastPatchInstallAt} fallback="Never" />
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </Panel>
          </div>
        );
      }}
    </QueryView>
  );
}

function Total({ label, value, hint, tone }: { label: string; value: number; hint?: string; tone?: string }) {
  return (
    <div>
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className={`mt-0.5 text-xl font-semibold ${tone ?? ''}`}>{value.toLocaleString('en')}</dd>
      {hint ? <dd className="text-muted-foreground text-xs">{hint}</dd> : null}
    </div>
  );
}

function PoliciesPanel() {
  const access = useAccess();
  const queryClient = useQueryClient();
  const { organizations } = useOrgFilter();
  const [editing, setEditing] = useState<PatchPolicy | 'new' | null>(null);
  const [deleting, setDeleting] = useState<PatchPolicy | null>(null);
  const query = useQuery({ queryKey: patchKeys.policies, queryFn: patchPoliciesApi.list });
  const canManage = access.has(AP.patchesApprove);
  const canEdit = (p: PatchPolicy) =>
    canManage && (p.organizationId !== null || access.hasPartnerWide(AP.patchesApprove));

  const remove = useMutation({
    mutationFn: (p: PatchPolicy) => patchPoliciesApi.remove(p.id),
    onSuccess: async (_, p) => {
      notifySuccess(`Policy “${p.name}” deleted`);
      setDeleting(null);
      await queryClient.invalidateQueries({ queryKey: patchKeys.policies });
    },
    onError: (error) => {
      notifyError(error);
      setDeleting(null);
    },
  });

  return (
    <>
      <Panel
        flush
        title="Patch policies"
        description="Each organization follows its own policy if it has one, otherwise the shared one. Without any policy, every update waits for manual approval and nothing installs on a schedule."
        actions={
          canManage ? (
            <Button
              size="sm"
              onClick={() => {
                setEditing('new');
              }}
            >
              <Plus aria-hidden="true" />
              New policy
            </Button>
          ) : undefined
        }
      >
        <QueryView
          query={query}
          what="patch policies"
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyState icon={ShieldCheck} title="No patch policies">
              Create one to approve critical updates automatically and install them in a nightly or weekly maintenance
              window.
            </EmptyState>
          }
        >
          {(policies) => (
            <ul className="divide-y">
              {policies.map((p) => {
                const cron = p.windowCron ? describeCron(p.windowCron) : null;
                return (
                  <li key={p.id} className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
                    <div className="min-w-0 flex-1">
                      <p className="font-medium">
                        {p.name}
                        {!p.enabled ? (
                          <StatusPill tone="idle" className="ml-2">
                            Inactive
                          </StatusPill>
                        ) : null}
                        <span className="text-muted-foreground ml-2 text-xs font-normal">
                          {p.organizationId
                            ? (organizations.find((o) => o.id === p.organizationId)?.name ?? 'One organization')
                            : 'Shared'}
                        </span>
                      </p>
                      <p className="mt-0.5">{describePolicy(p)}</p>
                      <p className="text-muted-foreground mt-0.5 text-xs">
                        {p.windowCron
                          ? `Maintenance window: ${cron?.ok ? cron.text : p.windowCron}, for ${formatMinutes(p.windowMinutes)}${p.organizationId ? '' : ' (UTC)'}.`
                          : 'No maintenance window: installs only when started by hand.'}{' '}
                        {p.enabled && p.nextWindowAt
                          ? `Next window ${formatDateTime(p.nextWindowAt)} (your time). `
                          : ''}
                        Restart: {(REBOOT_MODE_TEXT[p.rebootMode]?.label ?? p.rebootMode).toLowerCase()}
                        {p.rebootMode !== 'never' && p.rebootNotifyUser
                          ? `, user is told first and may postpone ${p.rebootDeferrals} ${p.rebootDeferrals === 1 ? 'time' : 'times'}, at the latest after ${formatMinutes(p.rebootDeadlineMinutes)}`
                          : ''}
                        .
                      </p>
                    </div>
                    {canEdit(p) ? (
                      <div className="flex gap-1.5">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setEditing(p);
                          }}
                        >
                          <Pencil aria-hidden="true" />
                          Edit<span className="sr-only"> {p.name}</span>
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setDeleting(p);
                          }}
                        >
                          <Trash2 aria-hidden="true" />
                          Delete<span className="sr-only"> {p.name}</span>
                        </Button>
                      </div>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          )}
        </QueryView>
      </Panel>
      {editing ? (
        <PolicyDialog
          policy={editing === 'new' ? null : editing}
          onClose={() => {
            setEditing(null);
          }}
        />
      ) : null}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
          }
        }}
        title={`Delete the policy “${deleting?.name ?? ''}”?`}
        description={
          <p>
            Its organizations fall back to the shared policy, or to manual approval if there is none. Updates it already
            approved stay approved.
          </p>
        }
        confirmLabel="Delete policy"
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
