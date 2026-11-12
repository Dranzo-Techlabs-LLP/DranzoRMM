import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ClipboardCheck, MapPin, Pencil, Play, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { describeScope, type ScopeDirectory } from '@/features/admin/scope';
import { useGroups, useSites } from '@/features/tenants/queries';
import { policiesApi, policyKeys, type Policy } from '@/lib/api/policies';
import { P } from '@/lib/auth/permissions';
import { useAccess, useMe } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import { AssignmentsEditor } from './AssignmentsEditor';
import { ComplianceBar } from './ComplianceBar';
import { checkLabel, describePolicyParams, formatInterval, SCRIPT_CHECK } from './policy-params';
import { PolicyEditor } from './PolicyEditor';

type Section = 'compliance' | 'policies';

export default function PoliciesPage() {
  useDocumentTitle('Policies');
  const [params, setParams] = useSearchParams();
  const section: Section = params.get('tab') === 'policies' ? 'policies' : 'compliance';
  return (
    <>
      <PageHeader
        title="Policies and compliance"
        description="Desired settings that devices are checked against, and how many devices meet them."
      />
      <Tabs
        value={section}
        onValueChange={(next) => {
          setParams(next === 'compliance' ? {} : { tab: next }, { replace: true });
        }}
      >
        <TabsList variant="line" className="mb-4 w-full justify-start border-b">
          <TabsTrigger value="compliance" className="flex-none px-3">
            Compliance
          </TabsTrigger>
          <TabsTrigger value="policies" className="flex-none px-3">
            Policies
          </TabsTrigger>
        </TabsList>
        <TabsContent value="compliance">
          <ComplianceSection />
        </TabsContent>
        <TabsContent value="policies">
          <PolicySection />
        </TabsContent>
      </Tabs>
    </>
  );
}

function ComplianceSection() {
  const { orgId, organization, organizations, available: orgsAvailable } = useOrgFilter();
  const compliance = useQuery({
    queryKey: policyKeys.compliance(orgId ?? undefined),
    queryFn: () => policiesApi.compliance(orgId ?? undefined),
    refetchInterval: 60_000,
  });
  const orgName = new Map(organizations.map((o) => [o.id, o.name]));
  return (
    <QueryView query={compliance} what="compliance">
      {(data) =>
        data.devices === 0 ? (
          <Panel>
            <EmptyState icon={ClipboardCheck} title="No compliance results yet">
              Results appear once a policy is assigned and its devices have been checked. Devices are checked while they
              are online.
            </EmptyState>
          </Panel>
        ) : (
          <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
            <Panel>
              <dl className="grid grid-cols-2 gap-x-8 gap-y-4 md:grid-cols-4">
                <div>
                  <dt className="text-muted-foreground text-xs">
                    Compliant devices{organization ? ` in ${organization.name}` : ''}
                  </dt>
                  <dd className="text-2xl leading-8 font-semibold tracking-tight">
                    {data.compliantDevices.toLocaleString('en')}{' '}
                    <span className="text-muted-foreground text-base font-normal">
                      of {data.devices.toLocaleString('en')}
                    </span>
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground text-xs">Out of compliance</dt>
                  <dd
                    className={`text-2xl leading-8 font-semibold tracking-tight ${data.devices - data.compliantDevices > 0 ? 'text-danger' : ''}`}
                  >
                    {(data.devices - data.compliantDevices).toLocaleString('en')}
                  </dd>
                </div>
              </dl>
              <ComplianceBar
                className="mt-4"
                compliant={data.compliantDevices}
                nonCompliant={data.devices - data.compliantDevices}
                unsupported={0}
              />
            </Panel>
            <Panel title="By policy" description="Each device counts once per policy that applies to it." flush>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Policy</TableHead>
                    <TableHead scope="col" className="w-[32%] min-w-40">
                      Results
                    </TableHead>
                    <TableHead scope="col" className="text-right">
                      Compliant
                    </TableHead>
                    <TableHead scope="col" className="text-right">
                      Not compliant
                    </TableHead>
                    <TableHead scope="col" className="text-right">
                      Not supported
                    </TableHead>
                    <TableHead scope="col" className="text-right">
                      Fixed automatically
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.policies.map((p) => (
                    <TableRow key={p.policyId}>
                      <TableHead
                        scope="row"
                        className="text-foreground h-auto py-2 text-sm font-normal whitespace-normal"
                      >
                        <div className="font-medium">{p.name ?? 'Deleted policy'}</div>
                        <div className="text-muted-foreground text-xs">{checkLabel(p.check)}</div>
                      </TableHead>
                      <TableCell>
                        <ComplianceBar
                          compliant={p.compliant}
                          nonCompliant={p.nonCompliant}
                          unsupported={p.unsupported}
                        />
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{p.compliant}</TableCell>
                      <TableCell
                        className={`text-right tabular-nums ${p.nonCompliant > 0 ? 'text-danger font-medium' : ''}`}
                      >
                        {p.nonCompliant}
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{p.unsupported}</TableCell>
                      <TableCell className="text-right tabular-nums">{p.remediated}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <p className="text-muted-foreground border-t px-4 py-2 text-xs">
                Bars: solid is compliant, hatched is not compliant, light is not supported on that operating system.
              </p>
            </Panel>
            <Panel title={`Devices out of compliance (${data.nonCompliant.length})`} flush>
              {data.nonCompliant.length === 0 ? (
                <p className="text-muted-foreground px-4 py-6 text-center">Every checked device meets every policy.</p>
              ) : (
                <div className="max-h-[36rem] overflow-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead scope="col">Device</TableHead>
                        <TableHead scope="col">Policy</TableHead>
                        <TableHead scope="col">Detail</TableHead>
                        <TableHead scope="col">Not compliant since</TableHead>
                        <TableHead scope="col">Last checked</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.nonCompliant.map((r) => (
                        <TableRow key={`${r.deviceId}:${r.policyId}`}>
                          <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-normal">
                            <Link
                              to={`/devices/${r.deviceId}?tab=compliance`}
                              className="ident font-medium hover:underline"
                            >
                              {r.hostname}
                            </Link>
                            {orgsAvailable && !orgId ? (
                              <div className="text-muted-foreground text-xs">{orgName.get(r.organizationId)}</div>
                            ) : null}
                          </TableHead>
                          <TableCell className="whitespace-normal">{r.policy ?? 'Deleted policy'}</TableCell>
                          <TableCell className="max-w-md text-xs break-words whitespace-pre-wrap">{r.detail}</TableCell>
                          <TableCell>
                            <RelativeTime value={r.nonCompliantSince} fallback="Unknown" />
                          </TableCell>
                          <TableCell>
                            <RelativeTime value={r.evaluatedAt} />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </Panel>
          </div>
        )
      }
    </QueryView>
  );
}

type Dialogs = { kind: 'edit'; policy: Policy | null } | { kind: 'assign'; policyId: string } | null;

function PolicySection() {
  const access = useAccess();
  const me = useMe();
  const queryClient = useQueryClient();
  const { orgId, organizations } = useOrgFilter();
  const sites = useSites();
  const groups = useGroups();
  const [dialog, setDialog] = useState<Dialogs>(null);
  const [deleting, setDeleting] = useState<Policy | null>(null);
  const [evaluating, setEvaluating] = useState(false);
  const canManage = access.has(P.policiesManage);
  const policies = useQuery({ queryKey: policyKeys.list, queryFn: policiesApi.list });
  const directory: ScopeDirectory = { organizations, sites: sites.data ?? [], groups: groups.data ?? [] };
  const canChange = (p: Policy) => canManage && (p.organizationId !== null || me.partnerWide);
  const assigning = dialog?.kind === 'assign' ? policies.data?.items.find((p) => p.id === dialog.policyId) : undefined;

  const remove = useMutation({
    mutationFn: (p: Policy) => policiesApi.remove(p.id),
    onSuccess: async () => {
      notifySuccess('Policy deleted');
      setDeleting(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: policyKeys.list }),
        queryClient.invalidateQueries({ queryKey: policyKeys.complianceAll }),
      ]);
    },
    onError: notifyError,
  });
  const evaluate = useMutation({
    mutationFn: () =>
      orgId
        ? policiesApi.evaluate({ organizationId: orgId })
        : Promise.all(organizations.map((o) => policiesApi.evaluate({ organizationId: o.id }))).then((r) => ({
            deviceCount: r.reduce((n, x) => n + x.deviceCount, 0),
          })),
    onSuccess: (result) => {
      setEvaluating(false);
      notifySuccess(
        result.deviceCount === 0
          ? 'No online device has a policy to check right now.'
          : `Checking ${result.deviceCount} ${result.deviceCount === 1 ? 'device' : 'devices'} now. Results appear on the Compliance tab within a minute or two.`,
      );
      setTimeout(() => {
        void queryClient.invalidateQueries({ queryKey: policyKeys.complianceAll });
      }, 15_000);
    },
    onError: (error) => {
      setEvaluating(false);
      notifyError(error);
    },
  });

  const actions = canManage ? (
    <>
      <Button
        variant="outline"
        size="sm"
        disabled={organizations.length === 0}
        onClick={() => {
          setEvaluating(true);
        }}
      >
        <Play aria-hidden="true" />
        Evaluate now
      </Button>
      <Button
        size="sm"
        disabled={!policies.data}
        onClick={() => {
          setDialog({ kind: 'edit', policy: null });
        }}
      >
        <Plus aria-hidden="true" />
        New policy
      </Button>
    </>
  ) : null;

  return (
    <>
      <Panel title="Policies" actions={actions} flush>
        <QueryView
          query={policies}
          what="policies"
          isEmpty={(d) => d.items.length === 0}
          empty={
            <EmptyState icon={ClipboardCheck} title="No policies yet">
              {canManage
                ? 'Create a policy, then assign it to organizations, sites or groups.'
                : 'Nobody has created a policy yet.'}
            </EmptyState>
          }
        >
          {(data) => (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Policy</TableHead>
                    <TableHead scope="col">Check</TableHead>
                    <TableHead scope="col">Operating systems</TableHead>
                    <TableHead scope="col">Applies to</TableHead>
                    <TableHead scope="col">Schedule</TableHead>
                    <TableHead scope="col">Status</TableHead>
                    {canManage ? (
                      <TableHead scope="col">
                        <span className="sr-only">Actions</span>
                      </TableHead>
                    ) : null}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((p) => {
                    const settings = describePolicyParams(p.check, p.params);
                    const os = p.osTargets.length > 0 ? p.osTargets : (data.checks[p.check] ?? []);
                    return (
                      <TableRow key={p.id}>
                        <TableHead
                          scope="row"
                          className="text-foreground h-auto max-w-64 py-2 text-sm font-normal whitespace-normal"
                        >
                          <div className="font-medium">{p.name}</div>
                          {p.description ? <div className="text-muted-foreground text-xs">{p.description}</div> : null}
                          <div className="text-muted-foreground text-xs">
                            {p.organizationId === null
                              ? 'Shared with all organizations'
                              : `Owned by ${organizations.find((o) => o.id === p.organizationId)?.name ?? 'one organization'}`}
                          </div>
                        </TableHead>
                        <TableCell className="max-w-64 whitespace-normal">
                          <div>{checkLabel(p.check)}</div>
                          {settings ? (
                            <div className="text-muted-foreground text-xs break-words">{settings}</div>
                          ) : null}
                          {p.check === SCRIPT_CHECK ? (
                            <div className="text-warn text-xs font-medium">Runs as SYSTEM / root</div>
                          ) : null}
                        </TableCell>
                        <TableCell>{os.map(osLabel).join(', ')}</TableCell>
                        <TableCell className="max-w-56 whitespace-normal">
                          {p.assignments.length === 0 ? (
                            <span className="text-muted-foreground">Not assigned</span>
                          ) : (
                            <ul className="space-y-0.5">
                              {p.assignments.map((a) => (
                                <li key={a.id}>{describeScope(a.scopeType, a.scopeId, directory)}</li>
                              ))}
                            </ul>
                          )}
                        </TableCell>
                        <TableCell className="whitespace-nowrap">{formatInterval(p.intervalMinutes)}</TableCell>
                        <TableCell>
                          <div className="flex flex-col items-start gap-1">
                            <StatusPill tone={p.enabled ? 'ok' : 'idle'}>{p.enabled ? 'On' : 'Off'}</StatusPill>
                            {p.remediate ? (
                              <span className="text-xs">Fixes automatically</span>
                            ) : (
                              <span className="text-muted-foreground text-xs">Reports only</span>
                            )}
                          </div>
                        </TableCell>
                        {canManage ? (
                          <TableCell className="py-1 text-right">
                            {canChange(p) ? (
                              <div className="flex justify-end gap-1">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => {
                                    setDialog({ kind: 'assign', policyId: p.id });
                                  }}
                                >
                                  <MapPin aria-hidden="true" />
                                  Assign<span className="sr-only"> {p.name}</span>
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => {
                                    setDialog({ kind: 'edit', policy: p });
                                  }}
                                >
                                  <Pencil aria-hidden="true" />
                                  Edit<span className="sr-only"> {p.name}</span>
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="text-destructive hover:text-destructive"
                                  onClick={() => {
                                    setDeleting(p);
                                  }}
                                >
                                  <Trash2 aria-hidden="true" />
                                  Delete<span className="sr-only"> {p.name}</span>
                                </Button>
                              </div>
                            ) : null}
                          </TableCell>
                        ) : null}
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </QueryView>
      </Panel>

      <Dialog
        open={dialog !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDialog(null);
          }
        }}
      >
        <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-2xl">
          {dialog?.kind === 'edit' && policies.data ? (
            <PolicyEditor
              policy={dialog.policy}
              checks={policies.data.checks}
              organizations={organizations}
              partnerWide={me.partnerWide}
              onDone={() => {
                setDialog(null);
              }}
            />
          ) : null}
          {dialog?.kind === 'assign' && assigning ? (
            <AssignmentsEditor
              policy={assigning}
              directory={directory}
              partnerWide={me.partnerWide}
              onDone={() => {
                setDialog(null);
              }}
            />
          ) : null}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
          }
        }}
        title={`Delete the policy ${deleting?.name ?? ''}?`}
        description={
          <p>Its assignments and all compliance results recorded for it are removed. This cannot be undone.</p>
        }
        confirmLabel="Delete policy"
        destructive
        typeToConfirm={deleting?.name}
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) {
            remove.mutate(deleting);
          }
        }}
      />
      <ConfirmDialog
        open={evaluating}
        onOpenChange={setEvaluating}
        title="Check policies now?"
        description={
          <p>
            Every policy that applies is checked right away on the online devices of{' '}
            {orgId ? (organizations.find((o) => o.id === orgId)?.name ?? 'this organization') : 'all organizations'},
            ignoring the schedule. Policies with automatic fixing turned on may change settings on those devices.
          </p>
        }
        confirmLabel="Check now"
        pending={evaluate.isPending}
        onConfirm={() => {
          evaluate.mutate();
        }}
      />
    </>
  );
}
