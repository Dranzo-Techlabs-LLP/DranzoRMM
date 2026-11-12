import { useQuery } from '@tanstack/react-query';
import { MonitorSmartphone } from 'lucide-react';
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { OsIcon } from '@/components/os';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { DeviceStatus } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { devicesApi, qk, type DeviceListFilter, type DeviceListItem, type Id } from '@/lib/api';
import { alertKeys, alertsApi } from '@/lib/api/alerts';
import { patchesApi, patchKeys } from '@/lib/api/patches';
import { policiesApi, policyKeys } from '@/lib/api/policies';
import { securityApi, securityKeys } from '@/lib/api/security';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { osLabel } from '@/lib/os';
import { cn } from '@/lib/utils';
import type { FleetCounts } from './fleet';

/**
 * Online / offline proportion. Offline is hatched as well as grey, and the exact numbers are always printed
 * beside the bar, so the bar never carries meaning through colour alone.
 */
function FleetBar({ counts, className }: { counts: Pick<FleetCounts, 'total' | 'online'>; className?: string }) {
  const onlinePct = counts.total === 0 ? 0 : (counts.online / counts.total) * 100;
  return (
    <div
      aria-hidden="true"
      className={cn('bg-idle-surface relative h-2.5 w-full overflow-hidden rounded-[3px]', className)}
      style={{
        backgroundImage:
          counts.total === 0
            ? undefined
            : 'repeating-linear-gradient(135deg, transparent 0 3px, color-mix(in oklab, var(--idle-mark) 45%, transparent) 3px 4px)',
      }}
    >
      <div className="bg-ok-mark absolute inset-y-0 left-0" style={{ width: `${onlinePct}%` }} />
    </div>
  );
}

function Figure({
  label,
  value,
  to,
  note,
  emphasis = false,
}: {
  label: string;
  value: number | string;
  to?: string;
  note?: ReactNode;
  emphasis?: boolean;
}) {
  const body = (
    <>
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className={cn('text-2xl leading-8 font-semibold tracking-tight', emphasis && 'text-danger')}>
        {typeof value === 'number' ? value.toLocaleString('en') : value}
      </dd>
      {note ? <dd className="text-muted-foreground text-xs">{note}</dd> : null}
    </>
  );
  return to ? (
    <Link to={to} className="hover:bg-accent/60 -m-2 block rounded-md p-2">
      {body}
    </Link>
  ) : (
    <div>{body}</div>
  );
}

/** Health figures from the areas the user may read. Each card is hidden when its permission is missing. */
function HealthSummary({ organizationId }: { organizationId?: Id }) {
  const access = useAccess();
  const openFilter = { state: 'open' as const, organizationId, page: 1, pageSize: 1 };
  const alerts = useQuery({
    queryKey: alertKeys.list(openFilter),
    queryFn: ({ signal }) => alertsApi.list(openFilter, signal),
    enabled: access.has(P.alertsRead),
    refetchInterval: 60_000,
  });
  const posture = useQuery({
    queryKey: securityKeys.posture(organizationId),
    queryFn: () => securityApi.posture(organizationId),
    enabled: access.has(P.securityRead),
    refetchInterval: 5 * 60_000,
  });
  const compliance = useQuery({
    queryKey: policyKeys.compliance(organizationId),
    queryFn: () => policiesApi.compliance(organizationId),
    enabled: access.has(P.policiesRead),
    refetchInterval: 5 * 60_000,
  });
  const patches = useQuery({
    queryKey: patchKeys.compliance(organizationId),
    queryFn: () => patchesApi.compliance(organizationId),
    enabled: access.has(P.patchesRead),
    refetchInterval: 5 * 60_000,
  });

  const cards: ReactNode[] = [];
  if (access.has(P.alertsRead)) {
    const n = alerts.data?.total;
    cards.push(
      <Figure
        key="alerts"
        label="Open alerts"
        value={n ?? '…'}
        to="/alerts"
        emphasis={(n ?? 0) > 0}
        note={n === 0 ? 'Nothing needs attention' : undefined}
      />,
    );
  }
  if (access.has(P.securityRead) && posture.data) {
    const d = posture.data;
    const issues = Math.max(d.antivirusIssues, d.firewallIssues, d.encryptionIssues);
    cards.push(
      <Figure
        key="security"
        label="Devices with a protection problem"
        value={
          new Set(
            d.items
              .filter((i) => i.antivirusOk === false || i.firewallOk === false || i.encryptionOk === false)
              .map((i) => i.id),
          ).size
        }
        to="/security"
        emphasis={issues > 0}
        note={`Antivirus ${d.antivirusIssues}, firewall ${d.firewallIssues}, encryption ${d.encryptionIssues}`}
      />,
      <Figure
        key="kev"
        label="Devices with known exploited vulnerabilities"
        value={d.withKnownExploited}
        to="/security?tab=vulnerabilities"
        emphasis={d.withKnownExploited > 0}
      />,
    );
  }
  if (access.has(P.policiesRead) && compliance.data && compliance.data.devices > 0) {
    const c = compliance.data;
    cards.push(
      <Figure
        key="compliance"
        label="Compliant devices"
        value={`${c.compliantDevices} of ${c.devices}`}
        to="/policies"
        note={
          c.devices === c.compliantDevices
            ? 'All checked devices comply'
            : `${c.devices - c.compliantDevices} out of compliance`
        }
      />,
    );
  }
  if (access.has(P.patchesRead) && patches.data) {
    const p = patches.data;
    cards.push(
      <Figure
        key="patches"
        label="Fully updated devices"
        value={`${p.patched} of ${p.total}`}
        to="/patches"
        note={`${p.unpatched} missing updates, ${p.unknown} not scanned yet`}
      />,
    );
  }
  if (cards.length === 0) {
    return null;
  }
  return (
    <Panel title="Health">
      <dl className="grid grid-cols-2 gap-x-8 gap-y-4 md:grid-cols-3 xl:grid-cols-5">{cards}</dl>
    </Panel>
  );
}

function DeviceShortList({ title, empty, filter }: { title: string; empty: string; filter: DeviceListFilter }) {
  const query = useQuery({
    queryKey: qk.deviceList(filter),
    queryFn: ({ signal }) => devicesApi.list(filter, signal),
    refetchInterval: 60_000,
  });
  return (
    <Panel title={title} flush>
      <QueryView query={query} what="devices" rows={4}>
        {(data) =>
          data.items.length === 0 ? (
            <p className="text-muted-foreground px-4 py-6 text-center">{empty}</p>
          ) : (
            <ul className="divide-y">
              {data.items.map((d: DeviceListItem) => (
                <li key={d.id} className="flex items-center gap-3 px-4 py-2">
                  <OsIcon os={d.os} className="text-muted-foreground" />
                  <Link to={`/devices/${d.id}`} className="ident min-w-0 flex-1 truncate font-medium hover:underline">
                    {d.hostname}
                  </Link>
                  <DeviceStatus device={d} className="text-xs" />
                  <span className="text-muted-foreground w-28 text-right text-xs">
                    <RelativeTime value={d.lastSeenAt} />
                  </span>
                </li>
              ))}
              {data.total > data.items.length ? (
                <li className="text-muted-foreground px-4 py-2 text-xs">and {data.total - data.items.length} more</li>
              ) : null}
            </ul>
          )
        }
      </QueryView>
    </Panel>
  );
}

export default function OverviewPage() {
  useDocumentTitle('Overview');
  const access = useAccess();
  const { orgId, organization, organizations, available: orgsAvailable } = useOrgFilter();
  const summary = useQuery({
    queryKey: qk.overview(orgId ?? undefined),
    queryFn: ({ signal }) => devicesApi.overview(orgId ?? undefined, signal),
    refetchInterval: 60_000,
  });
  // Exactly one organization visible (the client portal): its name is the subject of the page.
  const onlyOrg = summary.data?.organizations.length === 1 ? summary.data.organizations[0] : undefined;
  const subject = organization?.name ?? onlyOrg?.name;
  const rows = orgsAvailable ? (orgId ? organizations.filter((o) => o.id === orgId) : organizations) : [];

  return (
    <>
      <PageHeader
        title={subject && !orgsAvailable ? subject : 'Overview'}
        description={
          subject ? `Devices and their health in ${subject}.` : 'Every device you manage, across all organizations.'
        }
      />
      <QueryView query={summary} what="the overview">
        {(data) => {
          const { total, online, pendingReboot } = data.devices;
          const offline = total - online;
          if (total === 0) {
            return (
              <Panel>
                <EmptyState
                  icon={MonitorSmartphone}
                  title="No devices yet"
                  action={
                    access.hasPartnerWide(P.tenantsManage) ? (
                      <Button asChild size="sm">
                        <Link to="/organizations">Add an organization</Link>
                      </Button>
                    ) : undefined
                  }
                >
                  {access.has(P.enrollmentManage)
                    ? 'Create an enrollment token and install the agent on a computer. It appears here as soon as it connects.'
                    : 'Devices appear here once your IT provider has installed the agent on them.'}
                </EmptyState>
              </Panel>
            );
          }
          return (
            <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
              <Panel>
                <dl className="grid grid-cols-2 gap-x-8 gap-y-4 md:grid-cols-4">
                  <Figure label="Devices" value={total} to="/devices" />
                  <Figure label="Online" value={online} to="/devices?status=online" />
                  <Figure label="Offline" value={offline} to="/devices?status=offline" />
                  <Figure label="Restart pending" value={pendingReboot} to="/devices?reboot=1" />
                </dl>
                <FleetBar counts={{ total, online }} className="mt-4 h-3" />
                <p className="text-muted-foreground mt-2 text-xs">
                  <span className="sr-only">Summary: </span>
                  {`${online} of ${total} devices online (${Math.round((online / total) * 100)}%). Solid is online, hatched is offline.`}
                  {data.devices.byOs.length > 0
                    ? ` ${data.devices.byOs.map((o) => `${osLabel(o.os)}: ${o.count}`).join(', ')}.`
                    : ''}
                </p>
              </Panel>

              <HealthSummary organizationId={orgId ?? undefined} />

              {rows.length > 1 ? (
                <Panel title="By organization" flush>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead scope="col">Organization</TableHead>
                        <TableHead scope="col" className="w-[34%] min-w-40">
                          Online share
                        </TableHead>
                        <TableHead scope="col" className="text-right">
                          Devices
                        </TableHead>
                        <TableHead scope="col" className="text-right">
                          Online
                        </TableHead>
                        <TableHead scope="col" className="text-right">
                          Offline
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {rows.map((r) => (
                        <TableRow key={r.id}>
                          <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-medium">
                            <Link to={`/organizations/${r.id}`} className="hover:underline">
                              {r.name}
                            </Link>
                          </TableHead>
                          <TableCell>
                            <FleetBar counts={{ total: r.deviceCount, online: r.onlineCount }} />
                          </TableCell>
                          <TableCell className="text-right">{r.deviceCount}</TableCell>
                          <TableCell className="text-right">{r.onlineCount}</TableCell>
                          <TableCell className={cn('text-right', r.deviceCount - r.onlineCount > 0 && 'font-medium')}>
                            {r.deviceCount - r.onlineCount}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Panel>
              ) : null}

              <div className="grid gap-4 xl:grid-cols-2">
                <DeviceShortList
                  title="Waiting for a restart"
                  empty="No device is waiting for a restart."
                  filter={{ organizationId: orgId ?? undefined, pendingReboot: true, page: 1, pageSize: 8 }}
                />
                <DeviceShortList
                  title="Offline, most recently seen first"
                  empty="Every device is online."
                  filter={{ organizationId: orgId ?? undefined, online: false, sort: 'lastSeen', page: 1, pageSize: 8 }}
                />
              </div>
            </div>
          );
        }}
      </QueryView>
    </>
  );
}
