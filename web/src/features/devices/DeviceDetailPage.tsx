import { useQuery } from '@tanstack/react-query';
import { TriangleAlert } from 'lucide-react';
import { Link, useParams, useSearchParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { OsIcon } from '@/components/os';
import { ErrorState, LoadingRows, PageHeader } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { DeviceStatus, InlineAlert, PendingRebootBadge } from '@/components/status';
import { formatDateTime } from '@/lib/format';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useGroups, useSites } from '@/features/tenants/queries';
import { devicesApi, qk, type DeviceDetail } from '@/lib/api';
import { useAccess } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { osLabel } from '@/lib/os';
import { RemoteSessionsProvider } from '@/features/remote/RemoteSessions';
import { AgentCard } from './AgentCard';
import { TagList } from './DevicesPage';
import { DEVICE_TABS } from './tabs/registry';

export default function DeviceDetailPage() {
  const { deviceId = '' } = useParams();
  const query = useQuery({
    queryKey: qk.deviceDetail(deviceId),
    queryFn: () => devicesApi.get(deviceId),
    refetchInterval: 60_000,
  });
  useDocumentTitle(query.data?.hostname ?? 'Device');

  if (query.isPending) {
    return <LoadingRows label="device" rows={8} />;
  }
  if (query.isError) {
    return <ErrorState error={query.error} what="this device" onRetry={() => void query.refetch()} />;
  }
  // Keyed by the saved values so the edit form resets when the device changes on the server.
  return <DeviceView device={query.data} />;
}

function HeaderFact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  );
}

function DeviceView({ device }: { device: DeviceDetail }) {
  const access = useAccess();
  const { organizations } = useOrgFilter();
  const sites = useSites(device.organizationId);
  const groups = useGroups(device.organizationId);
  const [params, setParams] = useSearchParams();

  const tabs = DEVICE_TABS.filter((t) => access.can(t));
  const requested = params.get('tab');
  const active = tabs.find((t) => t.id === requested)?.id ?? tabs[0]?.id ?? 'overview';

  const organization = organizations.find((o) => o.id === device.organizationId);
  const site = sites.data?.find((s) => s.id === device.siteId);
  const group = groups.data?.find((g) => g.id === device.groupId);
  const location = [organization?.name, site?.name, group?.name].filter(Boolean).join(' / ');

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Devices', to: '/devices' }, { label: device.hostname }]}
        title={<span className="ident">{device.hostname}</span>}
        description={location || undefined}
      />

      {device.possibleDuplicateOfDeviceId ? (
        <InlineAlert tone="warn" live={false} className="mb-4" title="This may be a duplicate">
          Another device reports the same hardware.{' '}
          <Link to={`/devices/${device.possibleDuplicateOfDeviceId}`} className="underline">
            Open the other device
          </Link>{' '}
          and delete whichever entry is stale.
        </InlineAlert>
      ) : null}

      <dl className="bg-card mb-4 grid grid-cols-2 gap-x-6 gap-y-3 rounded-lg border px-4 py-3 md:grid-cols-4 xl:grid-cols-6">
        <HeaderFact label="Status">
          <DeviceStatus device={device} />
        </HeaderFact>
        <HeaderFact label="Last seen">
          {device.isOnline ? 'Connected now' : <RelativeTime value={device.lastSeenAt} />}
        </HeaderFact>
        <HeaderFact label="Operating system">
          <span className="inline-flex items-center gap-1.5">
            <OsIcon os={device.os} className="text-muted-foreground" />
            {device.osName || osLabel(device.os)} {device.osVersion}
          </span>
        </HeaderFact>
        <HeaderFact label="Agent version">
          <span className="ident">{device.agentVersion || 'Unknown'}</span>
        </HeaderFact>
        <HeaderFact label="Restart">
          {device.pendingReboot ? <PendingRebootBadge /> : <span className="text-muted-foreground">Not needed</span>}
        </HeaderFact>
        {device.defaultGateway || device.wifiSsid !== undefined ? (
          <HeaderFact label="Network">
            {[
              device.wifiSsid === null || device.wifiSsid === undefined
                ? null
                : device.wifiSsid === ''
                  ? 'Wi-Fi (name hidden by the OS)'
                  : `Wi-Fi ${device.wifiSsid}`,
              device.defaultGateway ? `gateway ${device.defaultGateway}` : null,
            ]
              .filter(Boolean)
              .join(' · ') || (
              // Neither Wi-Fi nor a gateway was reported: older agents send nothing, which is not proof of a cable.
              <span className="text-muted-foreground">Not reported by the agent</span>
            )}
          </HeaderFact>
        ) : null}
        <HeaderFact label="Tags">
          {device.tags.length > 0 ? (
            <TagList tags={device.tags} />
          ) : (
            <span className="text-muted-foreground">None</span>
          )}
        </HeaderFact>
      </dl>

      {device.isolatedAt ? (
        <InlineAlert tone="danger" title="Isolated from the network" className="mb-4">
          Since {formatDateTime(device.isolatedAt)}
          {device.isolatedBy ? ` by ${device.isolatedBy}` : ''}
          {device.isolationReason ? `: ${device.isolationReason}` : ''}. The device can only reach DranzoRMM, remote
          desktop, DNS and DHCP until it is released.
        </InlineAlert>
      ) : null}
      <AgentCard device={device} />

      {/* Remote sessions belong to the page, not to one tab: switching tabs keeps them, leaving the page ends them. */}
      <RemoteSessionsProvider deviceId={device.id} online={device.isOnline}>
        <Tabs
          className="min-w-0"
          value={active}
          onValueChange={(tab) => {
            setParams(tab === tabs[0]?.id ? {} : { tab }, { replace: true });
          }}
        >
          <TabsList variant="line" className="mb-4 w-full justify-start overflow-x-auto overflow-y-hidden border-b">
            {tabs.map((t) => (
              <TabsTrigger key={t.id} value={t.id} className="flex-none px-3">
                {t.id === 'danger' ? <TriangleAlert aria-hidden="true" /> : null}
                {t.label}
              </TabsTrigger>
            ))}
          </TabsList>
          {tabs.map((t) => (
            <TabsContent key={t.id} value={t.id}>
              <t.component
                // Remount the edit form when the saved values change so it never shows stale drafts.
                key={`${device.id}:${device.siteId}:${device.groupId ?? ''}:${device.tags.join('\u0001')}`}
                device={device}
              />
            </TabsContent>
          ))}
        </Tabs>
      </RemoteSessionsProvider>
    </>
  );
}
