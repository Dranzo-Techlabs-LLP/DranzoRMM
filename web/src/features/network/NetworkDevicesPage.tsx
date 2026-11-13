import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Ban, CircleCheck, Network, Radar, Router, Search, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { RelativeTime } from '@/components/relative-time';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useOrgFilter } from '@/app/org-filter';
import { useSites } from '@/features/tenants/queries';
import {
  networkApi,
  networkKeys,
  type NetworkDevice,
  type NetworkDeviceFilter,
  type NetworkDeviceStatus,
} from '@/lib/api/network';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { deviceKind, displayName, STATUS_LABEL, STATUS_TONE } from './model';

const PAGE_SIZE = 50;

function ScanButton({ organizationId }: { organizationId: string | null }) {
  const sites = useSites(organizationId ?? undefined);
  const [siteId, setSiteId] = useState('');
  const queryClient = useQueryClient();
  const scan = useMutation({
    mutationFn: (id: string) => networkApi.scan({ siteId: id }),
    onSuccess: (r) => {
      notifySuccess(`${r.hostname} is scanning its network. New devices appear here within a minute.`);
      for (const delay of [8000, 20000, 45000]) {
        setTimeout(() => void queryClient.invalidateQueries({ queryKey: networkKeys.all }), delay);
      }
    },
    onError: notifyError,
  });
  const list = sites.data ?? [];
  const chosen = siteId || list[0]?.id || '';
  return (
    <div className="flex items-center gap-2">
      {list.length > 1 ? (
        <NativeSelect
          size="sm"
          aria-label="Site to scan"
          value={chosen}
          onChange={(e) => {
            setSiteId(e.target.value);
          }}
        >
          {list.map((s) => (
            <NativeSelectOption key={s.id} value={s.id}>
              {s.name}
            </NativeSelectOption>
          ))}
        </NativeSelect>
      ) : null}
      <Button
        size="sm"
        disabled={!chosen || scan.isPending}
        onClick={() => {
          scan.mutate(chosen);
        }}
      >
        <Radar aria-hidden="true" />
        {scan.isPending ? 'Starting…' : 'Scan network'}
      </Button>
    </div>
  );
}

export default function NetworkDevicesPage() {
  useDocumentTitle('Network devices');
  const access = useAccess();
  const canManage = access.has(P.networkManage);
  const queryClient = useQueryClient();
  const { orgId } = useOrgFilter();
  const [status, setStatus] = useState<NetworkDeviceStatus | ''>('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [forgetting, setForgetting] = useState<NetworkDevice | null>(null);

  const filter: NetworkDeviceFilter = {
    organizationId: orgId ?? undefined,
    status: status || undefined,
    search: search.trim() || undefined,
    page,
    pageSize: PAGE_SIZE,
  };
  const devices = useQuery({
    queryKey: networkKeys.devices(filter),
    queryFn: () => networkApi.devices(filter),
    placeholderData: keepPreviousData,
    refetchInterval: 30_000,
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: networkKeys.all });
  const setOne = useMutation({
    mutationFn: ({ d, to }: { d: NetworkDevice; to: NetworkDeviceStatus }) => networkApi.setStatus(d.id, to),
    onSuccess: async (r, { d, to }) => {
      notifySuccess(`${displayName(d)}: ${STATUS_LABEL[to].toLowerCase()} (${r.controller}).`);
      await invalidate();
    },
    onError: notifyError,
  });
  const setMany = useMutation({
    mutationFn: (to: NetworkDeviceStatus) => networkApi.setStatusBulk([...selected], to),
    onSuccess: async (r, to) => {
      notifySuccess(`${String(r.updated)} devices ${STATUS_LABEL[to].toLowerCase()} (${r.controller}).`);
      setSelected(new Set());
      await invalidate();
    },
    onError: notifyError,
  });
  const forget = useMutation({
    mutationFn: (d: NetworkDevice) => networkApi.forget(d.id),
    onSuccess: async () => {
      setForgetting(null);
      await invalidate();
    },
    onError: notifyError,
  });

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  return (
    <>
      <PageHeader
        title="Network devices"
        description="Everything a managed computer has seen on its local network. Approve the devices that belong there and block the rest. Blocking takes effect on the Wi-Fi once a UniFi controller is connected."
        actions={canManage ? <ScanButton organizationId={orgId} /> : null}
      />
      <Panel
        flush
        title={
          devices.data
            ? `${String(devices.data.counts.unknown)} not reviewed · ${String(devices.data.counts.approved)} approved · ${String(devices.data.counts.blocked)} blocked`
            : 'Devices'
        }
        description={
          devices.data?.lastScanAt ? (
            <>
              Last seen in a scan <RelativeTime value={devices.data.lastScanAt} />
            </>
          ) : undefined
        }
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search aria-hidden="true" className="text-muted-foreground absolute top-2 left-2 size-4" />
              <Input
                aria-label="Search by name, IP or MAC"
                placeholder="Name, IP or MAC"
                className="h-8 w-48 pl-8"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(1);
                }}
              />
            </div>
            <NativeSelect
              size="sm"
              aria-label="Status"
              value={status}
              onChange={(e) => {
                setStatus(e.target.value as NetworkDeviceStatus | '');
                setPage(1);
              }}
            >
              <NativeSelectOption value="">Any status</NativeSelectOption>
              <NativeSelectOption value="unknown">Not reviewed</NativeSelectOption>
              <NativeSelectOption value="approved">Approved</NativeSelectOption>
              <NativeSelectOption value="blocked">Blocked</NativeSelectOption>
            </NativeSelect>
          </div>
        }
      >
        {canManage && selected.size > 0 ? (
          <div className="bg-muted/50 flex flex-wrap items-center gap-2 border-b px-4 py-2 text-sm">
            <span>{selected.size} selected</span>
            <Button
              size="sm"
              variant="outline"
              disabled={setMany.isPending}
              onClick={() => {
                setMany.mutate('approved');
              }}
            >
              <CircleCheck aria-hidden="true" />
              Approve
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={setMany.isPending}
              onClick={() => {
                setMany.mutate('blocked');
              }}
            >
              <Ban aria-hidden="true" />
              Block
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setSelected(new Set());
              }}
            >
              Clear
            </Button>
          </div>
        ) : null}
        <QueryView
          query={devices}
          what="network devices"
          isEmpty={(d) => d.total === 0}
          empty={
            <EmptyState icon={Network} title={search || status ? 'No device matches' : 'No scan yet'}>
              {search || status
                ? 'Change the search or status filter.'
                : 'Scan a site: one of its online computers lists every device it can see on the local network.'}
            </EmptyState>
          }
        >
          {(data) => (
            <>
              <Table>
                <TableHeader>
                  <TableRow>
                    {canManage ? (
                      <TableHead className="w-8">
                        <Checkbox
                          aria-label="Select all on this page"
                          checked={data.items.length > 0 && data.items.every((d) => selected.has(d.id))}
                          onCheckedChange={(v) => {
                            setSelected(v === true ? new Set(data.items.map((d) => d.id)) : new Set());
                          }}
                        />
                      </TableHead>
                    ) : null}
                    <TableHead>Device</TableHead>
                    <TableHead>IP</TableHead>
                    <TableHead>MAC</TableHead>
                    <TableHead>Site</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last seen</TableHead>
                    {canManage ? <TableHead className="text-right">Actions</TableHead> : null}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.items.map((d) => (
                    <TableRow key={d.id}>
                      {canManage ? (
                        <TableCell>
                          <Checkbox
                            aria-label={`Select ${displayName(d)}`}
                            checked={selected.has(d.id)}
                            onCheckedChange={() => {
                              toggle(d.id);
                            }}
                          />
                        </TableCell>
                      ) : null}
                      <TableCell>
                        <div className="flex items-center gap-1.5 font-medium">
                          {d.isGateway ? <Router aria-hidden="true" className="text-muted-foreground size-4" /> : null}
                          {d.managedDeviceId ? (
                            <Link to={`/devices/${d.managedDeviceId}`} className="hover:underline">
                              {displayName(d)}
                            </Link>
                          ) : (
                            displayName(d)
                          )}
                        </div>
                        <div className="text-muted-foreground text-xs">{deviceKind(d)}</div>
                      </TableCell>
                      <TableCell className="ident tabular-nums">{d.ip}</TableCell>
                      <TableCell className="ident text-xs">{d.mac}</TableCell>
                      <TableCell>{d.siteName}</TableCell>
                      <TableCell>
                        <StatusPill tone={STATUS_TONE[d.status]}>{STATUS_LABEL[d.status]}</StatusPill>
                        {d.statusChangedBy ? (
                          <div className="text-muted-foreground mt-0.5 text-xs">by {d.statusChangedBy}</div>
                        ) : null}
                      </TableCell>
                      <TableCell>
                        <RelativeTime value={d.lastSeenAt} />
                        {d.seenByHostname ? (
                          <div className="text-muted-foreground text-xs">by {d.seenByHostname}</div>
                        ) : null}
                      </TableCell>
                      {canManage ? (
                        <TableCell className="text-right whitespace-nowrap">
                          {d.status !== 'approved' ? (
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => {
                                setOne.mutate({ d, to: 'approved' });
                              }}
                            >
                              Approve<span className="sr-only"> {displayName(d)}</span>
                            </Button>
                          ) : null}
                          {d.status !== 'blocked' ? (
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => {
                                setOne.mutate({ d, to: 'blocked' });
                              }}
                            >
                              Block<span className="sr-only"> {displayName(d)}</span>
                            </Button>
                          ) : null}
                          <Button
                            size="icon"
                            variant="ghost"
                            aria-label={`Forget ${displayName(d)}`}
                            onClick={() => {
                              setForgetting(d);
                            }}
                          >
                            <Trash2 aria-hidden="true" />
                          </Button>
                        </TableCell>
                      ) : null}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <div className="border-t px-4 py-2">
                <Pagination
                  page={data.page}
                  pageSize={data.pageSize}
                  total={data.total}
                  noun="devices"
                  onPageChange={setPage}
                />
              </div>
            </>
          )}
        </QueryView>
      </Panel>
      <ConfirmDialog
        open={forgetting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setForgetting(null);
          }
        }}
        title={forgetting ? `Forget ${displayName(forgetting)}?` : ''}
        description="It is removed from this list and its approval status is lost. It appears again as not reviewed if a later scan sees it."
        confirmLabel="Forget"
        destructive
        pending={forget.isPending}
        onConfirm={() => {
          if (forgetting) {
            forget.mutate(forgetting);
          }
        }}
      />
    </>
  );
}
