import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { MonitorSmartphone, Search, ShieldBan, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { OsIcon } from '@/components/os';
import { EmptyState, ErrorState, LoadingRows, PageHeader, Panel } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { RelativeTime } from '@/components/relative-time';
import { DeviceStatus, PendingRebootBadge, StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useGroups, useSites } from '@/features/tenants/queries';
import { devicesApi, OS_FAMILIES, qk } from '@/lib/api';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { useDebounced, useDocumentTitle } from '@/lib/hooks';
import { osLabel } from '@/lib/os';
import { cn } from '@/lib/utils';
import { Checkbox } from '@/components/ui/checkbox';
import {
  DEVICE_PAGE_SIZE,
  DEVICE_SORTS,
  hasActiveFilters,
  readDeviceFilters,
  toApiFilter,
  writeDeviceFilters,
  type DeviceUrlFilters,
} from './filters';

const ALL_ORGS = '';

export default function DevicesPage() {
  useDocumentTitle('Devices');
  const access = useAccess();
  const { orgId, setOrgId, organizations, available: orgsAvailable } = useOrgFilter();
  const [params, setParams] = useSearchParams();
  const filters = readDeviceFilters(params);

  // Text boxes update the URL (and so the query) after a short pause, not on every keystroke.
  const [searchText, setSearchText] = useState(filters.search);
  const [tagText, setTagText] = useState(filters.tag);
  const debouncedSearch = useDebounced(searchText);
  const debouncedTag = useDebounced(tagText);

  const update = (patch: Partial<DeviceUrlFilters>) => {
    const next = { ...filters, page: 1, ...patch };
    setParams(writeDeviceFilters(next), { replace: true });
  };

  useEffect(() => {
    if (debouncedSearch.trim() !== filters.search || debouncedTag.trim() !== filters.tag) {
      setParams(writeDeviceFilters({ ...filters, page: 1, search: debouncedSearch, tag: debouncedTag }), {
        replace: true,
      });
    }
    // Only react to the debounced text; `filters` is derived from the URL this effect writes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch, debouncedTag]);

  const sites = useSites(orgId ?? undefined);
  const groups = useGroups(orgId ?? undefined);
  const siteOptions = sites.data ?? [];
  const groupOptions = (groups.data ?? []).filter((g) => !filters.siteId || g.siteId === filters.siteId);
  const orgName = new Map(organizations.map((o) => [o.id, o.name]));
  const siteName = new Map(siteOptions.map((s) => [s.id, s.name]));

  const apiFilter = toApiFilter(filters, orgId);
  const query = useQuery({
    queryKey: qk.deviceList(apiFilter),
    queryFn: ({ signal }) => devicesApi.list(apiFilter, signal),
    placeholderData: keepPreviousData,
    // Safety net when live updates are not connected.
    refetchInterval: 60_000,
  });

  const filtered = hasActiveFilters(filters) || orgId !== null;
  const clear = () => {
    setSearchText('');
    setTagText('');
    setParams(new URLSearchParams(), { replace: true });
  };

  return (
    <>
      <PageHeader
        title="Devices"
        description="Computers with the agent installed. Status updates as devices connect and disconnect."
      />

      <Panel flush>
        <form
          role="search"
          aria-label="Filter devices"
          className="flex flex-wrap items-end gap-x-3 gap-y-2 border-b px-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
          }}
        >
          <div className="grid min-w-52 flex-1 gap-1">
            <Label htmlFor="device-search" className="text-xs">
              Search
            </Label>
            <div className="relative">
              <Search
                aria-hidden="true"
                className="text-muted-foreground absolute top-1/2 left-2.5 size-4 -translate-y-1/2"
              />
              <Input
                id="device-search"
                type="search"
                className="h-8 pl-8"
                placeholder="Hostname, serial, model, OS or user"
                value={searchText}
                onChange={(e) => {
                  setSearchText(e.target.value);
                }}
              />
            </div>
          </div>
          {orgsAvailable ? (
            <FilterSelect
              id="device-org"
              label="Organization"
              value={orgId ?? ALL_ORGS}
              onChange={(v) => {
                setOrgId(v === ALL_ORGS ? null : v);
                update({ siteId: '', groupId: '' });
              }}
            >
              <NativeSelectOption value={ALL_ORGS}>All organizations</NativeSelectOption>
              {organizations.map((o) => (
                <NativeSelectOption key={o.id} value={o.id}>
                  {o.name}
                </NativeSelectOption>
              ))}
            </FilterSelect>
          ) : null}
          {access.has(P.tenantsRead) ? (
            <>
              <FilterSelect
                id="device-site"
                label="Site"
                value={filters.siteId}
                onChange={(v) => {
                  update({ siteId: v, groupId: '' });
                }}
              >
                <NativeSelectOption value="">All sites</NativeSelectOption>
                {siteOptions.map((s) => (
                  <NativeSelectOption key={s.id} value={s.id}>
                    {orgId ? s.name : `${orgName.get(s.organizationId) ?? 'Unknown'} / ${s.name}`}
                  </NativeSelectOption>
                ))}
              </FilterSelect>
              <FilterSelect
                id="device-group"
                label="Group"
                value={filters.groupId}
                onChange={(v) => {
                  update({ groupId: v });
                }}
              >
                <NativeSelectOption value="">All groups</NativeSelectOption>
                {groupOptions.map((g) => (
                  <NativeSelectOption key={g.id} value={g.id}>
                    {filters.siteId ? g.name : `${siteName.get(g.siteId) ?? 'Unknown'} / ${g.name}`}
                  </NativeSelectOption>
                ))}
              </FilterSelect>
            </>
          ) : null}
          <FilterSelect
            id="device-os"
            label="Operating system"
            value={filters.os}
            onChange={(v) => {
              update({ os: v });
            }}
          >
            <NativeSelectOption value="">Any</NativeSelectOption>
            {OS_FAMILIES.map((os) => (
              <NativeSelectOption key={os} value={os}>
                {osLabel(os)}
              </NativeSelectOption>
            ))}
          </FilterSelect>
          <FilterSelect
            id="device-status"
            label="Status"
            value={filters.status}
            onChange={(v) => {
              update({ status: v as DeviceUrlFilters['status'] });
            }}
          >
            <NativeSelectOption value="">Any</NativeSelectOption>
            <NativeSelectOption value="online">Online</NativeSelectOption>
            <NativeSelectOption value="offline">Offline</NativeSelectOption>
          </FilterSelect>
          <div className="grid w-32 gap-1">
            <Label htmlFor="device-tag" className="text-xs">
              Tag
            </Label>
            <Input
              id="device-tag"
              className="h-8"
              placeholder="Exact tag"
              value={tagText}
              maxLength={48}
              onChange={(e) => {
                setTagText(e.target.value);
              }}
            />
          </div>
          <div className="flex h-8 items-center gap-2">
            <Checkbox
              id="device-reboot"
              checked={filters.reboot}
              onCheckedChange={(v) => {
                update({ reboot: v === true });
              }}
            />
            <Label htmlFor="device-reboot" className="font-normal">
              Restart pending
            </Label>
          </div>
          <FilterSelect
            id="device-sort"
            label="Sort by"
            value={filters.sort}
            onChange={(v) => {
              update({ sort: DEVICE_SORTS.find((s) => s.value === v)?.value ?? 'hostname' });
            }}
          >
            {DEVICE_SORTS.map((s) => (
              <NativeSelectOption key={s.value} value={s.value}>
                {s.label}
              </NativeSelectOption>
            ))}
          </FilterSelect>
          {filtered ? (
            <Button type="button" variant="ghost" size="sm" onClick={clear}>
              <X aria-hidden="true" />
              Clear filters
            </Button>
          ) : null}
        </form>

        {query.isPending ? (
          <LoadingRows label="devices" rows={10} />
        ) : query.isError ? (
          <ErrorState error={query.error} what="devices" onRetry={() => void query.refetch()} />
        ) : query.data.total === 0 ? (
          filtered ? (
            <EmptyState
              icon={Search}
              title="No devices match these filters"
              action={
                <Button variant="outline" size="sm" onClick={clear}>
                  Clear filters
                </Button>
              }
            >
              {orgId ? 'The organization filter in the top bar is also applied.' : 'Try a broader search.'}
            </EmptyState>
          ) : (
            <EmptyState
              icon={MonitorSmartphone}
              title="No devices enrolled yet"
              action={
                access.has(P.enrollmentManage) ? (
                  <Button asChild size="sm">
                    <Link to="/enrollment">Create an enrollment token</Link>
                  </Button>
                ) : undefined
              }
            >
              Install the agent on a computer with an enrollment token. It appears here as soon as it connects.
            </EmptyState>
          )
        ) : (
          <>
            <div
              className={cn('overflow-x-auto', query.isPlaceholderData && 'opacity-60')}
              aria-busy={query.isFetching}
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col" className="w-24">
                      Status
                    </TableHead>
                    <TableHead scope="col">Device</TableHead>
                    <TableHead scope="col">Operating system</TableHead>
                    {orgsAvailable && !orgId ? <TableHead scope="col">Organization</TableHead> : null}
                    <TableHead scope="col">Console user</TableHead>
                    <TableHead scope="col">Last seen</TableHead>
                    <TableHead scope="col">Tags</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {query.data.items.map((d) => (
                    <TableRow key={d.id}>
                      <TableCell>
                        <DeviceStatus device={d} className="text-xs" />
                      </TableCell>
                      <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-normal">
                        <div className="flex items-center gap-2">
                          <Link to={`/devices/${d.id}`} className="ident font-medium hover:underline">
                            {d.hostname}
                          </Link>
                          {d.pendingReboot ? <PendingRebootBadge /> : null}
                          {d.isolatedAt ? (
                            <StatusPill tone="danger" icon={ShieldBan}>
                              Isolated
                            </StatusPill>
                          ) : null}
                        </div>
                        {d.model ? <div className="text-muted-foreground text-xs">{d.model}</div> : null}
                      </TableHead>
                      <TableCell>
                        <span className="inline-flex items-center gap-1.5">
                          <OsIcon os={d.os} className="text-muted-foreground" />
                          <span>
                            {d.osName || osLabel(d.os)} {d.osVersion}
                          </span>
                        </span>
                        <span className="text-muted-foreground ml-1.5 text-xs">{d.arch}</span>
                      </TableCell>
                      {orgsAvailable && !orgId ? (
                        <TableCell>
                          {orgName.get(d.organizationId) ?? <span className="text-muted-foreground">Unknown</span>}
                        </TableCell>
                      ) : null}
                      <TableCell>
                        {d.consoleUser ? d.consoleUser : <span className="text-muted-foreground">Nobody</span>}
                      </TableCell>
                      <TableCell>
                        {d.isOnline ? (
                          <span className="text-muted-foreground">Connected now</span>
                        ) : (
                          <RelativeTime value={d.lastSeenAt} />
                        )}
                      </TableCell>
                      <TableCell>
                        <TagList tags={d.tags} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {typeof query.data.online === 'number' ? (
              <p className="text-muted-foreground border-t px-4 py-2 text-xs" aria-live="polite">
                {query.data.online.toLocaleString('en')} of {query.data.total.toLocaleString('en')} matching devices are
                online.
              </p>
            ) : null}
            <Pagination
              page={query.data.page}
              pageSize={query.data.pageSize || DEVICE_PAGE_SIZE}
              total={query.data.total}
              noun="devices"
              onPageChange={(page) => {
                update({ page });
              }}
            />
          </>
        )}
      </Panel>
    </>
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
  onChange: (value: string) => void;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-1">
      <Label htmlFor={id} className="text-xs">
        {label}
      </Label>
      <NativeSelect
        id={id}
        size="sm"
        className="max-w-48"
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

export function TagList({ tags }: { tags: string[] }) {
  if (tags.length === 0) {
    return null;
  }
  const shown = tags.slice(0, 3);
  return (
    <ul aria-label="Tags" className="flex flex-wrap gap-1">
      {shown.map((t) => (
        <li key={t} className="bg-muted rounded-sm px-1.5 py-0.5 text-xs">
          {t}
        </li>
      ))}
      {tags.length > shown.length ? (
        <li className="text-muted-foreground px-1 py-0.5 text-xs" title={tags.slice(3).join(', ')}>
          +{tags.length - shown.length} more
        </li>
      ) : null}
    </ul>
  );
}
