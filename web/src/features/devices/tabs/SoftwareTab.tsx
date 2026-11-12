import { useQuery } from '@tanstack/react-query';
import { Download, PackageOpen, Search } from 'lucide-react';
import { useState } from 'react';
import { EmptyState, ErrorState, LoadingRows, Panel } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { AP } from '@/features/jobs/permissions';
import { DeploySoftwareDialog } from '@/features/software/DeploySoftwareDialog';
import { managerForSource, PACKAGE_ID, sourceLabel } from '@/features/software/software-model';
import { softwareApi, softwareKeys, type DeployAction, type DeviceSoftwareItem } from '@/lib/api/software';
import { useAccess } from '@/lib/auth/session';
import { formatDateTime } from '@/lib/format';
import type { DeviceTabProps } from './registry';

const PAGE_SIZE = 100;

/** Software installed on one device (`GET /devices/{id}/software`), searchable, with install and uninstall. */
export function SoftwareTab({ device }: DeviceTabProps) {
  const access = useAccess();
  const [text, setText] = useState('');
  const [source, setSource] = useState('');
  const [page, setPage] = useState(1);
  const [dialog, setDialog] = useState<{ action: DeployAction; item?: DeviceSoftwareItem } | null>(null);
  const canDeploy = access.has(AP.softwareDeploy) && device.status !== 'revoked';
  // The whole list is loaded once (the server caps it at 5,000) so that searching is instant.
  const query = useQuery({
    queryKey: softwareKeys.device(device.id, ''),
    queryFn: ({ signal }) => softwareApi.forDevice(device.id, undefined, signal),
    refetchInterval: 120_000,
  });

  const all = query.data ?? [];
  const needle = text.trim().toLowerCase();
  const sources = [...new Set(all.map((s) => s.source))].sort();
  const filtered = all.filter(
    (s) =>
      (!source || s.source === source) &&
      (!needle ||
        s.name.toLowerCase().includes(needle) ||
        (s.publisher ?? '').toLowerCase().includes(needle) ||
        (s.packageId ?? '').toLowerCase().includes(needle)),
  );
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pages);
  const rows = filtered.slice((current - 1) * PAGE_SIZE, current * PAGE_SIZE);
  const lastSeen = all.reduce<string | null>(
    (latest, s) => (latest === null || s.seenAt > latest ? s.seenAt : latest),
    null,
  );

  const uninstallable = (item: DeviceSoftwareItem) => {
    const manager = managerForSource(item.source);
    return manager !== null && item.packageId !== null && PACKAGE_ID.test(item.packageId) ? manager : null;
  };

  return (
    <>
      <Panel
        flush
        title="Installed software"
        description={
          query.isSuccess
            ? all.length === 0
              ? undefined
              : `${all.length.toLocaleString('en')} ${all.length === 1 ? 'item' : 'items'}, reported ${formatDateTime(lastSeen)}.`
            : undefined
        }
        actions={
          canDeploy ? (
            <Button
              size="sm"
              onClick={() => {
                setDialog({ action: 'install' });
              }}
            >
              <Download aria-hidden="true" />
              Install software
            </Button>
          ) : undefined
        }
      >
        {all.length > 0 ? (
          <form
            role="search"
            aria-label="Search installed software"
            className="flex flex-wrap items-end gap-3 border-b px-4 py-3"
            onSubmit={(e) => {
              e.preventDefault();
            }}
          >
            <div className="grid min-w-52 flex-1 gap-1">
              <Label htmlFor="device-software-search" className="text-xs">
                Search
              </Label>
              <div className="relative">
                <Search
                  aria-hidden="true"
                  className="text-muted-foreground absolute top-1/2 left-2.5 size-4 -translate-y-1/2"
                />
                <Input
                  id="device-software-search"
                  type="search"
                  className="h-8 pl-8"
                  placeholder="Name, publisher or package id"
                  value={text}
                  onChange={(e) => {
                    setText(e.target.value);
                    setPage(1);
                  }}
                />
              </div>
            </div>
            <div className="grid gap-1">
              <Label htmlFor="device-software-source" className="text-xs">
                Installed through
              </Label>
              <NativeSelect
                id="device-software-source"
                size="sm"
                value={source}
                onChange={(e) => {
                  setSource(e.target.value);
                  setPage(1);
                }}
              >
                <NativeSelectOption value="">Anything</NativeSelectOption>
                {sources.map((s) => (
                  <NativeSelectOption key={s} value={s}>
                    {sourceLabel(s)}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            </div>
            <p className="text-muted-foreground self-center text-xs" role="status" aria-live="polite">
              {filtered.length === all.length
                ? ''
                : `${filtered.length.toLocaleString('en')} ${filtered.length === 1 ? 'match' : 'matches'}`}
            </p>
          </form>
        ) : null}
        {query.isPending ? (
          <LoadingRows label="installed software" rows={8} />
        ) : query.isError ? (
          <ErrorState error={query.error} what="the software on this device" onRetry={() => void query.refetch()} />
        ) : all.length === 0 ? (
          <EmptyState icon={PackageOpen} title="No software reported yet">
            The agent sends its software list shortly after it connects and then on a schedule. If the device is online
            and this stays empty, its agent version may not collect software yet.
          </EmptyState>
        ) : rows.length === 0 ? (
          <EmptyState icon={PackageOpen} title="Nothing matches this search" />
        ) : (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Name</TableHead>
                  <TableHead scope="col">Version</TableHead>
                  <TableHead scope="col" className="hidden lg:table-cell">
                    Publisher
                  </TableHead>
                  <TableHead scope="col">Installed through</TableHead>
                  <TableHead scope="col" className="hidden xl:table-cell">
                    Installed
                  </TableHead>
                  {canDeploy ? (
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  ) : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((s, i) => (
                  <TableRow key={`${s.source}:${s.packageId ?? s.name}:${s.version}:${i}`}>
                    <TableHead
                      scope="row"
                      className="text-foreground h-auto max-w-96 py-2 font-medium whitespace-normal"
                    >
                      {s.name}
                      {s.packageId && s.packageId !== s.name ? (
                        <span className="ident text-muted-foreground block text-xs font-normal break-all">
                          {s.packageId}
                        </span>
                      ) : null}
                    </TableHead>
                    <TableCell className="ident">
                      {s.version || <span className="text-muted-foreground">–</span>}
                    </TableCell>
                    <TableCell className="hidden max-w-64 truncate lg:table-cell">{s.publisher}</TableCell>
                    <TableCell>{sourceLabel(s.source)}</TableCell>
                    <TableCell className="hidden xl:table-cell">
                      {s.installDate ? (
                        formatDateTime(s.installDate)
                      ) : (
                        <span className="text-muted-foreground">Unknown</span>
                      )}
                    </TableCell>
                    {canDeploy ? (
                      <TableCell className="text-right">
                        {uninstallable(s) ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setDialog({ action: 'uninstall', item: s });
                            }}
                          >
                            Uninstall<span className="sr-only"> {s.name}</span>
                          </Button>
                        ) : null}
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            {filtered.length > PAGE_SIZE ? (
              <Pagination
                page={current}
                pageSize={PAGE_SIZE}
                total={filtered.length}
                noun="items"
                onPageChange={setPage}
              />
            ) : null}
          </>
        )}
      </Panel>
      {canDeploy && all.length > 0 ? (
        <p className="text-muted-foreground mt-2 text-xs">
          “Uninstall” is offered for software a package manager installed (winget, Homebrew, apt, dnf). Other software
          can be removed with an uploaded package that has an uninstall command, or with a script.
        </p>
      ) : null}
      {dialog ? (
        <DeploySoftwareDialog
          device={{ id: device.id, hostname: device.hostname, os: device.os }}
          initialAction={dialog.action}
          initialPackages={
            dialog.item
              ? (() => {
                  const manager = uninstallable(dialog.item);
                  return manager && dialog.item.packageId ? { [manager]: dialog.item.packageId } : undefined;
                })()
              : undefined
          }
          onClose={() => {
            setDialog(null);
          }}
        />
      ) : null}
    </>
  );
}
