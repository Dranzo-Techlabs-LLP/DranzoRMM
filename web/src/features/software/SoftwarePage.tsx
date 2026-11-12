import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, PackageOpen, PackagePlus, Search, Trash2, Upload } from 'lucide-react';
import { useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { OsIcon } from '@/components/os';
import { EmptyState, ErrorState, LoadingRows, PageHeader, Panel, QueryView } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AP } from '@/features/jobs/permissions';
import {
  packagesApi,
  softwareApi,
  softwareKeys,
  type PackageItem,
  type SoftwareListFilter,
  type SoftwareSummary,
} from '@/lib/api/software';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { formatBytes, formatDateTime } from '@/lib/format';
import { useDebounced, useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import { cn } from '@/lib/utils';
import { DeployPackageDialog } from './DeployPackageDialog';
import { DeploySoftwareDialog } from './DeploySoftwareDialog';
import { describeDetection, sourceLabel } from './software-model';
import { UploadPackageDialog } from './UploadPackageDialog';

const PAGE_SIZE = 50;

export default function SoftwarePage() {
  useDocumentTitle('Software');
  const access = useAccess();
  const [params, setParams] = useSearchParams();
  const view = params.get('view') === 'packages' ? 'packages' : 'inventory';
  const [deploying, setDeploying] = useState(false);

  return (
    <>
      <PageHeader
        title="Software"
        description="What is installed across your devices, and the tools to install or remove software: through each system’s package manager, or with installers you upload."
        actions={
          access.has(AP.softwareDeploy) ? (
            <Button
              onClick={() => {
                setDeploying(true);
              }}
            >
              <Download aria-hidden="true" />
              Deploy software
            </Button>
          ) : undefined
        }
      />
      <Tabs
        value={view}
        onValueChange={(next) => {
          setParams(next === 'inventory' ? {} : { view: next }, { replace: true });
        }}
      >
        <TabsList variant="line" className="mb-4 w-full justify-start border-b">
          <TabsTrigger value="inventory" className="flex-none px-3">
            Installed software
          </TabsTrigger>
          <TabsTrigger value="packages" className="flex-none px-3">
            Packages
          </TabsTrigger>
        </TabsList>
        <TabsContent value="inventory">
          <InventoryPanel />
        </TabsContent>
        <TabsContent value="packages">
          <PackagesPanel />
        </TabsContent>
      </Tabs>
      {deploying ? (
        <DeploySoftwareDialog
          onClose={() => {
            setDeploying(false);
          }}
        />
      ) : null}
    </>
  );
}

function InventoryPanel() {
  const { orgId, organization } = useOrgFilter();
  const [text, setText] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<SoftwareSummary | null>(null);
  const search = useDebounced(text.trim());
  const filter: SoftwareListFilter = {
    organizationId: orgId ?? undefined,
    search: search || undefined,
    page,
    pageSize: PAGE_SIZE,
  };
  const query = useQuery({
    queryKey: softwareKeys.list(filter),
    queryFn: ({ signal }) => softwareApi.list(filter, signal),
    placeholderData: keepPreviousData,
  });

  return (
    <>
      <Panel flush>
        <form
          role="search"
          aria-label="Search installed software"
          className="flex flex-wrap items-end gap-3 border-b px-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
          }}
        >
          <div className="grid min-w-52 flex-1 gap-1">
            <Label htmlFor="software-search" className="text-xs">
              Search
            </Label>
            <div className="relative">
              <Search
                aria-hidden="true"
                className="text-muted-foreground absolute top-1/2 left-2.5 size-4 -translate-y-1/2"
              />
              <Input
                id="software-search"
                type="search"
                className="h-8 pl-8"
                placeholder="Software name"
                value={text}
                onChange={(e) => {
                  setText(e.target.value);
                  setPage(1);
                }}
              />
            </div>
          </div>
          <p className="text-muted-foreground ml-auto self-center text-xs">
            {organization ? `Devices of ${organization.name}.` : 'Devices of all organizations.'} Most widely installed
            first.
          </p>
        </form>
        {query.isPending ? (
          <LoadingRows label="software" rows={8} />
        ) : query.isError ? (
          <ErrorState error={query.error} what="the software inventory" onRetry={() => void query.refetch()} />
        ) : query.data.items.length === 0 ? (
          <EmptyState
            icon={PackageOpen}
            title={search ? 'No software matches this search' : 'No software reported yet'}
          >
            {search
              ? null
              : 'Agents report installed software shortly after they connect and then on a schedule. If devices are online and this stays empty, their agent version may not collect software yet.'}
          </EmptyState>
        ) : (
          <>
            <div className={cn(query.isPlaceholderData && 'opacity-60')} aria-busy={query.isFetching}>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Name</TableHead>
                    <TableHead scope="col" className="hidden md:table-cell">
                      Publisher
                    </TableHead>
                    <TableHead scope="col" className="text-right">
                      Devices
                    </TableHead>
                    <TableHead scope="col" className="text-right">
                      Versions
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {query.data.items.map((s) => (
                    <TableRow key={`${s.name}\u0001${s.publisher ?? ''}`}>
                      <TableHead
                        scope="row"
                        className="text-foreground h-auto max-w-96 py-2 font-medium whitespace-normal"
                      >
                        <button
                          type="button"
                          className="text-link text-left hover:underline"
                          onClick={() => {
                            setSelected(s);
                          }}
                        >
                          {s.name}
                          <span className="sr-only">: show devices</span>
                        </button>
                      </TableHead>
                      <TableCell className="hidden max-w-72 truncate md:table-cell">
                        {s.publisher || <span className="text-muted-foreground">Unknown</span>}
                      </TableCell>
                      <TableCell className="text-right">{s.devices.toLocaleString('en')}</TableCell>
                      <TableCell className="text-right">
                        {s.versions}
                        {s.versions > 1 ? <span className="text-warn ml-1.5 text-xs font-medium">mixed</span> : null}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <Pagination
              page={query.data.page}
              pageSize={query.data.pageSize || PAGE_SIZE}
              total={query.data.total}
              noun="titles"
              onPageChange={setPage}
            />
          </>
        )}
      </Panel>
      {selected ? (
        <SoftwareDevicesDialog
          software={selected}
          onClose={() => {
            setSelected(null);
          }}
        />
      ) : null}
    </>
  );
}

function SoftwareDevicesDialog({ software, onClose }: { software: SoftwareSummary; onClose: () => void }) {
  const access = useAccess();
  const { orgId, organizations } = useOrgFilter();
  const query = useQuery({
    queryKey: softwareKeys.devicesWith(software.name, orgId),
    queryFn: () => softwareApi.devicesWith(software.name, orgId ?? undefined),
  });
  const orgName = (id: string) => organizations.find((o) => o.id === id)?.name ?? '';
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) {
          onClose();
        }
      }}
    >
      <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Devices with {software.name}</DialogTitle>
          <DialogDescription>
            {software.publisher ? `Published by ${software.publisher}. ` : ''}
            One row per installed copy, so a device can appear more than once.
          </DialogDescription>
        </DialogHeader>
        <div className="rounded-md border">
          <QueryView
            query={query}
            what="devices"
            isEmpty={(d) => d.length === 0}
            empty={<EmptyState title="No devices" />}
          >
            {(devices) => (
              <>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead scope="col">Device</TableHead>
                      {orgId ? null : <TableHead scope="col">Organization</TableHead>}
                      <TableHead scope="col">Version</TableHead>
                      <TableHead scope="col">Installed through</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {devices.map((d, i) => (
                      <TableRow key={`${d.deviceId}:${d.version}:${d.source}:${i}`}>
                        <TableHead scope="row" className="ident text-foreground h-auto py-2 font-medium">
                          {access.has(P.devicesRead) ? (
                            <Link to={`/devices/${d.deviceId}?tab=software`} className="text-link hover:underline">
                              {d.hostname}
                            </Link>
                          ) : (
                            d.hostname
                          )}
                        </TableHead>
                        {orgId ? null : <TableCell>{orgName(d.organizationId)}</TableCell>}
                        <TableCell className="ident">{d.version || '–'}</TableCell>
                        <TableCell>{sourceLabel(d.source)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {devices.length >= 2000 ? (
                  <p className="text-muted-foreground border-t px-3 py-2 text-xs">
                    Showing the first 2,000. Choose an organization in the top bar to narrow the list.
                  </p>
                ) : null}
              </>
            )}
          </QueryView>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function PackagesPanel() {
  const access = useAccess();
  const queryClient = useQueryClient();
  const { organizations } = useOrgFilter();
  const canManage = access.has(AP.packagesManage);
  const canDeploy = access.has(AP.softwareDeploy);
  const [uploading, setUploading] = useState(false);
  const [deploying, setDeploying] = useState<PackageItem | null>(null);
  const [deleting, setDeleting] = useState<PackageItem | null>(null);
  const query = useQuery({ queryKey: softwareKeys.packages, queryFn: packagesApi.list });

  const remove = useMutation({
    mutationFn: (pkg: PackageItem) => packagesApi.remove(pkg.id),
    onSuccess: async (_, pkg) => {
      notifySuccess(`Package “${pkg.name}” deleted`);
      setDeleting(null);
      await queryClient.invalidateQueries({ queryKey: softwareKeys.packages });
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
        title="Package library"
        description="Installers you uploaded. Agents verify the SHA-256 shown here before they run a file."
        actions={
          canManage ? (
            <Button
              size="sm"
              onClick={() => {
                setUploading(true);
              }}
            >
              <Upload aria-hidden="true" />
              Upload package
            </Button>
          ) : undefined
        }
      >
        <QueryView
          query={query}
          what="packages"
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyState icon={PackagePlus} title="No packages uploaded">
              Upload an MSI, EXE, PKG, DMG, DEB or RPM installer to deploy software that is not available through a
              package manager.
            </EmptyState>
          }
        >
          {(packages) => (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Package</TableHead>
                  <TableHead scope="col">For</TableHead>
                  <TableHead scope="col" className="text-right">
                    Size
                  </TableHead>
                  <TableHead scope="col" className="hidden lg:table-cell">
                    SHA-256
                  </TableHead>
                  <TableHead scope="col" className="hidden md:table-cell">
                    Scope
                  </TableHead>
                  {canManage || canDeploy ? (
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  ) : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {packages.map((p) => (
                  <TableRow key={p.id}>
                    <TableHead
                      scope="row"
                      className="text-foreground h-auto max-w-80 py-2 font-medium whitespace-normal"
                    >
                      {p.name}
                      {p.version ? (
                        <span className="ident text-muted-foreground ml-2 font-normal">{p.version}</span>
                      ) : null}
                      <span className="text-muted-foreground block text-xs font-normal">
                        <span className="ident break-all">{p.fileName ?? 'File missing'}</span> · added{' '}
                        {formatDateTime(p.createdAt)}
                      </span>
                      <span className="text-muted-foreground block text-xs font-normal">
                        {describeDetection(p.detection)}
                        {(p.uninstallCommand?.length ?? 0) === 0 ? ' · install only' : ''}
                      </span>
                    </TableHead>
                    <TableCell>
                      <span className="inline-flex items-center gap-1.5">
                        <OsIcon os={p.os} className="text-muted-foreground" />
                        {osLabel(p.os)} <span className="ident text-muted-foreground">.{p.type}</span>
                      </span>
                    </TableCell>
                    <TableCell className="text-right">{formatBytes(p.sizeBytes) || '–'}</TableCell>
                    <TableCell className="ident hidden text-xs lg:table-cell" title={p.sha256 ?? undefined}>
                      {p.sha256 ? `${p.sha256.slice(0, 16)}…` : '–'}
                    </TableCell>
                    <TableCell className="hidden md:table-cell">
                      {p.organizationId ? (
                        (organizations.find((o) => o.id === p.organizationId)?.name ?? 'One organization')
                      ) : (
                        <StatusPill tone="info">Shared</StatusPill>
                      )}
                    </TableCell>
                    {canManage || canDeploy ? (
                      <TableCell className="text-right">
                        <span className="inline-flex gap-1.5">
                          {canDeploy ? (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => {
                                setDeploying(p);
                              }}
                            >
                              <Download aria-hidden="true" />
                              Deploy<span className="sr-only"> {p.name}</span>
                            </Button>
                          ) : null}
                          {canManage && (p.organizationId || access.hasPartnerWide(AP.packagesManage)) ? (
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
                          ) : null}
                        </span>
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryView>
      </Panel>
      {uploading ? (
        <UploadPackageDialog
          onClose={() => {
            setUploading(false);
          }}
        />
      ) : null}
      {deploying ? (
        <DeployPackageDialog
          pkg={deploying}
          onClose={() => {
            setDeploying(null);
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
        title={`Delete the package “${deleting?.name ?? ''}”?`}
        description={
          <p>
            It can no longer be deployed. Software it already installed stays on the devices, and past deployment jobs
            stay in the history.
          </p>
        }
        confirmLabel="Delete package"
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
