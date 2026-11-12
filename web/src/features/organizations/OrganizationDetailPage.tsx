import { useMutation, useQueryClient } from '@tanstack/react-query';
import { FolderTree, MapPin, MoreHorizontal, Pencil, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { EmptyState, ErrorState, LoadingRows, PageHeader, Panel, QueryView } from '@/components/page';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useGroups, useSites, useOrganizationsQuery } from '@/features/tenants/queries';
import {
  ApiError,
  groupsApi,
  qk,
  sitesApi,
  UPDATE_RINGS,
  type DeviceGroup,
  type Id,
  type Organization,
  type Site,
  type UpdateRing,
} from '@/lib/api';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { CONSENT, RING } from './consent';
import { DeleteOrganizationDialog } from './DeleteOrganizationDialog';
import { NameDialog, type NameDialogValue } from './NameDialog';
import { OrganizationFormDialog } from './OrganizationFormDialog';

type Editing =
  | { kind: 'site-create' }
  | { kind: 'site-rename'; site: Site }
  | { kind: 'group-create'; site: Site }
  | { kind: 'group-rename'; group: DeviceGroup };

type Removing = { kind: 'site'; site: Site } | { kind: 'group'; group: DeviceGroup };

export default function OrganizationDetailPage() {
  const { organizationId = '' } = useParams();
  const orgs = useOrganizationsQuery();
  const organization = orgs.data?.find((o) => o.id === organizationId);
  useDocumentTitle(organization?.name ?? 'Organization');

  if (orgs.isPending) {
    return <LoadingRows label="organization" />;
  }
  if (orgs.isError) {
    return <ErrorState error={orgs.error} what="this organization" onRetry={() => void orgs.refetch()} />;
  }
  if (!organization) {
    return (
      <ErrorState
        error={new ApiError(404, 'not_found', 'It may have been deleted, or you may not have access to it.')}
        what="this organization"
      />
    );
  }
  return <OrganizationDetail organization={organization} />;
}

function OrganizationDetail({ organization }: { organization: Organization }) {
  const access = useAccess();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { setOrgId } = useOrgFilter();
  const sites = useSites(organization.id);
  const groups = useGroups(organization.id);
  const [editingOrg, setEditingOrg] = useState(false);
  const [deletingOrg, setDeletingOrg] = useState(false);
  const [editing, setEditing] = useState<Editing | null>(null);
  const [removing, setRemoving] = useState<Removing | null>(null);

  const canManage = access.has(P.tenantsManage);
  const canDelete = access.hasPartnerWide(P.tenantsManage);

  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.sitesAll }),
      queryClient.invalidateQueries({ queryKey: qk.groupsAll }),
    ]);

  const save = useMutation({
    mutationFn: async ({ target, value }: { target: Editing; value: NameDialogValue }) => {
      switch (target.kind) {
        case 'site-create':
          await sitesApi.create(organization.id, value.name);
          return 'Site added';
        case 'site-rename':
          await sitesApi.rename(target.site.id, value.name);
          return 'Site renamed';
        case 'group-create':
          await groupsApi.create(target.site.id, value.name, value.updateRing);
          return 'Group added';
        case 'group-rename':
          await groupsApi.update(target.group.id, { name: value.name, updateRing: value.updateRing });
          return 'Group saved';
      }
    },
    onSuccess: async (message) => {
      notifySuccess(message);
      setEditing(null);
      await refresh();
    },
  });

  const setRing = useMutation({
    mutationFn: ({ id, updateRing }: { id: Id; updateRing: UpdateRing }) => groupsApi.update(id, { updateRing }),
    onSuccess: async () => {
      notifySuccess('Update ring changed');
      await refresh();
    },
    onError: notifyError,
  });

  const remove = useMutation({
    mutationFn: async (target: Removing) => {
      if (target.kind === 'site') {
        await sitesApi.remove(target.site.id);
        return 'Site deleted';
      }
      await groupsApi.remove(target.group.id);
      return 'Group deleted';
    },
    onSuccess: async (message) => {
      notifySuccess(message);
      setRemoving(null);
      await Promise.all([
        refresh(),
        queryClient.invalidateQueries({ queryKey: qk.tokensAll }),
        queryClient.invalidateQueries({ queryKey: qk.devices }),
      ]);
    },
    onError: notifyError,
  });

  const openEditing = (next: Editing) => {
    save.reset();
    setEditing(next);
  };

  const addSiteButton = canManage ? (
    <Button
      size="sm"
      variant="outline"
      onClick={() => {
        openEditing({ kind: 'site-create' });
      }}
    >
      <Plus aria-hidden="true" />
      Add site
    </Button>
  ) : null;

  const dialog = editing ? dialogProps(editing) : null;

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Organizations', to: '/organizations' }, { label: organization.name }]}
        title={organization.name}
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <Link
                to="/devices"
                onClick={() => {
                  setOrgId(organization.id);
                }}
              >
                View devices
              </Link>
            </Button>
            {canManage ? (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setEditingOrg(true);
                }}
              >
                <Pencil aria-hidden="true" />
                Edit
              </Button>
            ) : null}
            {canDelete ? (
              <Button
                variant="outline"
                size="sm"
                className="text-destructive hover:text-destructive"
                onClick={() => {
                  setDeletingOrg(true);
                }}
              >
                <Trash2 aria-hidden="true" />
                Delete
              </Button>
            ) : null}
          </>
        }
      />

      <div className="grid gap-4">
        <Panel title="Settings">
          <dl className="grid gap-x-8 gap-y-3 sm:grid-cols-2 xl:grid-cols-4">
            <div>
              <dt className="text-muted-foreground text-xs">Devices</dt>
              <dd>
                {organization.deviceCount} enrolled, {organization.onlineCount} online
              </dd>
            </div>
            <div>
              <dt className="text-muted-foreground text-xs">Time zone</dt>
              <dd>{organization.timeZone.replaceAll('_', ' ')}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground text-xs">Remote sessions</dt>
              <dd>{CONSENT[organization.consentMode].label}</dd>
              <dd className="text-muted-foreground text-xs">{CONSENT[organization.consentMode].explanation}</dd>
            </div>
            <div>
              <dt className="text-muted-foreground text-xs">PowerShell scripts</dt>
              <dd>{organization.requireSignedPowerShell ? 'Signed scripts only' : 'Any script'}</dd>
            </div>
          </dl>
        </Panel>

        <Panel
          title="Sites and device groups"
          description="A site is a location such as an office. Groups sort a site's devices, for example by department."
          actions={addSiteButton}
          flush
        >
          <QueryView
            query={sites}
            what="sites"
            isEmpty={(d) => d.length === 0}
            empty={
              <EmptyState icon={MapPin} title="No sites yet" action={addSiteButton}>
                Add a site before creating an enrollment token: every device is enrolled into a site.
              </EmptyState>
            }
          >
            {(siteList) => (
              <ul className="divide-y">
                {siteList.map((site) => {
                  const siteGroups = (groups.data ?? []).filter((g) => g.siteId === site.id);
                  return (
                    <li key={site.id} className="px-4 py-3">
                      <div className="flex items-center justify-between gap-3">
                        <h3 className="flex min-w-0 items-center gap-2 font-semibold">
                          <MapPin aria-hidden="true" className="text-muted-foreground size-4 shrink-0" />
                          <span className="truncate">{site.name}</span>
                        </h3>
                        {canManage ? (
                          <div className="flex shrink-0 items-center gap-1">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                openEditing({ kind: 'group-create', site });
                              }}
                            >
                              <Plus aria-hidden="true" />
                              Add group
                            </Button>
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon-sm" aria-label={`Actions for site ${site.name}`}>
                                  <MoreHorizontal aria-hidden="true" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                <DropdownMenuItem
                                  onSelect={() => {
                                    openEditing({ kind: 'site-rename', site });
                                  }}
                                >
                                  <Pencil aria-hidden="true" />
                                  Rename
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                  variant="destructive"
                                  onSelect={() => {
                                    setRemoving({ kind: 'site', site });
                                  }}
                                >
                                  <Trash2 aria-hidden="true" />
                                  Delete
                                </DropdownMenuItem>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </div>
                        ) : null}
                      </div>
                      {groups.isPending ? (
                        <LoadingRows label="groups" rows={1} />
                      ) : groups.isError ? (
                        <ErrorState error={groups.error} what="groups" onRetry={() => void groups.refetch()} />
                      ) : siteGroups.length === 0 ? (
                        <p className="text-muted-foreground mt-1 pl-6 text-xs">
                          <FolderTree aria-hidden="true" className="mr-1 inline size-3" />
                          No groups. Devices at this site are ungrouped.
                        </p>
                      ) : (
                        <div className="mt-2 ml-6 overflow-hidden rounded-md border">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead scope="col">Group</TableHead>
                                <TableHead scope="col" className="w-56">
                                  Agent update ring
                                </TableHead>
                                {canManage ? (
                                  <TableHead scope="col" className="w-10">
                                    <span className="sr-only">Actions</span>
                                  </TableHead>
                                ) : null}
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {siteGroups.map((g) => (
                                <TableRow key={g.id}>
                                  <TableHead scope="row" className="text-foreground h-auto py-1.5 text-sm font-medium">
                                    {g.name}
                                  </TableHead>
                                  <TableCell className="py-1">
                                    {canManage ? (
                                      <NativeSelect
                                        size="sm"
                                        aria-label={`Update ring for ${g.name}`}
                                        value={g.updateRing}
                                        disabled={setRing.isPending}
                                        onChange={(e) => {
                                          setRing.mutate({ id: g.id, updateRing: e.target.value as UpdateRing });
                                        }}
                                      >
                                        {UPDATE_RINGS.map((r) => (
                                          <NativeSelectOption key={r} value={r}>
                                            {RING[r].label}
                                          </NativeSelectOption>
                                        ))}
                                      </NativeSelect>
                                    ) : (
                                      RING[g.updateRing].label
                                    )}
                                  </TableCell>
                                  {canManage ? (
                                    <TableCell className="py-1 text-right">
                                      <DropdownMenu>
                                        <DropdownMenuTrigger asChild>
                                          <Button
                                            variant="ghost"
                                            size="icon-sm"
                                            aria-label={`Actions for group ${g.name}`}
                                          >
                                            <MoreHorizontal aria-hidden="true" />
                                          </Button>
                                        </DropdownMenuTrigger>
                                        <DropdownMenuContent align="end">
                                          <DropdownMenuItem
                                            onSelect={() => {
                                              openEditing({ kind: 'group-rename', group: g });
                                            }}
                                          >
                                            <Pencil aria-hidden="true" />
                                            Rename
                                          </DropdownMenuItem>
                                          <DropdownMenuItem
                                            variant="destructive"
                                            onSelect={() => {
                                              setRemoving({ kind: 'group', group: g });
                                            }}
                                          >
                                            <Trash2 aria-hidden="true" />
                                            Delete
                                          </DropdownMenuItem>
                                        </DropdownMenuContent>
                                      </DropdownMenu>
                                    </TableCell>
                                  ) : null}
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </QueryView>
        </Panel>
      </div>

      <NameDialog
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setEditing(null);
          }
        }}
        title={dialog?.title ?? ''}
        description={dialog?.description}
        submitLabel={dialog?.submitLabel ?? 'Save'}
        initialName={dialog?.initialName}
        initialRing={dialog?.initialRing}
        pending={save.isPending}
        error={save.error}
        onSubmit={(value) => {
          if (editing) {
            save.mutate({ target: editing, value });
          }
        }}
      />

      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRemoving(null);
          }
        }}
        title={
          removing?.kind === 'site'
            ? `Delete site ${removing.site.name}?`
            : `Delete group ${removing?.group.name ?? ''}?`
        }
        description={
          removing?.kind === 'site' ? (
            <p>
              The site's groups and enrollment tokens are deleted with it. A site that still has devices cannot be
              deleted; move or remove them first.
            </p>
          ) : (
            <p>Devices in this group stay enrolled at their site and become ungrouped.</p>
          )
        }
        confirmLabel={removing?.kind === 'site' ? 'Delete site' : 'Delete group'}
        destructive
        pending={remove.isPending}
        onConfirm={() => {
          if (removing) {
            remove.mutate(removing);
          }
        }}
      />

      <OrganizationFormDialog open={editingOrg} onOpenChange={setEditingOrg} organization={organization} />
      <DeleteOrganizationDialog
        organization={deletingOrg ? organization : null}
        onOpenChange={setDeletingOrg}
        onDeleted={() => void navigate('/organizations', { replace: true })}
      />
    </>
  );
}

function dialogProps(editing: Editing): {
  title: string;
  description?: string;
  submitLabel: string;
  initialName?: string;
  initialRing?: UpdateRing;
} {
  switch (editing.kind) {
    case 'site-create':
      return { title: 'Add site', description: 'For example an office or a branch.', submitLabel: 'Add site' };
    case 'site-rename':
      return { title: `Rename ${editing.site.name}`, submitLabel: 'Save name', initialName: editing.site.name };
    case 'group-create':
      return {
        title: `Add group to ${editing.site.name}`,
        description: 'For example a department, or a set of pilot machines.',
        submitLabel: 'Add group',
        initialRing: 'all',
      };
    case 'group-rename':
      return {
        title: `Edit ${editing.group.name}`,
        submitLabel: 'Save group',
        initialName: editing.group.name,
        initialRing: editing.group.updateRing,
      };
  }
}
