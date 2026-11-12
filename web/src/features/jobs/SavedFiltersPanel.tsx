import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Filter, Plus, Trash2 } from 'lucide-react';
import { useState, type SyntheticEvent } from 'react';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Field } from '@/components/field';
import { EmptyState, Panel, QueryView } from '@/components/page';
import { InlineAlert } from '@/components/status';
import { TargetPicker } from '@/components/target-picker/TargetPicker';
import { TargetPreviewPanel } from '@/components/target-picker/TargetPreview';
import {
  describeFilter,
  emptyTarget,
  toFilterSpec,
  toTargetRequest,
  type TargetDraft,
} from '@/components/target-picker/target';
import { useTargetPreview } from '@/components/target-picker/use-target-preview';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useGroups, useSites } from '@/features/tenants/queries';
import { errorMessage } from '@/lib/api';
import { jobKeys, savedFiltersApi, type SavedFilter } from '@/lib/api/jobs';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { notifyError, notifySuccess } from '@/lib/notify';
import { AP } from './permissions';

/** Saved device filters: reusable targets for scripts, deployments and scans. */
export function SavedFiltersPanel() {
  const access = useAccess();
  const queryClient = useQueryClient();
  const { organizations } = useOrgFilter();
  const sites = useSites();
  const groups = useGroups();
  const canManage = access.has(P.devicesManage);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<SavedFilter | null>(null);
  const query = useQuery({ queryKey: jobKeys.savedFilters, queryFn: savedFiltersApi.list });
  const names = { organizations, sites: sites.data, groups: groups.data };

  const remove = useMutation({
    mutationFn: (filter: SavedFilter) => savedFiltersApi.remove(filter.id),
    onSuccess: async (_, filter) => {
      notifySuccess(`Filter “${filter.name}” deleted`);
      setDeleting(null);
      await queryClient.invalidateQueries({ queryKey: jobKeys.savedFilters });
    },
    onError: notifyError,
  });

  return (
    <>
      <Panel
        flush
        title="Saved filters"
        description="A saved filter is matched again every time it is used, so it always covers the devices that fit at that moment."
        actions={
          canManage ? (
            <Button
              size="sm"
              onClick={() => {
                setCreating(true);
              }}
            >
              <Plus aria-hidden="true" />
              New filter
            </Button>
          ) : undefined
        }
      >
        <QueryView
          query={query}
          what="saved filters"
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyState icon={Filter} title="No saved filters">
              Save a set of criteria, for example “Windows laptops with the tag finance”, and reuse it as the target of
              a script or deployment.
            </EmptyState>
          }
        >
          {(filters) => (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Name</TableHead>
                  <TableHead scope="col">Organization</TableHead>
                  <TableHead scope="col">Matches</TableHead>
                  {canManage ? (
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  ) : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {filters.map((f) => (
                  <TableRow key={f.id}>
                    <TableHead scope="row" className="text-foreground h-auto py-2 font-medium">
                      {f.name}
                    </TableHead>
                    <TableCell>
                      {f.organizationId ? (
                        (organizations.find((o) => o.id === f.organizationId)?.name ?? 'One organization')
                      ) : (
                        <span className="text-muted-foreground">All organizations</span>
                      )}
                    </TableCell>
                    <TableCell className="whitespace-normal">{describeFilter(f.filter, names)}</TableCell>
                    {canManage ? (
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setDeleting(f);
                          }}
                        >
                          <Trash2 aria-hidden="true" />
                          Delete<span className="sr-only"> filter {f.name}</span>
                        </Button>
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryView>
      </Panel>
      {creating ? (
        <NewFilterDialog
          onClose={() => {
            setCreating(false);
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
        title={`Delete the filter “${deleting?.name ?? ''}”?`}
        description={
          <p>Schedules that were created from this filter keep their own copy of the criteria and continue to run.</p>
        }
        confirmLabel="Delete filter"
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

function NewFilterDialog({ onClose }: { onClose: () => void }) {
  const access = useAccess();
  const queryClient = useQueryClient();
  const { orgId } = useOrgFilter();
  const [name, setName] = useState('');
  const [touched, setTouched] = useState(false);
  const [target, setTarget] = useState<TargetDraft>(() => emptyTarget({ mode: 'filter', organizationId: orgId ?? '' }));
  const preview = useTargetPreview(access.has(AP.scriptsRun) ? toTargetRequest(target) : null);
  const nameValid = name.trim().length > 0 && name.trim().length <= 120;
  const orgMissing = !target.organizationId && !access.hasPartnerWide(P.devicesManage);

  const create = useMutation({
    mutationFn: () =>
      savedFiltersApi.create({
        name: name.trim(),
        organizationId: target.organizationId || undefined,
        filter: toFilterSpec(target.filter, target.organizationId),
      }),
    onSuccess: async () => {
      notifySuccess(`Filter “${name.trim()}” saved`);
      await queryClient.invalidateQueries({ queryKey: jobKeys.savedFilters });
      onClose();
    },
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (nameValid && !orgMissing && !create.isPending) {
      create.mutate();
    }
  };

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
        <form onSubmit={submit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>New saved filter</DialogTitle>
            <DialogDescription>
              Describe which devices it should match. Leave a field empty to accept any value.
            </DialogDescription>
          </DialogHeader>
          <div aria-live="assertive" className="empty:hidden">
            {create.error ? <InlineAlert live={false}>{errorMessage(create.error)}</InlineAlert> : null}
          </div>
          <Field label="Name" error={touched && !nameValid ? 'Enter a name of up to 120 characters.' : null}>
            {(control) => (
              <Input
                {...control}
                value={name}
                maxLength={120}
                autoComplete="off"
                autoFocus
                onChange={(e) => {
                  setName(e.target.value);
                }}
              />
            )}
          </Field>
          <TargetPicker
            value={target}
            onChange={setTarget}
            modes={['filter']}
            allowSaveFilter={false}
            legend="Criteria"
          />
          {touched && orgMissing ? (
            <p role="alert" className="text-danger text-xs font-medium">
              Choose an organization. A filter across all organizations needs a partner-wide role.
            </p>
          ) : null}
          {access.has(AP.scriptsRun) ? (
            <TargetPreviewPanel state={preview} problem={null} stepUpNotice={false} />
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={create.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? 'Saving…' : 'Save filter'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
