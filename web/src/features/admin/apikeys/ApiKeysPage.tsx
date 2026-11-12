import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeySquare, Plus, Trash2, UserCog } from 'lucide-react';
import { useState, type SyntheticEvent } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { CopyButton } from '@/components/copy-button';
import { Field } from '@/components/field';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { InlineAlert, StatusPill } from '@/components/status';
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
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { AssignmentsDialog } from '@/features/admin/AssignmentsDialog';
import { describeScope, type ScopeDirectory } from '@/features/admin/scope';
import { useGroups, useOrganizationsQuery, useSites } from '@/features/tenants/queries';
import { errorMessage, isApiError, qk, rolesApi } from '@/lib/api';
import { apiKeyKeys, apiKeysApi, type ApiKey, type ApiKeyCreated } from '@/lib/api/apikeys';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { formatDateTime } from '@/lib/format';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';

const EXPIRY_DAYS = [30, 90, 180, 365, 730];

function keyState(k: ApiKey, now = Date.now()): { label: string; tone: 'ok' | 'idle' | 'danger' } {
  if (k.revokedAt) {
    return { label: 'Revoked', tone: 'danger' };
  }
  if (k.expiresAt && Date.parse(k.expiresAt) <= now) {
    return { label: 'Expired', tone: 'idle' };
  }
  return { label: 'Active', tone: 'ok' };
}

export default function ApiKeysPage() {
  useDocumentTitle('API keys');
  const access = useAccess();
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [assigningId, setAssigningId] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  const keys = useQuery({ queryKey: apiKeyKeys.list, queryFn: apiKeysApi.list });
  const roles = useQuery({
    queryKey: qk.roles,
    queryFn: rolesApi.list,
    enabled: access.has(P.usersRead) || access.has(P.rolesManage),
  });
  const orgs = useOrganizationsQuery(access.has(P.tenantsRead));
  const sites = useSites();
  const groups = useGroups();
  const directory: ScopeDirectory = {
    organizations: orgs.data ?? [],
    sites: sites.data ?? [],
    groups: groups.data ?? [],
  };
  const canAssign = access.hasPartnerWide(P.rolesManage);
  const assigning = keys.data?.find((k) => k.id === assigningId) ?? null;

  const revoke = useMutation({
    mutationFn: (k: ApiKey) => apiKeysApi.revoke(k.id),
    onSuccess: async () => {
      notifySuccess('API key revoked. Calls with it are refused from now on.');
      setRevoking(null);
      await queryClient.invalidateQueries({ queryKey: apiKeyKeys.list });
    },
    onError: notifyError,
  });

  const createButton = (
    <Button
      size="sm"
      onClick={() => {
        setCreating(true);
      }}
    >
      <Plus aria-hidden="true" />
      New API key
    </Button>
  );

  return (
    <>
      <PageHeader
        title="API keys"
        description="Keys let scripts and other systems use the DranzoRMM API. A key can do only what its roles allow, and never what needs a person: remote sessions, user and role changes, releases and settings."
        actions={createButton}
      />
      <Panel flush>
        <QueryView
          query={keys}
          what="API keys"
          isEmpty={(d) => d.length === 0}
          empty={<EmptyState icon={KeySquare} title="No API keys" action={createButton} />}
        >
          {(list) => (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Name</TableHead>
                    <TableHead scope="col">Key starts with</TableHead>
                    <TableHead scope="col">Status</TableHead>
                    <TableHead scope="col">Roles</TableHead>
                    <TableHead scope="col">Last used</TableHead>
                    <TableHead scope="col">Expires</TableHead>
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.map((k) => {
                    const state = keyState(k);
                    return (
                      <TableRow key={k.id}>
                        <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-medium">
                          {k.name}
                        </TableHead>
                        <TableCell className="ident">{k.prefix}</TableCell>
                        <TableCell>
                          <StatusPill tone={state.tone}>{state.label}</StatusPill>
                        </TableCell>
                        <TableCell className="whitespace-normal">
                          {k.assignments.length === 0 ? (
                            <span className="text-muted-foreground">None, so it can do nothing</span>
                          ) : (
                            <ul className="space-y-0.5">
                              {k.assignments.map((a) => (
                                <li key={a.id}>
                                  {a.roleName}{' '}
                                  <span className="text-muted-foreground">
                                    for {describeScope(a.scopeType, a.scopeId, directory)}
                                  </span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </TableCell>
                        <TableCell>
                          <RelativeTime value={k.lastUsedAt} fallback="Never" />
                        </TableCell>
                        <TableCell>
                          <RelativeTime value={k.expiresAt} fallback="Never" />
                        </TableCell>
                        <TableCell className="py-1 text-right">
                          {state.label === 'Active' ? (
                            <div className="flex justify-end gap-1">
                              {canAssign ? (
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  disabled={!roles.data}
                                  onClick={() => {
                                    setAssigningId(k.id);
                                  }}
                                >
                                  <UserCog aria-hidden="true" />
                                  Roles<span className="sr-only"> of {k.name}</span>
                                </Button>
                              ) : null}
                              <Button
                                variant="ghost"
                                size="sm"
                                className="text-destructive hover:text-destructive"
                                onClick={() => {
                                  setRevoking(k);
                                }}
                              >
                                <Trash2 aria-hidden="true" />
                                Revoke<span className="sr-only"> {k.name}</span>
                              </Button>
                            </div>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </QueryView>
      </Panel>

      <CreateKeyDialog open={creating} onOpenChange={setCreating} />
      <AssignmentsDialog
        subject={
          assigning
            ? { kind: 'apiKey', id: assigning.id, name: assigning.name, assignments: assigning.assignments }
            : null
        }
        roles={roles.data ?? []}
        directory={directory}
        onOpenChange={(open) => {
          if (!open) {
            setAssigningId(null);
          }
        }}
      />
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRevoking(null);
          }
        }}
        title={`Revoke ${revoking?.name ?? 'this key'}?`}
        description={
          <p>
            Every system using this key loses access at once. This cannot be undone. You will be asked for your
            authenticator code.
          </p>
        }
        confirmLabel="Revoke key"
        destructive
        typeToConfirm={revoking?.name}
        pending={revoke.isPending}
        onConfirm={() => {
          if (revoking) {
            revoke.mutate(revoking);
          }
        }}
      />
    </>
  );
}

function CreateKeyDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [days, setDays] = useState(90);
  const [touched, setTouched] = useState(false);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const nameValid = name.trim().length > 0 && name.trim().length <= 120;

  const close = () => {
    setName('');
    setDays(90);
    setTouched(false);
    setCreated(null);
    create.reset();
    onOpenChange(false);
  };
  const create = useMutation({
    mutationFn: () => apiKeysApi.create({ name: name.trim(), expiresInDays: days }),
    onSuccess: async (result) => {
      setCreated(result);
      await queryClient.invalidateQueries({ queryKey: apiKeyKeys.list });
    },
  });
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (nameValid) {
      create.mutate();
    }
  };
  const error =
    create.error && !(isApiError(create.error) && create.error.code === 'step_up_cancelled')
      ? errorMessage(create.error)
      : null;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          close();
        }
      }}
    >
      <DialogContent
        className="sm:max-w-lg"
        onInteractOutside={(e) => {
          if (created) {
            e.preventDefault();
          }
        }}
      >
        {created ? (
          <div className="grid gap-4">
            <DialogHeader>
              <DialogTitle>API key created</DialogTitle>
              <DialogDescription>
                Copy the key now. Only a hash is stored, so it cannot be shown again. It has no permissions until you
                give it a role.
              </DialogDescription>
            </DialogHeader>
            <div className="flex items-start gap-2">
              <code
                aria-label="API key"
                className="ident bg-muted min-w-0 flex-1 rounded-md px-2.5 py-2 break-all select-all"
              >
                {created.key}
              </code>
              <CopyButton value={created.key} label="Copy key" />
            </div>
            <p className="text-muted-foreground text-xs">
              Valid until {formatDateTime(created.expiresAt)}. Send it as{' '}
              <span className="ident">Authorization: Bearer &lt;key&gt;</span>.
            </p>
            <DialogFooter>
              <Button onClick={close}>I have copied it</Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={submit} noValidate className="grid gap-4">
            <DialogHeader>
              <DialogTitle>New API key</DialogTitle>
              <DialogDescription>You will be asked for your authenticator code.</DialogDescription>
            </DialogHeader>
            <div aria-live="assertive" className="empty:hidden">
              {error ? <InlineAlert live={false}>{error}</InlineAlert> : null}
            </div>
            <Field
              label="Name"
              hint="Say what uses it, for example “PSA ticket sync”."
              error={touched && !nameValid ? 'Enter a name of up to 120 characters.' : null}
            >
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
            <Field label="Expires after">
              {(control) => (
                <NativeSelect
                  {...control}
                  className="w-full"
                  value={String(days)}
                  onChange={(e) => {
                    setDays(Number(e.target.value));
                  }}
                >
                  {EXPIRY_DAYS.map((d) => (
                    <NativeSelectOption key={d} value={String(d)}>
                      {d} days
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              )}
            </Field>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={close} disabled={create.isPending}>
                Cancel
              </Button>
              <Button type="submit" disabled={create.isPending}>
                {create.isPending ? 'Creating…' : 'Create key'}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
