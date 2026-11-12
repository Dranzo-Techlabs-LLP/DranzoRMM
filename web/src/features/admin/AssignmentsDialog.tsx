import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Trash2 } from 'lucide-react';
import { useState, type SyntheticEvent } from 'react';
import { Field } from '@/components/field';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { NativeSelect, NativeSelectOptGroup, NativeSelectOption } from '@/components/ui/native-select';
import {
  errorMessage,
  isApiError,
  qk,
  rolesApi,
  SCOPE_TYPES,
  type Id,
  type Role,
  type RoleAssignment,
  type ScopeType,
} from '@/lib/api';
import { notifyError, notifySuccess } from '@/lib/notify';
import { describeScope, SCOPE_TYPE_LABEL, type ScopeDirectory } from './scope';

/** Who receives the roles: a user or an API key. */
export interface AssignmentSubject {
  kind: 'user' | 'apiKey';
  id: Id;
  name: string;
  assignments: RoleAssignment[];
}

/** Role assignments of one user or API key: remove existing ones, add role + scope. All changes need step-up. */
export function AssignmentsDialog({
  subject,
  roles,
  directory,
  onOpenChange,
  onCloseAutoFocus,
}: {
  subject: AssignmentSubject | null;
  roles: Role[];
  directory: ScopeDirectory;
  onOpenChange: (open: boolean) => void;
  onCloseAutoFocus?: (event: Event) => void;
}) {
  return (
    <Dialog open={subject !== null} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-2xl" onCloseAutoFocus={onCloseAutoFocus}>
        {subject ? (
          <Assignments
            user={subject}
            roles={roles}
            directory={directory}
            onClose={() => {
              onOpenChange(false);
            }}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function Assignments({
  user,
  roles,
  directory,
  onClose,
}: {
  user: AssignmentSubject;
  roles: Role[];
  directory: ScopeDirectory;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const isKey = user.kind === 'apiKey';
  const [roleId, setRoleId] = useState<Id>(roles[0]?.id ?? '');
  const [scopeType, setScopeType] = useState<ScopeType>('Partner');
  const [scopeId, setScopeId] = useState<Id>('');
  const [touched, setTouched] = useState(false);

  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.users }),
      queryClient.invalidateQueries({ queryKey: qk.me }),
      queryClient.invalidateQueries({ queryKey: ['api-keys'] }),
    ]);

  const assign = useMutation({
    mutationFn: () =>
      rolesApi.assign({
        ...(isKey ? { apiKeyId: user.id } : { userId: user.id }),
        roleId,
        scopeType,
        scopeId: scopeType === 'Partner' ? null : scopeId,
      }),
    onSuccess: async () => {
      notifySuccess('Role assigned');
      setTouched(false);
      await refresh();
    },
  });

  const unassign = useMutation({
    mutationFn: (assignmentId: Id) => rolesApi.unassign(assignmentId),
    onSuccess: async () => {
      notifySuccess('Role removed');
      await refresh();
    },
    onError: notifyError,
  });

  const orgName = (id: Id) => directory.organizations.find((o) => o.id === id)?.name ?? 'Unknown organization';
  const siteName = (id: Id) => directory.sites.find((s) => s.id === id)?.name ?? 'Unknown site';
  const needsTarget = scopeType !== 'Partner';
  const targetMissing = needsTarget && !scopeId;
  const duplicate = user.assignments.some(
    (a) => a.roleId === roleId && a.scopeType === scopeType && (a.scopeId ?? '') === (needsTarget ? scopeId : ''),
  );

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!roleId || targetMissing || duplicate) {
      return;
    }
    assign.mutate();
  };

  const assignError =
    assign.error && !(isApiError(assign.error) && assign.error.code === 'step_up_cancelled')
      ? errorMessage(assign.error)
      : null;

  return (
    <div className="grid gap-5">
      <DialogHeader>
        <DialogTitle>Roles for {user.name}</DialogTitle>
        <DialogDescription>
          A role gives its permissions inside one scope. Changing roles asks for your authenticator code.
          {isKey
            ? ' Roles with permissions that need a person (remote sessions, user, role, release and settings changes, revoking devices) cannot be given to an API key; the server refuses them.'
            : ''}
        </DialogDescription>
      </DialogHeader>

      <section aria-label="Current roles">
        {user.assignments.length === 0 ? (
          <p className="text-muted-foreground rounded-md border border-dashed px-3 py-4 text-center">
            {isKey
              ? 'No roles yet. This key can do nothing.'
              : 'No roles yet. This user can sign in but cannot see anything.'}
          </p>
        ) : (
          <ul className="divide-y rounded-md border">
            {user.assignments.map((a) => (
              <li key={a.id} className="flex items-center justify-between gap-3 px-3 py-2">
                <p className="min-w-0">
                  <span className="font-medium">{a.roleName}</span>{' '}
                  <span className="text-muted-foreground">for {describeScope(a.scopeType, a.scopeId, directory)}</span>
                </p>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-destructive hover:text-destructive shrink-0"
                  disabled={unassign.isPending}
                  onClick={() => {
                    unassign.mutate(a.id);
                  }}
                >
                  <Trash2 aria-hidden="true" />
                  Remove<span className="sr-only"> {a.roleName}</span>
                </Button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <form onSubmit={submit} noValidate className="grid gap-3 rounded-md border p-3">
        <h3 className="font-semibold">Add a role</h3>
        <div aria-live="assertive" className="empty:hidden">
          {assignError ? <InlineAlert live={false}>{assignError}</InlineAlert> : null}
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Role">
            {(control) => (
              <NativeSelect
                {...control}
                className="w-full"
                value={roleId}
                onChange={(e) => {
                  setRoleId(e.target.value);
                }}
              >
                {roles.map((r) => (
                  <NativeSelectOption key={r.id} value={r.id}>
                    {r.name}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            )}
          </Field>
          <Field label="Applies to">
            {(control) => (
              <NativeSelect
                {...control}
                className="w-full"
                value={scopeType}
                onChange={(e) => {
                  setScopeType(e.target.value as ScopeType);
                  setScopeId('');
                }}
              >
                {SCOPE_TYPES.map((s) => (
                  <NativeSelectOption key={s} value={s}>
                    {SCOPE_TYPE_LABEL[s]}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            )}
          </Field>
          {needsTarget ? (
            <Field
              label={scopeType === 'Organization' ? 'Organization' : scopeType === 'Site' ? 'Site' : 'Device group'}
              error={touched && targetMissing ? 'Choose one.' : null}
            >
              {(control) => (
                <NativeSelect
                  {...control}
                  className="w-full"
                  value={scopeId}
                  onChange={(e) => {
                    setScopeId(e.target.value);
                  }}
                >
                  <NativeSelectOption value="">Choose…</NativeSelectOption>
                  {scopeType === 'Organization'
                    ? directory.organizations.map((o) => (
                        <NativeSelectOption key={o.id} value={o.id}>
                          {o.name}
                        </NativeSelectOption>
                      ))
                    : null}
                  {scopeType === 'Site'
                    ? directory.organizations.map((o) => {
                        const sites = directory.sites.filter((s) => s.organizationId === o.id);
                        return sites.length === 0 ? null : (
                          <NativeSelectOptGroup key={o.id} label={o.name}>
                            {sites.map((s) => (
                              <NativeSelectOption key={s.id} value={s.id}>
                                {s.name}
                              </NativeSelectOption>
                            ))}
                          </NativeSelectOptGroup>
                        );
                      })
                    : null}
                  {scopeType === 'Group'
                    ? directory.organizations.map((o) => {
                        const groups = directory.groups.filter((g) => g.organizationId === o.id);
                        return groups.length === 0 ? null : (
                          <NativeSelectOptGroup key={o.id} label={orgName(o.id)}>
                            {groups.map((g) => (
                              <NativeSelectOption key={g.id} value={g.id}>
                                {siteName(g.siteId)} / {g.name}
                              </NativeSelectOption>
                            ))}
                          </NativeSelectOptGroup>
                        );
                      })
                    : null}
                </NativeSelect>
              )}
            </Field>
          ) : null}
        </div>
        {duplicate ? (
          <p role="status" className="text-muted-foreground text-xs">
            {isKey ? 'This key' : 'This user'} already has that role for that scope.
          </p>
        ) : null}
        <div>
          <Button type="submit" disabled={assign.isPending || !roleId || duplicate}>
            {assign.isPending ? 'Assigning…' : 'Assign role'}
          </Button>
        </div>
      </form>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose}>
          Done
        </Button>
      </DialogFooter>
    </div>
  );
}
