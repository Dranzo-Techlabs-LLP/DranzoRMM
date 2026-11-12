import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Ban,
  CircleCheck,
  Eye,
  KeyRound,
  LockKeyhole,
  LockKeyholeOpen,
  MoreHorizontal,
  Pencil,
  Plus,
  ShieldAlert,
  ShieldCheck,
  RectangleEllipsis,
  Trash2,
  UserCog,
  Users,
} from 'lucide-react';
import { useState } from 'react';
import { useSearchParams } from 'react-router';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useGroups, useSites, useOrganizationsQuery } from '@/features/tenants/queries';
import { qk, rolesApi, usersApi, type Id, type Role, type User } from '@/lib/api';
import { P } from '@/lib/auth/permissions';
import { useAccess, useMe } from '@/lib/auth/session';
import { useDocumentTitle, useReturnFocus } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { AssignmentsDialog } from './AssignmentsDialog';
import { CreateUserDialog } from './CreateUserDialog';
import { ResetPasswordDialog } from './ResetPasswordDialog';
import { RoleEditorDialog, type RoleEditorTarget } from './RoleEditorDialog';
import { describeScope, type ScopeDirectory } from './scope';

type UserAction = { kind: 'reset-mfa' | 'delete' | 'disable'; user: User };

export default function UsersPage() {
  useDocumentTitle('Users & roles');
  const access = useAccess();
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') === 'roles' ? 'roles' : 'users';

  const users = useQuery({ queryKey: qk.users, queryFn: usersApi.list });
  const roles = useQuery({ queryKey: qk.roles, queryFn: rolesApi.list });
  const orgs = useOrganizationsQuery(access.has(P.tenantsRead));
  const sites = useSites();
  const groups = useGroups();
  const directory: ScopeDirectory = {
    organizations: orgs.data ?? [],
    sites: sites.data ?? [],
    groups: groups.data ?? [],
  };

  return (
    <>
      <PageHeader
        title="Users & roles"
        description="Who can sign in to the dashboard, and what each person may do and where."
      />
      <Tabs
        value={tab}
        onValueChange={(v) => {
          setParams(v === 'roles' ? { tab: 'roles' } : {}, { replace: true });
        }}
      >
        <TabsList variant="line" className="mb-4 w-full justify-start border-b">
          <TabsTrigger value="users" className="flex-none px-3">
            Users
          </TabsTrigger>
          <TabsTrigger value="roles" className="flex-none px-3">
            Roles
          </TabsTrigger>
        </TabsList>
        <TabsContent value="users">
          <UsersTab users={users} roles={roles.data ?? []} directory={directory} />
        </TabsContent>
        <TabsContent value="roles">
          <RolesTab roles={roles} users={users.data ?? []} />
        </TabsContent>
      </Tabs>
    </>
  );
}

function UserState({ user }: { user: User }) {
  if (user.disabled) {
    return (
      <StatusPill tone="idle" icon={Ban}>
        Disabled
      </StatusPill>
    );
  }
  if (user.locked) {
    return (
      <StatusPill tone="warn" icon={LockKeyhole}>
        Locked out
      </StatusPill>
    );
  }
  return (
    <StatusPill tone="ok" icon={CircleCheck}>
      Active
    </StatusPill>
  );
}

function UsersTab({
  users,
  roles,
  directory,
}: {
  users: ReturnType<typeof useQuery<User[]>>;
  roles: Role[];
  directory: ScopeDirectory;
}) {
  const me = useMe();
  const access = useAccess();
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [assigningId, setAssigningId] = useState<Id | null>(null);
  const [action, setAction] = useState<UserAction | null>(null);
  const [resetting, setResetting] = useState<User | null>(null);
  const focus = useReturnFocus();

  const canManageUsers = access.hasPartnerWide(P.usersManage);
  const canManageRoles = access.hasPartnerWide(P.rolesManage);
  // Always the freshest copy, so the dialog reflects assignments as they change.
  const assigning = users.data?.find((u) => u.id === assigningId) ?? null;

  const act = useMutation({
    mutationFn: async (a: UserAction | { kind: 'enable' | 'unlock'; user: User }) => {
      switch (a.kind) {
        case 'unlock':
          await usersApi.unlock(a.user.id);
          return `${a.user.displayName} can sign in again`;
        case 'reset-mfa':
          await usersApi.resetMfa(a.user.id);
          return 'Authenticator reset. The user sets up a new one at next sign-in.';
        case 'delete':
          await usersApi.remove(a.user.id);
          return 'User deleted';
        case 'disable':
          await usersApi.update(a.user.id, { disabled: true });
          return 'User disabled and signed out';
        case 'enable':
          await usersApi.update(a.user.id, { disabled: false });
          return 'User enabled';
      }
    },
    onSuccess: async (message) => {
      notifySuccess(message);
      setAction(null);
      await queryClient.invalidateQueries({ queryKey: qk.users });
    },
    onError: notifyError,
  });

  const createButton = canManageUsers ? (
    <Button
      size="sm"
      onClick={() => {
        setCreating(true);
      }}
    >
      <Plus aria-hidden="true" />
      New user
    </Button>
  ) : null;

  return (
    <>
      <Panel title="Users" actions={createButton} flush>
        <QueryView
          query={users}
          what="users"
          isEmpty={(d) => d.length === 0}
          empty={<EmptyState icon={Users} title="No users" action={createButton} />}
        >
          {(list) => (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">User</TableHead>
                    <TableHead scope="col">Status</TableHead>
                    <TableHead scope="col">Two-step sign-in</TableHead>
                    <TableHead scope="col">Last sign-in</TableHead>
                    <TableHead scope="col">Roles</TableHead>
                    {canManageUsers || canManageRoles ? (
                      <TableHead scope="col" className="w-10">
                        <span className="sr-only">Actions</span>
                      </TableHead>
                    ) : null}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.map((u) => {
                    const self = u.id === me.user.id;
                    return (
                      <TableRow key={u.id}>
                        <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-normal">
                          <div className="font-medium">
                            {u.displayName}
                            {self ? <span className="text-muted-foreground font-normal"> (you)</span> : null}
                          </div>
                          <div className="text-muted-foreground text-xs">{u.email}</div>
                        </TableHead>
                        <TableCell>
                          <UserState user={u} />
                        </TableCell>
                        <TableCell>
                          {u.totpEnabled ? (
                            <StatusPill tone="ok" icon={ShieldCheck}>
                              Set up
                            </StatusPill>
                          ) : (
                            <StatusPill tone="warn" icon={ShieldAlert}>
                              Not set up yet
                            </StatusPill>
                          )}
                        </TableCell>
                        <TableCell>
                          <RelativeTime value={u.lastLoginAt} fallback="Never" />
                        </TableCell>
                        <TableCell className="whitespace-normal">
                          {u.assignments.length === 0 ? (
                            <span className="text-muted-foreground">No access</span>
                          ) : (
                            <ul className="space-y-0.5">
                              {u.assignments.map((a) => (
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
                        {canManageUsers || canManageRoles ? (
                          <TableCell className="py-1 text-right">
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button
                                  id={`user-actions-${u.id}`}
                                  variant="ghost"
                                  size="icon-sm"
                                  aria-label={`Actions for ${u.displayName}`}
                                >
                                  <MoreHorizontal aria-hidden="true" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end" className="w-56">
                                {canManageRoles ? (
                                  <DropdownMenuItem
                                    onSelect={() => {
                                      focus.from(`user-actions-${u.id}`);
                                      setAssigningId(u.id);
                                    }}
                                  >
                                    <UserCog aria-hidden="true" />
                                    Manage roles
                                  </DropdownMenuItem>
                                ) : null}
                                {canManageUsers ? (
                                  <>
                                    {canManageRoles ? <DropdownMenuSeparator /> : null}
                                    {u.disabled ? (
                                      <DropdownMenuItem
                                        onSelect={() => {
                                          act.mutate({ kind: 'enable', user: u });
                                        }}
                                      >
                                        <CircleCheck aria-hidden="true" />
                                        Enable sign-in
                                      </DropdownMenuItem>
                                    ) : (
                                      <DropdownMenuItem
                                        disabled={self}
                                        onSelect={() => {
                                          focus.from(`user-actions-${u.id}`);
                                          setAction({ kind: 'disable', user: u });
                                        }}
                                      >
                                        <Ban aria-hidden="true" />
                                        Disable sign-in
                                      </DropdownMenuItem>
                                    )}
                                    {u.locked ? (
                                      <DropdownMenuItem
                                        onSelect={() => {
                                          act.mutate({ kind: 'unlock', user: u });
                                        }}
                                      >
                                        <LockKeyholeOpen aria-hidden="true" />
                                        Unlock sign-in
                                      </DropdownMenuItem>
                                    ) : null}
                                    <DropdownMenuItem
                                      disabled={self}
                                      onSelect={() => {
                                        focus.from(`user-actions-${u.id}`);
                                        setResetting(u);
                                      }}
                                    >
                                      <RectangleEllipsis aria-hidden="true" />
                                      Set a temporary password
                                    </DropdownMenuItem>
                                    <DropdownMenuItem
                                      disabled={!u.totpEnabled}
                                      onSelect={() => {
                                        focus.from(`user-actions-${u.id}`);
                                        setAction({ kind: 'reset-mfa', user: u });
                                      }}
                                    >
                                      <KeyRound aria-hidden="true" />
                                      Reset authenticator
                                    </DropdownMenuItem>
                                    <DropdownMenuItem
                                      variant="destructive"
                                      disabled={self}
                                      onSelect={() => {
                                        focus.from(`user-actions-${u.id}`);
                                        setAction({ kind: 'delete', user: u });
                                      }}
                                    >
                                      <Trash2 aria-hidden="true" />
                                      Delete user
                                    </DropdownMenuItem>
                                  </>
                                ) : null}
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </TableCell>
                        ) : null}
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </QueryView>
      </Panel>

      <CreateUserDialog open={creating} onOpenChange={setCreating} />
      <ResetPasswordDialog
        user={resetting}
        onOpenChange={(open) => {
          if (!open) {
            setResetting(null);
          }
        }}
        onCloseAutoFocus={focus.onCloseAutoFocus}
      />
      <AssignmentsDialog
        subject={
          assigning
            ? { kind: 'user', id: assigning.id, name: assigning.displayName, assignments: assigning.assignments }
            : null
        }
        roles={roles}
        directory={directory}
        onCloseAutoFocus={focus.onCloseAutoFocus}
        onOpenChange={(open) => {
          if (!open) {
            setAssigningId(null);
          }
        }}
      />
      <ConfirmDialog
        open={action !== null}
        onOpenChange={(open) => {
          if (!open) {
            setAction(null);
          }
        }}
        title={
          action?.kind === 'reset-mfa'
            ? `Reset the authenticator for ${action.user.displayName}?`
            : action?.kind === 'delete'
              ? `Delete ${action.user.displayName}?`
              : `Disable sign-in for ${action?.user.displayName ?? 'this user'}?`
        }
        description={
          action?.kind === 'reset-mfa' ? (
            <p>
              Their authenticator app and recovery codes stop working and they are signed out everywhere. At the next
              sign-in they must set up an authenticator again. Two-step sign-in is never switched off.
            </p>
          ) : action?.kind === 'delete' ? (
            <p>
              The account, its sessions and its role assignments are removed. What the user did stays in the audit log.
              This cannot be undone.
            </p>
          ) : (
            <p>They are signed out everywhere and cannot sign in until you enable the account again.</p>
          )
        }
        confirmLabel={
          action?.kind === 'reset-mfa'
            ? 'Reset authenticator'
            : action?.kind === 'delete'
              ? 'Delete user'
              : 'Disable sign-in'
        }
        destructive
        typeToConfirm={action?.kind === 'delete' ? action.user.email : undefined}
        pending={act.isPending}
        onCloseAutoFocus={focus.onCloseAutoFocus}
        onConfirm={() => {
          if (action) {
            act.mutate(action);
          }
        }}
      />
    </>
  );
}

function RolesTab({ roles, users }: { roles: ReturnType<typeof useQuery<Role[]>>; users: User[] }) {
  const access = useAccess();
  const queryClient = useQueryClient();
  const [editor, setEditor] = useState<RoleEditorTarget | null>(null);
  const [deleting, setDeleting] = useState<Role | null>(null);
  const canManage = access.hasPartnerWide(P.rolesManage);

  const holders = (roleId: Id) => users.filter((u) => u.assignments.some((a) => a.roleId === roleId)).length;

  const remove = useMutation({
    mutationFn: (id: Id) => rolesApi.remove(id),
    onSuccess: async () => {
      notifySuccess('Role deleted');
      setDeleting(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.roles }),
        queryClient.invalidateQueries({ queryKey: qk.users }),
      ]);
    },
    onError: notifyError,
  });

  const createButton = canManage ? (
    <Button
      size="sm"
      onClick={() => {
        setEditor({ mode: 'create' });
      }}
    >
      <Plus aria-hidden="true" />
      New role
    </Button>
  ) : null;

  return (
    <>
      <Panel
        title="Roles"
        description="Built-in roles cover the common cases. Custom roles combine individual permissions."
        actions={createButton}
        flush
      >
        <QueryView query={roles} what="roles" isEmpty={(d) => d.length === 0} empty={<EmptyState title="No roles" />}>
          {(list) => (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Role</TableHead>
                    <TableHead scope="col">Type</TableHead>
                    <TableHead scope="col" className="text-right">
                      Permissions
                    </TableHead>
                    <TableHead scope="col" className="text-right">
                      Users
                    </TableHead>
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.map((r) => (
                    <TableRow key={r.id}>
                      <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-medium">
                        {r.name}
                      </TableHead>
                      <TableCell>{r.isBuiltIn ? 'Built-in' : 'Custom'}</TableCell>
                      <TableCell className="text-right">{r.permissions.length}</TableCell>
                      <TableCell className="text-right">{holders(r.id)}</TableCell>
                      <TableCell className="py-1 text-right">
                        <div className="flex justify-end gap-1">
                          {r.isBuiltIn || !canManage ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setEditor({ mode: 'view', role: r });
                              }}
                            >
                              <Eye aria-hidden="true" />
                              View<span className="sr-only"> {r.name}</span>
                            </Button>
                          ) : (
                            <>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => {
                                  setEditor({ mode: 'edit', role: r });
                                }}
                              >
                                <Pencil aria-hidden="true" />
                                Edit<span className="sr-only"> {r.name}</span>
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="text-destructive hover:text-destructive"
                                onClick={() => {
                                  setDeleting(r);
                                }}
                              >
                                <Trash2 aria-hidden="true" />
                                Delete<span className="sr-only"> {r.name}</span>
                              </Button>
                            </>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </QueryView>
      </Panel>

      <RoleEditorDialog
        target={editor}
        onOpenChange={(open) => {
          if (!open) {
            setEditor(null);
          }
        }}
      />
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
          }
        }}
        title={`Delete the role ${deleting?.name ?? ''}?`}
        description={
          <p>
            {deleting && holders(deleting.id) > 0
              ? `${holders(deleting.id)} ${holders(deleting.id) === 1 ? 'user has' : 'users have'} this role and will lose the access it gives.`
              : 'No user has this role.'}{' '}
            You will be asked for your authenticator code.
          </p>
        }
        confirmLabel="Delete role"
        destructive
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) {
            remove.mutate(deleting.id);
          }
        }}
      />
    </>
  );
}
