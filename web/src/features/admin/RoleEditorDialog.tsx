import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState, type SyntheticEvent } from 'react';
import { Field } from '@/components/field';
import { ErrorState, LoadingRows } from '@/components/page';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { authApi, errorMessage, isApiError, qk, rolesApi, type Role } from '@/lib/api';
import { notifySuccess } from '@/lib/notify';
import { groupPermissions, type PermissionGroup } from './permission-catalog';

export type RoleEditorTarget = { mode: 'create' } | { mode: 'edit' | 'view'; role: Role };

/** Create or edit a custom role, or view a built-in one. Permissions come from `GET /auth/permissions`. */
export function RoleEditorDialog({
  target,
  onOpenChange,
}: {
  target: RoleEditorTarget | null;
  onOpenChange: (open: boolean) => void;
}) {
  const catalog = useQuery({
    queryKey: qk.permissionCatalog,
    queryFn: authApi.permissions,
    staleTime: 10 * 60_000,
    enabled: target !== null,
  });
  return (
    <Dialog open={target !== null} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-3xl">
        {target === null ? null : catalog.isPending ? (
          <>
            <DialogHeader>
              <DialogTitle>Role</DialogTitle>
              <DialogDescription>Loading the permission list.</DialogDescription>
            </DialogHeader>
            <LoadingRows label="permissions" />
          </>
        ) : catalog.isError ? (
          <>
            <DialogHeader>
              <DialogTitle>Role</DialogTitle>
              <DialogDescription>The permission list is needed to show this role.</DialogDescription>
            </DialogHeader>
            <ErrorState error={catalog.error} what="permissions" onRetry={() => void catalog.refetch()} />
          </>
        ) : (
          <RoleForm
            target={target}
            groups={groupPermissions(catalog.data.permissions)}
            onDone={() => {
              onOpenChange(false);
            }}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function RoleForm({
  target,
  groups,
  onDone,
}: {
  target: RoleEditorTarget;
  groups: PermissionGroup[];
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const role = target.mode === 'create' ? null : target.role;
  const readOnly = target.mode === 'view';
  const [name, setName] = useState(role?.name ?? '');
  const [selected, setSelected] = useState<Set<string>>(() => new Set(role?.permissions ?? []));
  const [touched, setTouched] = useState(false);

  const save = useMutation({
    mutationFn: async () => {
      const input = { name: name.trim(), permissions: [...selected] };
      if (role) {
        await rolesApi.update(role.id, input);
      } else {
        await rolesApi.create(input);
      }
    },
    onSuccess: async () => {
      notifySuccess(role ? 'Role saved' : 'Role created');
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.roles }),
        queryClient.invalidateQueries({ queryKey: qk.users }),
        queryClient.invalidateQueries({ queryKey: qk.me }),
      ]);
      onDone();
    },
  });

  const toggle = (id: string, on: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (on) {
        next.add(id);
      } else {
        next.delete(id);
      }
      return next;
    });
  };
  const toggleGroup = (group: PermissionGroup, on: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const item of group.items) {
        if (on) {
          next.add(item.id);
        } else {
          next.delete(item.id);
        }
      }
      return next;
    });
  };

  const nameValid = name.trim().length > 0 && name.trim().length <= 64;
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (readOnly || !nameValid || selected.size === 0) {
      return;
    }
    save.mutate();
  };
  const serverError =
    save.error && !(isApiError(save.error) && save.error.code === 'step_up_cancelled')
      ? errorMessage(save.error)
      : null;

  return (
    <form onSubmit={submit} noValidate className="grid gap-4">
      <DialogHeader>
        <DialogTitle>{role ? (readOnly ? role.name : `Edit ${role.name}`) : 'New role'}</DialogTitle>
        <DialogDescription>
          {readOnly
            ? 'Built-in roles cannot be changed. Create a custom role if you need a different mix of permissions.'
            : 'Choose what people with this role may do. Where they may do it is set when you assign the role.'}
        </DialogDescription>
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {serverError ? <InlineAlert live={false}>{serverError}</InlineAlert> : null}
      </div>
      {readOnly ? null : (
        <Field label="Role name" error={touched && !nameValid ? 'Enter a name of up to 64 characters.' : null}>
          {(control) => (
            <Input
              {...control}
              className="max-w-sm"
              value={name}
              maxLength={64}
              autoComplete="off"
              autoFocus
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          )}
        </Field>
      )}
      <div>
        <div className="mb-2 flex items-baseline justify-between gap-3">
          <p className="text-sm font-medium">Permissions</p>
          <p className="text-muted-foreground text-xs" aria-live="polite">
            {selected.size} selected
          </p>
        </div>
        {touched && selected.size === 0 ? (
          <p role="alert" className="text-danger mb-2 text-xs font-medium">
            Select at least one permission.
          </p>
        ) : null}
        <div className="grid gap-x-6 gap-y-4 sm:grid-cols-2">
          {groups.map((group) => {
            const count = group.items.filter((i) => selected.has(i.id)).length;
            const all = count === group.items.length;
            return (
              <fieldset key={group.area} className="min-w-0 rounded-md border p-3" disabled={readOnly}>
                <legend className="px-1 text-sm font-semibold">{group.label}</legend>
                {group.items.length > 1 && !readOnly ? (
                  <label className="text-muted-foreground mb-2 flex items-center gap-2 text-xs">
                    <Checkbox
                      checked={all ? true : count > 0 ? 'indeterminate' : false}
                      onCheckedChange={(v) => {
                        toggleGroup(group, v === true);
                      }}
                    />
                    Everything in {group.label.toLowerCase()}
                  </label>
                ) : null}
                <ul className="grid gap-1.5">
                  {group.items.map((item) => (
                    <li key={item.id}>
                      <label className="flex items-start gap-2">
                        <Checkbox
                          className="mt-0.5"
                          checked={selected.has(item.id)}
                          onCheckedChange={(v) => {
                            toggle(item.id, v === true);
                          }}
                        />
                        <span className="min-w-0">
                          {item.label} <span className="ident text-muted-foreground text-xs">{item.id}</span>
                        </span>
                      </label>
                    </li>
                  ))}
                </ul>
              </fieldset>
            );
          })}
        </div>
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={save.isPending}>
          {readOnly ? 'Close' : 'Cancel'}
        </Button>
        {readOnly ? null : (
          <Button type="submit" disabled={save.isPending}>
            {save.isPending ? 'Saving…' : role ? 'Save role' : 'Create role'}
          </Button>
        )}
      </DialogFooter>
    </form>
  );
}
