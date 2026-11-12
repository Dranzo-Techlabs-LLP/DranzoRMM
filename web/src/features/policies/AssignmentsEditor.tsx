import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Trash2 } from 'lucide-react';
import { useState, type SyntheticEvent } from 'react';
import { Field } from '@/components/field';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { NativeSelect, NativeSelectOptGroup, NativeSelectOption } from '@/components/ui/native-select';
import { describeScope, SCOPE_TYPE_LABEL, type ScopeDirectory } from '@/features/admin/scope';
import { errorMessage, SCOPE_TYPES, type Id, type ScopeType } from '@/lib/api';
import { policiesApi, policyKeys, type Policy } from '@/lib/api/policies';
import { notifyError, notifySuccess } from '@/lib/notify';

/** Where a policy applies: add or remove organization, site or group assignments (or all organizations). */
export function AssignmentsEditor({
  policy,
  directory,
  partnerWide,
  onDone,
}: {
  policy: Policy;
  directory: ScopeDirectory;
  partnerWide: boolean;
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  // An organization's own policy can only be assigned inside that organization.
  const orgs = directory.organizations.filter((o) => policy.organizationId === null || o.id === policy.organizationId);
  const sites = directory.sites.filter((s) => orgs.some((o) => o.id === s.organizationId));
  const groups = directory.groups.filter((g) => orgs.some((o) => o.id === g.organizationId));
  const types = SCOPE_TYPES.filter((t) => t !== 'Partner' || (partnerWide && policy.organizationId === null));
  const [scopeType, setScopeType] = useState<ScopeType>(
    types.includes('Organization') ? 'Organization' : (types[0] ?? 'Organization'),
  );
  const [scopeId, setScopeId] = useState<Id>('');
  const [touched, setTouched] = useState(false);
  const needsTarget = scopeType !== 'Partner';
  const duplicate = policy.assignments.some(
    (a) => a.scopeType === scopeType && (a.scopeId ?? '') === (needsTarget ? scopeId : ''),
  );

  const refresh = () => queryClient.invalidateQueries({ queryKey: policyKeys.list });
  const assign = useMutation({
    mutationFn: () => policiesApi.assign(policy.id, scopeType, needsTarget ? scopeId : null),
    onSuccess: async () => {
      notifySuccess('Assigned');
      setScopeId('');
      setTouched(false);
      await refresh();
    },
  });
  const unassign = useMutation({
    mutationFn: (assignmentId: Id) => policiesApi.unassign(policy.id, assignmentId),
    onSuccess: async () => {
      notifySuccess('Assignment removed');
      await refresh();
    },
    onError: notifyError,
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if ((!needsTarget || scopeId) && !duplicate) {
      assign.mutate();
    }
  };
  const orgName = (id: Id) => directory.organizations.find((o) => o.id === id)?.name ?? 'Unknown organization';
  const siteName = (id: Id) => directory.sites.find((s) => s.id === id)?.name ?? 'Unknown site';

  return (
    <div className="grid gap-5">
      <DialogHeader>
        <DialogTitle>Where {policy.name} applies</DialogTitle>
        <DialogDescription>
          The policy is checked on devices covered by any of these assignments that run a supported operating system.
        </DialogDescription>
      </DialogHeader>
      <section aria-label="Current assignments">
        {policy.assignments.length === 0 ? (
          <p className="text-muted-foreground rounded-md border border-dashed px-3 py-4 text-center">
            Not assigned yet, so no device is checked.
          </p>
        ) : (
          <ul className="divide-y rounded-md border">
            {policy.assignments.map((a) => {
              const label = describeScope(a.scopeType, a.scopeId, directory);
              return (
                <li key={a.id} className="flex items-center justify-between gap-3 px-3 py-2">
                  <span className="min-w-0">
                    <span className="text-muted-foreground">{SCOPE_TYPE_LABEL[a.scopeType]}: </span>
                    {label}
                  </span>
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
                    Remove<span className="sr-only"> {label}</span>
                  </Button>
                </li>
              );
            })}
          </ul>
        )}
      </section>
      <form onSubmit={submit} noValidate className="grid gap-3 rounded-md border p-3">
        <h3 className="font-semibold">Add an assignment</h3>
        <div aria-live="assertive" className="empty:hidden">
          {assign.error ? <InlineAlert live={false}>{errorMessage(assign.error)}</InlineAlert> : null}
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
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
                {types.map((t) => (
                  <NativeSelectOption key={t} value={t}>
                    {SCOPE_TYPE_LABEL[t]}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            )}
          </Field>
          {needsTarget ? (
            <Field
              label={scopeType === 'Organization' ? 'Organization' : scopeType === 'Site' ? 'Site' : 'Device group'}
              error={touched && !scopeId ? 'Choose one.' : null}
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
                    ? orgs.map((o) => (
                        <NativeSelectOption key={o.id} value={o.id}>
                          {o.name}
                        </NativeSelectOption>
                      ))
                    : orgs.map((o) => {
                        const items =
                          scopeType === 'Site'
                            ? sites.filter((s) => s.organizationId === o.id).map((s) => ({ id: s.id, label: s.name }))
                            : groups
                                .filter((g) => g.organizationId === o.id)
                                .map((g) => ({ id: g.id, label: `${siteName(g.siteId)} / ${g.name}` }));
                        return items.length === 0 ? null : (
                          <NativeSelectOptGroup key={o.id} label={orgName(o.id)}>
                            {items.map((i) => (
                              <NativeSelectOption key={i.id} value={i.id}>
                                {i.label}
                              </NativeSelectOption>
                            ))}
                          </NativeSelectOptGroup>
                        );
                      })}
                </NativeSelect>
              )}
            </Field>
          ) : null}
        </div>
        {duplicate ? (
          <p role="status" className="text-muted-foreground text-xs">
            Already assigned there.
          </p>
        ) : null}
        <div>
          <Button type="submit" disabled={assign.isPending || duplicate}>
            {assign.isPending ? 'Assigning…' : 'Assign'}
          </Button>
        </div>
      </form>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone}>
          Done
        </Button>
      </DialogFooter>
    </div>
  );
}
