import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useId, useState, type SyntheticEvent } from 'react';
import { useOrgFilter } from '@/app/org-filter';
import { Field } from '@/components/field';
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
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Switch } from '@/components/ui/switch';
import { AP } from '@/features/jobs/permissions';
import { describeCron } from '@/features/scripts/cron';
import { errorMessage, isApiError } from '@/lib/api';
import {
  PATCH_SEVERITIES,
  PATCH_SOURCES,
  patchKeys,
  patchPoliciesApi,
  REBOOT_MODES,
  type PatchPolicy,
} from '@/lib/api/patches';
import { useAccess } from '@/lib/auth/session';
import { notifySuccess } from '@/lib/notify';
import {
  patchSourceLabel,
  policyDraft,
  REBOOT_MODE_TEXT,
  severity,
  toPolicyInput,
  validatePolicy,
  type PolicyDraft,
} from './patch-model';

export function PolicyDialog({ policy, onClose }: { policy: PatchPolicy | null; onClose: () => void }) {
  const access = useAccess();
  const queryClient = useQueryClient();
  const { organizations, orgId } = useOrgFilter();
  const ids = useId();
  const canShare = access.hasPartnerWide(AP.patchesApprove);
  const [d, setD] = useState<PolicyDraft>(() =>
    policyDraft(policy, canShare ? (orgId ?? '') : (orgId ?? organizations[0]?.id ?? '')),
  );
  const [categories, setCategories] = useState(() => d.autoApproveCategories.join(', '));
  const [touched, setTouched] = useState(false);
  const set = (patch: Partial<PolicyDraft>) => {
    setD({ ...d, ...patch });
  };
  const cron = describeCron(d.windowCron);
  const draft = {
    ...d,
    autoApproveCategories: categories
      .split(',')
      .map((c) => c.trim())
      .filter(Boolean),
  };
  const errors = validatePolicy(draft, (c) => describeCron(c).ok);
  const scopeMissing = !policy && !d.organizationId && !canShare;
  const valid = Object.keys(errors).length === 0 && !scopeMissing;
  const tz = organizations.find((o) => o.id === d.organizationId)?.timeZone;

  const save = useMutation({
    mutationFn: async () => {
      if (policy) {
        await patchPoliciesApi.update(policy.id, toPolicyInput(draft, false));
      } else {
        await patchPoliciesApi.create(toPolicyInput(draft, true));
      }
    },
    onSuccess: async () => {
      notifySuccess(policy ? `Policy “${draft.name.trim()}” saved` : `Policy “${draft.name.trim()}” created`);
      await queryClient.invalidateQueries({ queryKey: patchKeys.policies });
      onClose();
    },
  });
  const forbiddenShared = isApiError(save.error) && save.error.status === 403;

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (valid && !save.isPending) {
      save.mutate();
    }
  };
  const err = (key: keyof PolicyDraft) => (touched ? (errors[key] ?? null) : null);
  const toggle = (list: string[], value: string, on: boolean) =>
    on ? [...new Set([...list, value])] : list.filter((x) => x !== value);

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) {
          onClose();
        }
      }}
    >
      <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-3xl">
        <form onSubmit={submit} noValidate className="grid gap-5">
          <DialogHeader>
            <DialogTitle>{policy ? `Edit “${policy.name}”` : 'New patch policy'}</DialogTitle>
            <DialogDescription>
              A policy decides which updates are approved without asking, when they install and how devices restart. An
              organization’s own policy wins over a shared one.
            </DialogDescription>
          </DialogHeader>
          <div aria-live="assertive" className="empty:hidden">
            {save.error ? (
              <InlineAlert
                live={false}
                title={forbiddenShared ? 'Shared policies need a partner-wide role' : undefined}
              >
                {forbiddenShared
                  ? 'A shared policy applies to every organization without its own policy. Choose one organization for it.'
                  : errorMessage(save.error)}
              </InlineAlert>
            ) : null}
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" error={err('name')}>
              {(control) => (
                <Input
                  {...control}
                  value={d.name}
                  maxLength={120}
                  autoFocus
                  autoComplete="off"
                  onChange={(e) => {
                    set({ name: e.target.value });
                  }}
                />
              )}
            </Field>
            {policy ? (
              <div className="grid content-start gap-1.5">
                <p className="text-sm font-medium">Applies to</p>
                <p className="flex min-h-9 items-center">
                  {policy.organizationId
                    ? (organizations.find((o) => o.id === policy.organizationId)?.name ?? 'One organization')
                    : 'All organizations without their own policy (shared)'}
                </p>
              </div>
            ) : (
              <Field label="Applies to" error={touched && scopeMissing ? 'Choose an organization.' : null}>
                {(control) => (
                  <NativeSelect
                    {...control}
                    className="w-full"
                    value={d.organizationId}
                    onChange={(e) => {
                      set({ organizationId: e.target.value });
                    }}
                  >
                    {canShare ? (
                      <NativeSelectOption value="">All organizations without their own policy</NativeSelectOption>
                    ) : (
                      <NativeSelectOption value="">Choose…</NativeSelectOption>
                    )}
                    {organizations.map((o) => (
                      <NativeSelectOption key={o.id} value={o.id}>
                        {o.name}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                )}
              </Field>
            )}
            <div className="flex items-center gap-2.5 sm:col-span-2">
              <Switch
                id={`${ids}-enabled`}
                aria-labelledby={`${ids}-enabled-label`}
                checked={d.enabled}
                onCheckedChange={(enabled) => {
                  set({ enabled });
                }}
              />
              <label htmlFor={`${ids}-enabled`}>
                <span id={`${ids}-enabled-label`} className="font-medium">
                  Policy is active
                </span>
                <span className="text-muted-foreground block text-xs">
                  An inactive policy approves nothing and opens no maintenance window.
                </span>
              </label>
            </div>
          </div>

          <fieldset className="grid gap-2">
            <legend className="mb-1 text-sm font-semibold">Approve automatically</legend>
            <p className="text-muted-foreground text-xs">
              New updates with these ratings are approved the moment a device reports them. Everything else waits for
              someone to approve it under Patches.
            </p>
            <div className="flex flex-wrap gap-x-5 gap-y-2">
              {PATCH_SEVERITIES.map((s) => (
                <div key={s} className="flex items-center gap-2">
                  <Checkbox
                    id={`${ids}-sev-${s}`}
                    checked={d.autoApproveSeverities.includes(s)}
                    onCheckedChange={(c) => {
                      set({ autoApproveSeverities: toggle(d.autoApproveSeverities, s, c === true) });
                    }}
                  />
                  <label htmlFor={`${ids}-sev-${s}`}>{severity(s).label}</label>
                </div>
              ))}
            </div>
            <Field
              label="Also approve these categories (optional)"
              hint="Comma-separated, as the device reports them, for example Security Updates, Definition Updates."
              error={err('autoApproveCategories')}
            >
              {(control) => (
                <Input
                  {...control}
                  value={categories}
                  maxLength={2000}
                  autoComplete="off"
                  onChange={(e) => {
                    setCategories(e.target.value);
                  }}
                />
              )}
            </Field>
          </fieldset>

          <fieldset className="grid gap-2">
            <legend className="mb-1 text-sm font-semibold">Sources</legend>
            <p className="text-muted-foreground text-xs">
              Which update sources this policy covers. None ticked means all of them.
            </p>
            <div className="grid gap-2 sm:grid-cols-2">
              {PATCH_SOURCES.map((s) => (
                <div key={s} className="flex items-center gap-2">
                  <Checkbox
                    id={`${ids}-src-${s}`}
                    checked={d.sources.includes(s)}
                    onCheckedChange={(c) => {
                      set({ sources: toggle(d.sources, s, c === true) });
                    }}
                  />
                  <label htmlFor={`${ids}-src-${s}`}>{patchSourceLabel(s)}</label>
                </div>
              ))}
            </div>
          </fieldset>

          <fieldset className="grid gap-3">
            <legend className="mb-1 text-sm font-semibold">When updates install</legend>
            <Field
              label="Wait before installing (days)"
              hint="An update is installed only once it has been known for this many days, so bad updates can be pulled first. 0 to 90."
              error={err('deferDays')}
              className="sm:w-1/2"
            >
              {(control) => (
                <Input
                  {...control}
                  inputMode="numeric"
                  value={d.deferDays}
                  maxLength={2}
                  onChange={(e) => {
                    set({ deferDays: e.target.value });
                  }}
                />
              )}
            </Field>
            <div className="flex items-start gap-2.5">
              <Checkbox
                id={`${ids}-window`}
                className="mt-0.5"
                checked={d.windowEnabled}
                onCheckedChange={(c) => {
                  set({ windowEnabled: c === true });
                }}
              />
              <label htmlFor={`${ids}-window`}>
                <span className="font-medium">Install in a maintenance window</span>
                <span className="text-muted-foreground block text-xs">
                  When the window opens, every device of the organization installs its approved updates. Devices that
                  are offline for the whole window are skipped until the next one. Without a window, updates install
                  only when someone starts an install.
                </span>
              </label>
            </div>
            {d.windowEnabled ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <Field
                  label="Window opens (cron expression)"
                  hint="Five fields: minute, hour, day of month, month, day of week."
                  error={touched || !cron.ok ? (cron.ok ? null : cron.error) : null}
                >
                  {(control) => (
                    <Input
                      {...control}
                      className="ident"
                      value={d.windowCron}
                      maxLength={100}
                      spellCheck={false}
                      onChange={(e) => {
                        set({ windowCron: e.target.value });
                      }}
                    />
                  )}
                </Field>
                <Field label="Window length (minutes)" hint="15 to 1440." error={err('windowMinutes')}>
                  {(control) => (
                    <Input
                      {...control}
                      inputMode="numeric"
                      value={d.windowMinutes}
                      maxLength={4}
                      onChange={(e) => {
                        set({ windowMinutes: e.target.value });
                      }}
                    />
                  )}
                </Field>
                <p className="bg-muted/50 rounded-md border px-3 py-2 sm:col-span-2" role="status" aria-live="polite">
                  {cron.ok ? (
                    <>
                      <span className="font-semibold">{cron.text}</span>
                      {cron.exact ? ', ' : ' '}
                      {d.organizationId
                        ? `in the organization’s time zone${tz ? ` (${tz})` : ''}.`
                        : 'in UTC (shared policies use UTC).'}
                    </>
                  ) : (
                    <span className="text-muted-foreground">The schedule is not valid yet.</span>
                  )}
                </p>
              </div>
            ) : null}
          </fieldset>

          <fieldset className="grid gap-3">
            <legend className="mb-1 text-sm font-semibold">Restart after installing</legend>
            <div className="grid gap-2">
              {REBOOT_MODES.map((m) => (
                <label key={m} className="flex cursor-pointer items-start gap-2.5">
                  <input
                    type="radio"
                    name={`${ids}-reboot`}
                    className="accent-primary mt-1"
                    checked={d.rebootMode === m}
                    onChange={() => {
                      set({ rebootMode: m });
                    }}
                  />
                  <span>
                    <span className="font-medium">{REBOOT_MODE_TEXT[m]?.label}</span>
                    <span className="text-muted-foreground block text-xs">{REBOOT_MODE_TEXT[m]?.explain}</span>
                  </span>
                </label>
              ))}
            </div>
            <div className="flex items-start gap-2.5">
              <Checkbox
                id={`${ids}-notify`}
                className="mt-0.5"
                checked={d.rebootNotifyUser}
                onCheckedChange={(c) => {
                  set({ rebootNotifyUser: c === true });
                }}
              />
              <label htmlFor={`${ids}-notify`}>
                <span className="font-medium">Tell the signed-in user first and let them postpone</span>
              </label>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Postponements allowed" hint="0 to 20." error={err('rebootDeferrals')}>
                {(control) => (
                  <Input
                    {...control}
                    inputMode="numeric"
                    value={d.rebootDeferrals}
                    maxLength={2}
                    onChange={(e) => {
                      set({ rebootDeferrals: e.target.value });
                    }}
                  />
                )}
              </Field>
              <Field
                label="Restart at the latest after (minutes)"
                hint="After this the device restarts anyway. Up to 10080 (7 days)."
                error={err('rebootDeadlineMinutes')}
              >
                {(control) => (
                  <Input
                    {...control}
                    inputMode="numeric"
                    value={d.rebootDeadlineMinutes}
                    maxLength={5}
                    onChange={(e) => {
                      set({ rebootDeadlineMinutes: e.target.value });
                    }}
                  />
                )}
              </Field>
            </div>
          </fieldset>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={save.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={save.isPending}>
              {save.isPending ? 'Saving…' : policy ? 'Save policy' : 'Create policy'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
