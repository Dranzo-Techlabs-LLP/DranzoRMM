import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useId, useState, type SyntheticEvent } from 'react';
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
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Switch } from '@/components/ui/switch';
import {
  CONSENT_MODES,
  errorMessage,
  isApiError,
  organizationsApi,
  qk,
  type ConsentMode,
  type Organization,
} from '@/lib/api';
import { notifySuccess } from '@/lib/notify';
import { cn } from '@/lib/utils';
import { CONSENT } from './consent';
import { browserTimeZone, useTimeZoneOptions } from './timezones';

/** Create (no `organization`) or edit an organization. */
export function OrganizationFormDialog({
  open,
  onOpenChange,
  organization,
  onCreated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organization?: Organization;
  onCreated?: (id: string) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-xl">
        {/* Mounted per open so the form always starts from the current values. */}
        {open ? (
          <OrganizationForm
            organization={organization}
            onDone={(id) => {
              onOpenChange(false);
              if (id) {
                onCreated?.(id);
              }
            }}
            onCancel={() => {
              onOpenChange(false);
            }}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function OrganizationForm({
  organization,
  onDone,
  onCancel,
}: {
  organization?: Organization;
  onDone: (createdId?: string) => void;
  onCancel: () => void;
}) {
  const queryClient = useQueryClient();
  const consentName = useId();
  const signedId = useId();
  const [name, setName] = useState(organization?.name ?? '');
  const [timeZone, setTimeZone] = useState(organization?.timeZone ?? browserTimeZone());
  const [consentMode, setConsentMode] = useState<ConsentMode>(organization?.consentMode ?? 'require');
  const [signed, setSigned] = useState(organization?.requireSignedPowerShell ?? false);
  const [touched, setTouched] = useState(false);
  const zones = useTimeZoneOptions(organization?.timeZone);

  const save = useMutation({
    mutationFn: async () => {
      const input = { name: name.trim(), timeZone, consentMode, requireSignedPowerShell: signed };
      if (organization) {
        await organizationsApi.update(organization.id, input);
        return undefined;
      }
      return (await organizationsApi.create(input)).id;
    },
    onSuccess: async (createdId) => {
      await queryClient.invalidateQueries({ queryKey: qk.organizations });
      notifySuccess(organization ? 'Organization saved' : 'Organization created');
      onDone(createdId);
    },
  });

  const nameError =
    touched && !name.trim() ? 'Enter a name.' : name.trim().length > 120 ? 'Use 120 characters or fewer.' : null;
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!name.trim() || name.trim().length > 120) {
      return;
    }
    save.mutate();
  };
  const serverError =
    save.error && !(isApiError(save.error) && save.error.code === 'unauthenticated') ? errorMessage(save.error) : null;

  return (
    <form onSubmit={submit} noValidate className="grid gap-5">
      <DialogHeader>
        <DialogTitle>{organization ? `Edit ${organization.name}` : 'New organization'}</DialogTitle>
        <DialogDescription>
          An organization is one client business. Its sites, groups and devices live inside it.
        </DialogDescription>
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {serverError ? <InlineAlert live={false}>{serverError}</InlineAlert> : null}
      </div>
      <Field label="Name" error={nameError}>
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
      <Field label="Time zone" hint="Scheduled work and maintenance windows for this organization use this time zone.">
        {(control) => (
          <NativeSelect
            {...control}
            className="w-full"
            value={timeZone}
            onChange={(e) => {
              setTimeZone(e.target.value);
            }}
          >
            {zones.map((z) => (
              <NativeSelectOption key={z} value={z}>
                {z.replaceAll('_', ' ')}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        )}
      </Field>
      <fieldset className="grid gap-2">
        <legend className="mb-1.5 text-sm font-medium">When a technician starts a remote session</legend>
        {[...CONSENT_MODES].reverse().map((mode) => {
          const id = `${consentName}-${mode}`;
          return (
            <label
              key={mode}
              htmlFor={id}
              className={cn(
                'flex cursor-pointer items-start gap-3 rounded-md border p-3',
                consentMode === mode ? 'border-foreground/40 bg-accent/50' : 'hover:bg-accent/30',
              )}
            >
              <input
                id={id}
                type="radio"
                name={consentName}
                value={mode}
                checked={consentMode === mode}
                onChange={() => {
                  setConsentMode(mode);
                }}
                className="accent-primary mt-1 size-3.5"
                aria-describedby={`${id}-help`}
              />
              <span>
                <span className="block font-medium">{CONSENT[mode].label}</span>
                <span id={`${id}-help`} className="text-muted-foreground block">
                  {CONSENT[mode].explanation}
                </span>
              </span>
            </label>
          );
        })}
      </fieldset>
      <div className="flex items-start justify-between gap-4 rounded-md border p-3">
        <div>
          <Label htmlFor={signedId}>Only run signed PowerShell scripts</Label>
          <p id={`${signedId}-help`} className="text-muted-foreground mt-1">
            Windows devices in this organization refuse PowerShell scripts that are not signed by a trusted certificate.
            Other script types are not affected.
          </p>
        </div>
        <Switch id={signedId} checked={signed} onCheckedChange={setSigned} aria-describedby={`${signedId}-help`} />
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel} disabled={save.isPending}>
          Cancel
        </Button>
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? 'Saving…' : organization ? 'Save changes' : 'Create organization'}
        </Button>
      </DialogFooter>
    </form>
  );
}
