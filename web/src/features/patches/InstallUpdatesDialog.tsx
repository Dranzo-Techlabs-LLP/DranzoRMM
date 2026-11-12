import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useId, useState, type SyntheticEvent } from 'react';
import { useNavigate } from 'react-router';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Field } from '@/components/field';
import { InlineAlert } from '@/components/status';
import { TargetPicker } from '@/components/target-picker/TargetPicker';
import { TargetPreviewPanel } from '@/components/target-picker/TargetPreview';
import type { PickedDevice } from '@/components/target-picker/target';
import { useTargetForm } from '@/components/target-picker/use-target-form';
import { deviceCountLabel } from '@/components/target-picker/use-target-preview';
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
import { AP } from '@/features/jobs/permissions';
import { errorMessage, type Id } from '@/lib/api';
import { jobKeys } from '@/lib/api/jobs';
import { patchesApi, patchKeys, REBOOT_MODES, type RebootMode } from '@/lib/api/patches';
import { useAccess } from '@/lib/auth/session';
import { notifySuccess } from '@/lib/notify';
import { REBOOT_MODE_TEXT } from './patch-model';

/**
 * Installs approved updates (`POST /patches/install`). Each device gets only its own approved updates; with
 * `catalogEntryIds` only those. Reboot options override the policy for this run.
 */
export function InstallUpdatesDialog({
  device,
  catalogEntryIds,
  label,
  onClose,
}: {
  device?: PickedDevice;
  catalogEntryIds?: Id[];
  /** For example "3 selected updates". */
  label?: string;
  onClose: () => void;
}) {
  const access = useAccess();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const ids = useId();
  const form = useTargetForm({ fixedDevice: device, preview: access.has(AP.scriptsRun) });
  const [mode, setMode] = useState<RebootMode>('if_required');
  const [notifyUser, setNotifyUser] = useState(true);
  const [deferrals, setDeferrals] = useState('3');
  const [deadline, setDeadline] = useState('240');
  const [message, setMessage] = useState('');
  const [touched, setTouched] = useState(false);
  const [confirming, setConfirming] = useState(false);

  const deferralsN = /^\d+$/.test(deferrals) && Number(deferrals) <= 20 ? Number(deferrals) : null;
  const deadlineN = /^\d+$/.test(deadline) && Number(deadline) <= 10080 ? Number(deadline) : null;
  const valid = form.request !== null && (mode === 'never' || (deferralsN !== null && deadlineN !== null));

  const install = useMutation({
    mutationFn: () =>
      patchesApi.install({
        target: form.request ?? {},
        catalogEntryIds,
        reboot: {
          mode,
          notifyUser,
          deferrals: deferralsN ?? undefined,
          deadlineMinutes: deadlineN ?? undefined,
          message: message.trim() || undefined,
        },
      }),
    onSuccess: async (created) => {
      notifySuccess(`Installing approved updates on ${deviceCountLabel(created.deviceCount)}`);
      await queryClient.invalidateQueries({ queryKey: jobKeys.all });
      await queryClient.invalidateQueries({ queryKey: patchKeys.all });
      onClose();
      await navigate(`/jobs/${created.jobId}`);
    },
    onError: () => {
      setConfirming(false);
    },
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (valid && !install.isPending) {
      setConfirming(true);
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
      <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-3xl">
        <form onSubmit={submit} noValidate className="grid gap-5">
          <DialogHeader>
            <DialogTitle>Install {label ?? 'approved updates'}</DialogTitle>
            <DialogDescription>
              Each device installs only updates that are approved for it and whose deferral period has passed. Devices
              with nothing approved are skipped.
            </DialogDescription>
          </DialogHeader>
          <div aria-live="assertive" className="empty:hidden">
            {install.error ? <InlineAlert live={false}>{errorMessage(install.error)}</InlineAlert> : null}
          </div>

          {device ? null : (
            <section aria-labelledby={`${ids}-target`} className="grid gap-3">
              <h3 id={`${ids}-target`} className="text-sm font-semibold">
                Target
              </h3>
              <TargetPicker value={form.target} onChange={form.setTarget} />
              <TargetPreviewPanel
                state={form.preview}
                problem={form.problem ? (touched ? form.problem : 'Choose where to install.') : null}
              />
            </section>
          )}

          <fieldset className="grid gap-2">
            <legend className="mb-1.5 text-sm font-semibold">Restart</legend>
            {REBOOT_MODES.map((m) => (
              <label key={m} className="flex cursor-pointer items-start gap-2.5">
                <input
                  type="radio"
                  name={`${ids}-reboot`}
                  className="accent-primary mt-1"
                  checked={mode === m}
                  onChange={() => {
                    setMode(m);
                  }}
                />
                <span>
                  <span className="font-medium">{REBOOT_MODE_TEXT[m]?.label ?? m}</span>
                  <span className="text-muted-foreground block text-xs">{REBOOT_MODE_TEXT[m]?.explain}</span>
                </span>
              </label>
            ))}
          </fieldset>
          {mode !== 'never' ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="flex items-start gap-2.5 sm:col-span-2">
                <Checkbox
                  id={`${ids}-notify`}
                  className="mt-0.5"
                  checked={notifyUser}
                  onCheckedChange={(c) => {
                    setNotifyUser(c === true);
                  }}
                />
                <label htmlFor={`${ids}-notify`}>
                  <span className="font-medium">Tell the signed-in user first</span>
                  <span className="text-muted-foreground block text-xs">
                    They see a message and can postpone the restart, up to the limits below.
                  </span>
                </label>
              </div>
              <Field
                label="Postponements allowed"
                hint="0 to 20."
                error={touched && deferralsN === null ? 'Enter a whole number from 0 to 20.' : null}
              >
                {(control) => (
                  <Input
                    {...control}
                    inputMode="numeric"
                    value={deferrals}
                    maxLength={2}
                    onChange={(e) => {
                      setDeferrals(e.target.value);
                    }}
                  />
                )}
              </Field>
              <Field
                label="Restart at the latest after (minutes)"
                hint="Then it restarts even if the user keeps postponing. Up to 10080 (7 days)."
                error={touched && deadlineN === null ? 'Enter a whole number from 0 to 10080.' : null}
              >
                {(control) => (
                  <Input
                    {...control}
                    inputMode="numeric"
                    value={deadline}
                    maxLength={5}
                    onChange={(e) => {
                      setDeadline(e.target.value);
                    }}
                  />
                )}
              </Field>
              <Field
                label="Message to the user (optional)"
                className="sm:col-span-2"
                hint="Default: “Your IT provider installed updates. This computer needs to restart.”"
              >
                {(control) => (
                  <Input
                    {...control}
                    value={message}
                    maxLength={500}
                    onChange={(e) => {
                      setMessage(e.target.value);
                    }}
                  />
                )}
              </Field>
            </div>
          ) : null}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={install.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={install.isPending}>
              {form.count !== null && !form.single ? `Install on up to ${deviceCountLabel(form.count)}…` : 'Install…'}
            </Button>
          </DialogFooter>
        </form>
        <ConfirmDialog
          open={confirming}
          onOpenChange={setConfirming}
          title={`Install ${label ?? 'approved updates'} on ${form.count !== null && !form.single ? deviceCountLabel(form.count) : form.where}?`}
          description={
            <>
              <p>
                {REBOOT_MODE_TEXT[mode]?.label}
                {mode !== 'never' && notifyUser ? ', after telling the signed-in user' : ''}. Installing can take a
                while; the job page shows progress per device.
              </p>
              {form.preview.preview?.stepUpRequired ? <p>You will be asked for your authenticator code.</p> : null}
            </>
          }
          confirmLabel="Install"
          pending={install.isPending}
          onConfirm={() => {
            install.mutate();
          }}
        />
      </DialogContent>
    </Dialog>
  );
}
