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
import { errorMessage } from '@/lib/api';
import { jobKeys } from '@/lib/api/jobs';
import { softwareApi, type DeployAction } from '@/lib/api/software';
import { useAccess } from '@/lib/auth/session';
import { notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import {
  EMPTY_PACKAGE_IDS,
  managedOs,
  PACKAGE_ID,
  PACKAGE_MANAGERS,
  validatePackageIds,
  type PackageIds,
} from './software-model';

/**
 * Install or uninstall through the device's package manager (winget, Homebrew, apt, dnf). One package id per
 * manager: every device uses the entry for its own manager and reports "not supported" when there is none.
 */
export function DeploySoftwareDialog({
  device,
  initialAction = 'install',
  initialPackages,
  onClose,
}: {
  /** Deploy to this one device (device page). Otherwise a target is chosen in the dialog. */
  device?: PickedDevice;
  initialAction?: DeployAction;
  initialPackages?: Partial<PackageIds>;
  onClose: () => void;
}) {
  const access = useAccess();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const ids = useId();
  const [action, setAction] = useState<DeployAction>(initialAction);
  const [packages, setPackages] = useState<PackageIds>({ ...EMPTY_PACKAGE_IDS, ...initialPackages });
  const [version, setVersion] = useState('');
  const [touched, setTouched] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const form = useTargetForm({ fixedDevice: device, preview: access.has(AP.scriptsRun) });

  const validation = validatePackageIds(packages);
  const versionProblem =
    version.trim() !== '' && !PACKAGE_ID.test(version.trim())
      ? 'Use only letters, digits and + . _ : @ / - (no spaces).'
      : null;
  const valid =
    form.request !== null && validation.form === null && Object.keys(validation.errors).length === 0 && !versionProblem;
  const first = Object.values(validation.packages)[0] ?? '';
  const verb = action === 'install' ? 'Install' : 'Uninstall';
  const managers = device ? PACKAGE_MANAGERS.filter((m) => m.os === device.os) : PACKAGE_MANAGERS;

  const deploy = useMutation({
    mutationFn: () =>
      softwareApi.deploy({
        action,
        packages: validation.packages,
        version: action === 'install' && version.trim() ? version.trim() : undefined,
        target: form.request ?? {},
      }),
    onSuccess: async (created) => {
      notifySuccess(`${verb} of ${first} started on ${deviceCountLabel(created.deviceCount)}`);
      await queryClient.invalidateQueries({ queryKey: jobKeys.all });
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
    if (valid && !deploy.isPending) {
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
            <DialogTitle>{device ? `${verb} software on ${device.hostname}` : 'Deploy software'}</DialogTitle>
            <DialogDescription>
              Uses the package manager that belongs to each device’s operating system. The agent passes the package id
              as a single argument; it never builds a command line from it.
            </DialogDescription>
          </DialogHeader>
          <div aria-live="assertive" className="empty:hidden">
            {deploy.error ? <InlineAlert live={false}>{errorMessage(deploy.error)}</InlineAlert> : null}
          </div>

          <fieldset>
            <legend className="mb-1.5 text-sm font-medium">Action</legend>
            <div className="flex flex-wrap gap-x-6 gap-y-2">
              {(['install', 'uninstall'] as const).map((a) => (
                <label key={a} className="flex cursor-pointer items-center gap-2">
                  <input
                    type="radio"
                    name={`${ids}-action`}
                    className="accent-primary"
                    checked={action === a}
                    onChange={() => {
                      setAction(a);
                    }}
                  />
                  {a === 'install' ? 'Install' : 'Uninstall'}
                </label>
              ))}
            </div>
          </fieldset>

          <section aria-labelledby={`${ids}-packages`} className="grid gap-3">
            <div>
              <h3 id={`${ids}-packages`} className="text-sm font-semibold">
                Package
              </h3>
              <p className="text-muted-foreground text-xs">
                {device
                  ? `Enter the package id as ${managers.map((m) => m.label).join(' or ')} knows it.`
                  : 'Enter the id of the same software for each package manager you want to cover. Leave the others empty.'}
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              {managers.map((m) => (
                <Field
                  key={m.id}
                  label={`${m.label} package id`}
                  hint={`${m.devices}. Example: ${m.example}`}
                  error={touched ? (validation.errors[m.id] ?? null) : null}
                >
                  {(control) => (
                    <Input
                      {...control}
                      className="ident"
                      value={packages[m.id]}
                      maxLength={200}
                      spellCheck={false}
                      autoCapitalize="none"
                      autoComplete="off"
                      onChange={(e) => {
                        setPackages({ ...packages, [m.id]: e.target.value });
                      }}
                    />
                  )}
                </Field>
              ))}
            </div>
            {touched && validation.form ? (
              <p role="alert" className="text-danger text-xs font-medium">
                {validation.form}
              </p>
            ) : null}
            {managers.some((m) => m.id === 'brew') ? (
              <InlineAlert tone="info" live={false}>
                Homebrew always runs as the person signed in at the Mac, never as root. If nobody is signed in, or
                Homebrew is not installed for that person, the run fails on that device and says why.
              </InlineAlert>
            ) : null}
            {action === 'install' ? (
              <Field
                label="Version (optional)"
                hint="Leave empty for the newest version. Not every package manager can install a specific version."
                error={touched ? versionProblem : null}
                className="sm:w-1/2"
              >
                {(control) => (
                  <Input
                    {...control}
                    className="ident"
                    value={version}
                    maxLength={200}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(e) => {
                      setVersion(e.target.value);
                    }}
                  />
                )}
              </Field>
            ) : null}
          </section>

          <section aria-labelledby={`${ids}-target`} className="grid gap-3">
            <h3 id={`${ids}-target`} className="text-sm font-semibold">
              Target
            </h3>
            {device ? (
              <p>
                This device: <span className="ident font-medium">{device.hostname}</span>
                {device.os ? ` (${osLabel(device.os)})` : ''}
              </p>
            ) : (
              <>
                <TargetPicker value={form.target} onChange={form.setTarget} />
                <TargetPreviewPanel
                  state={form.preview}
                  problem={form.problem ? (touched ? form.problem : 'Choose what to deploy to.') : null}
                  supportedOs={Object.keys(validation.packages).length > 0 ? managedOs(validation.packages) : undefined}
                />
              </>
            )}
          </section>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={deploy.isPending}>
              Cancel
            </Button>
            <Button
              type="submit"
              variant={action === 'uninstall' ? 'destructive' : 'default'}
              disabled={deploy.isPending}
            >
              {form.count !== null ? `${verb} on ${deviceCountLabel(form.count)}…` : `${verb}…`}
            </Button>
          </DialogFooter>
        </form>

        <ConfirmDialog
          open={confirming}
          onOpenChange={setConfirming}
          title={`${verb} ${first} on ${form.count !== null ? deviceCountLabel(form.count) : form.where}?`}
          description={
            <>
              <p>
                {action === 'install'
                  ? 'The package manager downloads and installs it on '
                  : 'The package manager removes it from '}
                {form.where}
                {form.count !== null && !form.single ? ` (${deviceCountLabel(form.count)} right now)` : ''}. Devices
                that are offline do it when they next connect. A failed attempt is retried once.
              </p>
              {form.preview.preview?.stepUpRequired ? <p>You will be asked for your authenticator code.</p> : null}
            </>
          }
          confirmLabel={`${verb}${form.count !== null ? ` on ${deviceCountLabel(form.count)}` : ''}`}
          destructive={action === 'uninstall'}
          pending={deploy.isPending}
          onConfirm={() => {
            deploy.mutate();
          }}
        />
      </DialogContent>
    </Dialog>
  );
}
