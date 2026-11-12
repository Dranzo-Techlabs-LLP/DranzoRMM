import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useId, useState, type SyntheticEvent } from 'react';
import { useNavigate } from 'react-router';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { InlineAlert } from '@/components/status';
import { TargetPicker } from '@/components/target-picker/TargetPicker';
import { TargetPreviewPanel } from '@/components/target-picker/TargetPreview';
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
import { AP } from '@/features/jobs/permissions';
import { errorMessage } from '@/lib/api';
import { jobKeys } from '@/lib/api/jobs';
import { packagesApi, type DeployAction, type PackageItem } from '@/lib/api/software';
import { useAccess } from '@/lib/auth/session';
import { notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import { describeDetection } from './software-model';

/** Installs or uninstalls an uploaded package on a target (`POST /packages/{id}/deploy`). */
export function DeployPackageDialog({ pkg, onClose }: { pkg: PackageItem; onClose: () => void }) {
  const access = useAccess();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const ids = useId();
  const canUninstall = (pkg.uninstallCommand?.length ?? 0) > 0;
  const [action, setAction] = useState<DeployAction>('install');
  const [touched, setTouched] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const form = useTargetForm({ organizationId: pkg.organizationId, preview: access.has(AP.scriptsRun) });
  const verb = action === 'install' ? 'Install' : 'Uninstall';
  const title = `${pkg.name}${pkg.version ? ` ${pkg.version}` : ''}`;

  const deploy = useMutation({
    mutationFn: () => packagesApi.deploy(pkg.id, action, form.request ?? {}),
    onSuccess: async (created) => {
      notifySuccess(`${verb} of ${title} started on ${deviceCountLabel(created.deviceCount)}`);
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
    if (form.request !== null && !deploy.isPending) {
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
            <DialogTitle>Deploy “{title}”</DialogTitle>
            <DialogDescription>
              {osLabel(pkg.os)} package ({pkg.type}). Each device downloads the file from your server and verifies its
              SHA-256 before running it. {describeDetection(pkg.detection)}.
            </DialogDescription>
          </DialogHeader>
          <div aria-live="assertive" className="empty:hidden">
            {deploy.error ? <InlineAlert live={false}>{errorMessage(deploy.error)}</InlineAlert> : null}
          </div>

          <fieldset>
            <legend className="mb-1.5 text-sm font-medium">Action</legend>
            <div className="flex flex-wrap gap-x-6 gap-y-2">
              {(['install', 'uninstall'] as const).map((a) => (
                <label
                  key={a}
                  className={
                    a === 'uninstall' && !canUninstall
                      ? 'text-muted-foreground flex items-center gap-2'
                      : 'flex cursor-pointer items-center gap-2'
                  }
                >
                  <input
                    type="radio"
                    name={`${ids}-action`}
                    className="accent-primary"
                    checked={action === a}
                    disabled={a === 'uninstall' && !canUninstall}
                    onChange={() => {
                      setAction(a);
                    }}
                  />
                  {a === 'install' ? 'Install' : 'Uninstall'}
                </label>
              ))}
            </div>
            {!canUninstall ? (
              <p className="text-muted-foreground mt-1.5 text-xs">
                This package has no uninstall command, so it can only be installed from here.
              </p>
            ) : null}
          </fieldset>

          <section aria-labelledby={`${ids}-target`} className="grid gap-3">
            <h3 id={`${ids}-target`} className="text-sm font-semibold">
              Target
            </h3>
            <TargetPicker value={form.target} onChange={form.setTarget} lockedOrganizationId={pkg.organizationId} />
            <TargetPreviewPanel
              state={form.preview}
              problem={form.problem ? (touched ? form.problem : 'Choose what to deploy to.') : null}
              supportedOs={[pkg.os]}
            />
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
          title={`${verb} ${title} on ${form.count !== null ? deviceCountLabel(form.count) : form.where}?`}
          description={
            <>
              <p>
                {action === 'install' ? 'It is installed silently on ' : 'Its uninstall command runs on '}
                {form.where}
                {form.count !== null && !form.single ? ` (${deviceCountLabel(form.count)} right now)` : ''}, as the
                system account. Devices that are offline do it when they next connect. A failed attempt is retried once.
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
