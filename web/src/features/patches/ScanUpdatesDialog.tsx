import { useMutation, useQueryClient } from '@tanstack/react-query';
import { type SyntheticEvent, useState } from 'react';
import { useNavigate } from 'react-router';
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
import { patchesApi } from '@/lib/api/patches';
import { useAccess } from '@/lib/auth/session';
import { notifySuccess } from '@/lib/notify';

/** Asks devices to look for updates now (`POST /patches/scan`). Read-only on the device, so no extra confirmation. */
export function ScanUpdatesDialog({ onClose }: { onClose: () => void }) {
  const access = useAccess();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const form = useTargetForm({ preview: access.has(AP.scriptsRun) });
  const [touched, setTouched] = useState(false);
  const scan = useMutation({
    mutationFn: () => patchesApi.scan(form.request ?? {}),
    onSuccess: async (created) => {
      notifySuccess(`Update scan started on ${deviceCountLabel(created.deviceCount)}`);
      await queryClient.invalidateQueries({ queryKey: jobKeys.all });
      onClose();
      await navigate(`/jobs/${created.jobId}`);
    },
  });
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (form.request && !scan.isPending) {
      scan.mutate();
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
            <DialogTitle>Scan for updates</DialogTitle>
            <DialogDescription>
              Devices check which updates they are missing and report back. Nothing is installed.
            </DialogDescription>
          </DialogHeader>
          <div aria-live="assertive" className="empty:hidden">
            {scan.error ? <InlineAlert live={false}>{errorMessage(scan.error)}</InlineAlert> : null}
          </div>
          <TargetPicker value={form.target} onChange={form.setTarget} />
          <TargetPreviewPanel
            state={form.preview}
            problem={form.problem ? (touched ? form.problem : 'Choose which devices to scan.') : null}
          />
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={scan.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={scan.isPending}>
              {scan.isPending ? 'Starting…' : form.count !== null ? `Scan ${deviceCountLabel(form.count)}` : 'Scan'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
