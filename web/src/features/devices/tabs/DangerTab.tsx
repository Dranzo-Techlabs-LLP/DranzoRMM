import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useNavigate } from 'react-router';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Button } from '@/components/ui/button';
import { devicesApi, qk } from '@/lib/api';
import { notifyError, notifySuccess } from '@/lib/notify';
import type { DeviceTabProps } from './registry';

/** Revoke and delete. Both are confirmed here and then need step-up on the server. */
export function DangerTab({ device }: DeviceTabProps) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [confirming, setConfirming] = useState<'revoke' | 'delete' | null>(null);
  const revoked = device.status === 'revoked';

  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.devices }),
      queryClient.invalidateQueries({ queryKey: qk.organizations }),
    ]);

  const revoke = useMutation({
    mutationFn: () => devicesApi.revoke(device.id),
    onSuccess: async () => {
      notifySuccess('Device revoked');
      setConfirming(null);
      await refresh();
    },
    onError: notifyError,
  });

  const remove = useMutation({
    mutationFn: () => devicesApi.remove(device.id),
    onSuccess: async () => {
      notifySuccess('Device deleted');
      setConfirming(null);
      queryClient.removeQueries({ queryKey: qk.deviceDetail(device.id) });
      void navigate('/devices', { replace: true });
      await refresh();
    },
    onError: notifyError,
  });

  return (
    <section aria-label="Danger zone" className="border-danger-mark/50 max-w-3xl divide-y rounded-lg border">
      <div className="flex flex-wrap items-center justify-between gap-4 p-4">
        <div className="max-w-[58ch]">
          <h2 className="font-semibold">Revoke this device</h2>
          <p className="text-muted-foreground mt-0.5">
            Cancels the device's certificate and disconnects it at once. The agent cannot reconnect until the computer
            is enrolled again with a new token. The device and its history stay in the dashboard.
          </p>
        </div>
        <Button
          variant="outline"
          className="text-destructive hover:text-destructive"
          disabled={revoked}
          onClick={() => {
            setConfirming('revoke');
          }}
        >
          {revoked ? 'Already revoked' : 'Revoke device'}
        </Button>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-4 p-4">
        <div className="max-w-[58ch]">
          <h2 className="font-semibold">Delete this device</h2>
          <p className="text-muted-foreground mt-0.5">
            Removes the device and its inventory from the dashboard and disconnects the agent. Audit log entries are
            kept. This cannot be undone.
          </p>
        </div>
        <Button
          variant="destructive"
          onClick={() => {
            setConfirming('delete');
          }}
        >
          Delete device
        </Button>
      </div>

      <ConfirmDialog
        open={confirming === 'revoke'}
        onOpenChange={(open) => {
          if (!open) {
            setConfirming(null);
          }
        }}
        title={`Revoke ${device.hostname}?`}
        description={
          <p>
            The agent is disconnected immediately and its certificate stops working. You will be asked for your
            authenticator code.
          </p>
        }
        confirmLabel="Revoke device"
        destructive
        pending={revoke.isPending}
        onConfirm={() => {
          revoke.mutate();
        }}
      />
      <ConfirmDialog
        open={confirming === 'delete'}
        onOpenChange={(open) => {
          if (!open) {
            setConfirming(null);
          }
        }}
        title={`Delete ${device.hostname}?`}
        description={
          <p>
            The device and its inventory are removed and the agent is disconnected. This cannot be undone. You will be
            asked for your authenticator code.
          </p>
        }
        confirmLabel="Delete device"
        destructive
        typeToConfirm={device.hostname}
        pending={remove.isPending}
        onConfirm={() => {
          remove.mutate();
        }}
      />
    </section>
  );
}
