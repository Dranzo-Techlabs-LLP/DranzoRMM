import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Field } from '@/components/field';
import { Button } from '@/components/ui/button';
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { devicesApi, qk, type DeviceDetail } from '@/lib/api';
import { notifyError, notifySuccess } from '@/lib/notify';

/** Isolate or release a device. Both need a fresh authenticator code (the server asks for it). */
export function IsolationForm({ device, onDone }: { device: DeviceDetail; onDone: () => void }) {
  const queryClient = useQueryClient();
  const releasing = Boolean(device.isolatedAt);
  const [reason, setReason] = useState('');
  const [message, setMessage] = useState('');
  const [touched, setTouched] = useState(false);
  const reasonError =
    !releasing && touched && reason.trim() === '' ? 'Give a reason; it is recorded in the audit log.' : null;
  const run = useMutation({
    mutationFn: () =>
      releasing
        ? devicesApi.release(device.id, { reason: reason.trim() || undefined, message: message.trim() || undefined })
        : devicesApi.isolate(device.id, { reason: reason.trim(), message: message.trim() || undefined }),
    onSuccess: () => {
      notifySuccess(
        releasing
          ? 'Release requested. The device gets its network back within seconds.'
          : device.isOnline
            ? 'Isolation requested. The device confirms within a minute.'
            : 'Isolation queued until the device reconnects.',
      );
      onDone();
      for (const delay of [3000, 10000, 30000]) {
        setTimeout(() => void queryClient.invalidateQueries({ queryKey: qk.deviceDetail(device.id) }), delay);
      }
    },
    onError: notifyError,
  });
  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        setTouched(true);
        if (!releasing && reason.trim() === '') {
          return;
        }
        run.mutate();
      }}
    >
      <DialogHeader>
        <DialogTitle>
          {releasing ? `Release ${device.hostname}?` : `Isolate ${device.hostname} from the network?`}
        </DialogTitle>
        <DialogDescription>
          {releasing
            ? 'The device gets full network access again.'
            : 'The device can then only reach DranzoRMM, remote desktop, DNS and DHCP. Everything else, including the internet and other computers, is blocked until you release it. The person at the computer is told. If the device could not reach DranzoRMM afterwards, it undoes the isolation by itself. You will be asked for your authenticator code.'}
        </DialogDescription>
      </DialogHeader>
      <Field label={releasing ? 'Reason (optional)' : 'Reason'} error={reasonError}>
        {(control) => (
          <Textarea
            {...control}
            rows={2}
            maxLength={500}
            placeholder={releasing ? 'Cleaned and checked' : 'For example: ransomware alert, ticket 1234'}
            value={reason}
            onChange={(e) => {
              setReason(e.target.value);
            }}
          />
        )}
      </Field>
      <Field
        label="Message to the person at the computer (optional)"
        hint="Shown in a notification. Up to 512 characters."
      >
        {(control) => (
          <Textarea
            {...control}
            rows={2}
            maxLength={512}
            value={message}
            onChange={(e) => {
              setMessage(e.target.value);
            }}
          />
        )}
      </Field>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={run.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant={releasing ? 'default' : 'destructive'} disabled={run.isPending}>
          {run.isPending ? 'Requesting…' : releasing ? 'Release' : 'Isolate'}
        </Button>
      </DialogFooter>
    </form>
  );
}
