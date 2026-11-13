import { useMutation, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Power, RotateCw, ShieldBan, Trash2 } from 'lucide-react';
import { useState, type SyntheticEvent } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Field } from '@/components/field';
import { Panel } from '@/components/page';
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
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { devicesApi, errorMessage, isApiError, qk, type DeviceDetail } from '@/lib/api';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { notifyError, notifySuccess } from '@/lib/notify';
import { IsolationForm } from './IsolationDialog';

const DELAYS = [
  { seconds: 0, label: 'Now' },
  { seconds: 300, label: 'In 5 minutes' },
  { seconds: 900, label: 'In 15 minutes' },
  { seconds: 3600, label: 'In 1 hour' },
];

/** Agent controls on one device: uninstall code, restart, uninstall. Each needs its own permission. */
export function AgentCard({ device }: { device: DeviceDetail }) {
  const access = useAccess();
  const queryClient = useQueryClient();
  const [dialog, setDialog] = useState<'code' | 'reboot' | 'uninstall' | 'isolate' | null>(null);
  const canManage = access.has(P.devicesManage);
  const canRevoke = access.has(P.devicesRevoke);
  const canIsolate = access.has(P.devicesIsolate);
  const revoked = device.status === 'revoked';
  if ((!canManage && !canRevoke && !canIsolate) || revoked) {
    return null;
  }
  const close = () => {
    setDialog(null);
  };

  return (
    <Panel
      className="mb-4"
      title="Agent"
      description={`Version ${device.agentVersion || 'unknown'}. Uninstall code ${device.uninstallCodeSet ? 'set' : 'not set'}: ${
        device.uninstallCodeSet
          ? 'removing the agent on the computer itself needs the code.'
          : 'an administrator of the computer can remove the agent without a code.'
      }`}
      actions={
        <>
          {canManage ? (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setDialog('code');
                }}
              >
                <KeyRound aria-hidden="true" />
                {device.uninstallCodeSet ? 'Change uninstall code' : 'Set uninstall code'}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setDialog('reboot');
                }}
              >
                <RotateCw aria-hidden="true" />
                Restart device
              </Button>
            </>
          ) : null}
          {canIsolate ? (
            <Button
              variant="outline"
              size="sm"
              className={device.isolatedAt ? undefined : 'text-destructive hover:text-destructive'}
              onClick={() => {
                setDialog('isolate');
              }}
            >
              <ShieldBan aria-hidden="true" />
              {device.isolatedAt ? 'Release isolation' : 'Isolate'}
            </Button>
          ) : null}
          {canRevoke ? (
            <Button
              variant="outline"
              size="sm"
              className="text-destructive hover:text-destructive"
              onClick={() => {
                setDialog('uninstall');
              }}
            >
              <Trash2 aria-hidden="true" />
              Uninstall agent
            </Button>
          ) : null}
        </>
      }
    >
      {!device.isOnline ? (
        <p className="text-muted-foreground text-xs">The device is offline. Requests wait until it reconnects.</p>
      ) : (
        <p className="text-muted-foreground text-xs">
          Every request here is carried out by the agent and recorded in the audit log.
        </p>
      )}
      <Dialog
        open={dialog === 'code' || dialog === 'reboot' || dialog === 'isolate'}
        onOpenChange={(open) => {
          if (!open) {
            close();
          }
        }}
      >
        <DialogContent className="sm:max-w-lg">
          {dialog === 'code' ? (
            <UninstallCodeForm
              device={device}
              onDone={async () => {
                close();
                await queryClient.invalidateQueries({ queryKey: qk.deviceDetail(device.id) });
              }}
            />
          ) : null}
          {dialog === 'reboot' ? <RebootForm device={device} onDone={close} /> : null}
          {dialog === 'isolate' ? <IsolationForm device={device} onDone={close} /> : null}
        </DialogContent>
      </Dialog>
      <UninstallConfirm device={device} open={dialog === 'uninstall'} onOpenChange={(open) => !open && close()} />
    </Panel>
  );
}

function UninstallCodeForm({ device, onDone }: { device: DeviceDetail; onDone: () => Promise<void> }) {
  const [code, setCode] = useState('');
  const [repeat, setRepeat] = useState('');
  const [touched, setTouched] = useState(false);
  const lengthOk = code.length >= 8 && code.length <= 64;
  const same = code === repeat;
  const save = useMutation({
    mutationFn: (value: string | null) => devicesApi.setUninstallCode(device.id, value),
    onSuccess: async (_, value) => {
      notifySuccess(value ? 'Uninstall code sent to the device' : 'Uninstall code removed');
      await onDone();
    },
  });
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (lengthOk && same) {
      save.mutate(code);
    }
  };
  const error =
    save.error && !(isApiError(save.error) && save.error.code === 'step_up_cancelled')
      ? errorMessage(save.error)
      : null;
  return (
    <form onSubmit={submit} noValidate className="grid gap-4">
      <DialogHeader>
        <DialogTitle>Uninstall code for {device.hostname}</DialogTitle>
        <DialogDescription>
          Removing the agent on the computer will then ask for this code. Only a salted hash is sent to the device; the
          code is never stored or shown again, so keep it in your password manager. You will be asked for your
          authenticator code.
        </DialogDescription>
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {error ? <InlineAlert live={false}>{error}</InlineAlert> : null}
      </div>
      <Field
        label="New code"
        hint="8 to 64 characters."
        error={touched && !lengthOk ? 'Use 8 to 64 characters.' : null}
      >
        {(control) => (
          <Input
            {...control}
            type="password"
            autoComplete="new-password"
            maxLength={64}
            autoFocus
            value={code}
            onChange={(e) => {
              setCode(e.target.value);
            }}
          />
        )}
      </Field>
      <Field label="Repeat the code" error={touched && !same ? 'The two codes do not match.' : null}>
        {(control) => (
          <Input
            {...control}
            type="password"
            autoComplete="new-password"
            maxLength={64}
            value={repeat}
            onChange={(e) => {
              setRepeat(e.target.value);
            }}
          />
        )}
      </Field>
      <DialogFooter className="sm:justify-between">
        {device.uninstallCodeSet ? (
          <Button
            type="button"
            variant="ghost"
            className="text-destructive hover:text-destructive"
            disabled={save.isPending}
            onClick={() => {
              save.mutate(null);
            }}
          >
            Remove the code
          </Button>
        ) : (
          <span />
        )}
        <div className="flex gap-2">
          <Button type="submit" disabled={save.isPending}>
            {save.isPending ? 'Sending…' : 'Set code'}
          </Button>
        </div>
      </DialogFooter>
    </form>
  );
}

function RebootForm({ device, onDone }: { device: DeviceDetail; onDone: () => void }) {
  const [delay, setDelay] = useState(300);
  const [notify, setNotify] = useState(true);
  const reboot = useMutation({
    mutationFn: () => devicesApi.reboot(device.id, { delaySeconds: delay, notifyUser: notify }),
    onSuccess: () => {
      notifySuccess(device.isOnline ? 'Restart requested' : 'Restart queued until the device reconnects');
      onDone();
    },
    onError: notifyError,
  });
  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        reboot.mutate();
      }}
    >
      <DialogHeader>
        <DialogTitle>Restart {device.hostname}?</DialogTitle>
        <DialogDescription>
          {device.consoleUser
            ? `${device.consoleUser} is logged in. Unsaved work on the computer may be lost.`
            : 'Nobody is logged in at the console right now.'}
        </DialogDescription>
      </DialogHeader>
      <Field label="When">
        {(control) => (
          <NativeSelect
            {...control}
            className="w-full"
            value={String(delay)}
            onChange={(e) => {
              setDelay(Number(e.target.value));
            }}
          >
            {DELAYS.map((d) => (
              <NativeSelectOption key={d.seconds} value={String(d.seconds)}>
                {d.label}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        )}
      </Field>
      <div className="flex items-start gap-2">
        <Checkbox
          id="reboot-notify"
          checked={notify}
          onCheckedChange={(v) => setNotify(v === true)}
          className="mt-0.5"
        />
        <Label htmlFor="reboot-notify" className="leading-5 font-normal">
          Tell the person at the computer before it restarts
        </Label>
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={reboot.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant="destructive" disabled={reboot.isPending}>
          <Power aria-hidden="true" />
          {reboot.isPending ? 'Requesting…' : 'Restart'}
        </Button>
      </DialogFooter>
    </form>
  );
}

function UninstallConfirm({
  device,
  open,
  onOpenChange,
}: {
  device: DeviceDetail;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const queryClient = useQueryClient();
  const uninstall = useMutation({
    mutationFn: () => devicesApi.uninstallAgent(device.id),
    onSuccess: async () => {
      notifySuccess('Uninstall requested. The device is revoked once the agent confirms it removed itself.');
      onOpenChange(false);
      await queryClient.invalidateQueries({ queryKey: qk.deviceDetail(device.id) });
    },
    onError: notifyError,
  });
  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={`Uninstall the agent from ${device.hostname}?`}
      description={
        <>
          <p>
            The agent removes itself from the computer and its certificate is revoked. The computer is no longer managed
            until it is enrolled again with a new token.
          </p>
          <p>You will be asked for your authenticator code.</p>
        </>
      }
      confirmLabel="Uninstall agent"
      destructive
      typeToConfirm={device.hostname}
      pending={uninstall.isPending}
      onConfirm={() => {
        uninstall.mutate();
      }}
    />
  );
}
