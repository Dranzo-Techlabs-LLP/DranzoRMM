import { useMutation, useQueryClient } from '@tanstack/react-query';
import { KeyRound, LogOut } from 'lucide-react';
import { useState, type SyntheticEvent } from 'react';
import { useNavigate } from 'react-router';
import { Field } from '@/components/field';
import { PageHeader, Panel } from '@/components/page';
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
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { authApi, errorMessage, isApiError, qk } from '@/lib/api';
import { clearSession, useMe } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { RecoveryCodesList } from './RecoveryCodesList';

function scopeLabel(scopeType: string): string {
  return scopeType === 'Partner' ? 'all organizations' : `one ${scopeType.toLowerCase()}`;
}

export default function AccountPage() {
  useDocumentTitle('Account');
  const me = useMe();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const minLength = me.passwordMinLength ?? 12;

  const change = useMutation({
    mutationFn: () => authApi.changePassword(current, next),
    onSuccess: async () => {
      setCurrent('');
      setNext('');
      setConfirm('');
      setSubmitted(false);
      notifySuccess('Password changed');
      await queryClient.invalidateQueries({ queryKey: qk.me });
    },
  });

  const signOut = useMutation({
    mutationFn: () => authApi.logout(),
    onSettled: () => {
      clearSession(queryClient, { explicit: true });
      void navigate('/login', { replace: true });
    },
  });

  const tooShort = next.length < minLength;
  const mismatch = next !== confirm;
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setSubmitted(true);
    if (!current || tooShort || mismatch) {
      return;
    }
    change.mutate();
  };
  const serverError =
    change.error && !(isApiError(change.error) && change.error.code === 'unauthenticated')
      ? errorMessage(change.error)
      : null;

  return (
    <div className="max-w-3xl">
      <PageHeader title="Account" description="Your sign-in details and access." />
      {me.user.mustChangePassword ? (
        <InlineAlert tone="warn" title="Set a new password to continue" className="mb-4" live={false}>
          You signed in with a temporary password. Choose your own before using the dashboard.
        </InlineAlert>
      ) : null}
      <div className="grid gap-4">
        <Panel title="Profile">
          <dl className="grid grid-cols-[8rem_1fr] gap-x-4 gap-y-2">
            <dt className="text-muted-foreground">Name</dt>
            <dd>{me.user.displayName}</dd>
            <dt className="text-muted-foreground">Email</dt>
            <dd className="break-all">{me.user.email}</dd>
            <dt className="text-muted-foreground">Company</dt>
            <dd>{me.partner.name}</dd>
            <dt className="text-muted-foreground">Roles</dt>
            <dd>
              {me.roles.length === 0 ? (
                <span className="text-muted-foreground">No roles assigned. Ask a Partner Admin for access.</span>
              ) : (
                <ul className="space-y-0.5">
                  {me.roles.map((r, i) => (
                    <li key={`${r.name}-${r.scopeType}-${r.scopeId ?? i}`}>
                      {r.name} <span className="text-muted-foreground">for {scopeLabel(r.scopeType)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </dd>
            <dt className="text-muted-foreground">Two-step sign-in</dt>
            <dd>On for every account. A Partner Admin can reset your authenticator if you lose it.</dd>
          </dl>
        </Panel>

        <Panel title="Change password">
          <form onSubmit={submit} noValidate className="grid max-w-sm gap-4">
            <div aria-live="assertive" className="empty:hidden">
              {serverError ? <InlineAlert live={false}>{serverError}</InlineAlert> : null}
            </div>
            <Field label="Current password" error={submitted && !current ? 'Enter your current password.' : null}>
              {(control) => (
                <Input
                  {...control}
                  type="password"
                  autoComplete="current-password"
                  maxLength={128}
                  value={current}
                  onChange={(e) => {
                    setCurrent(e.target.value);
                  }}
                />
              )}
            </Field>
            <Field
              label="New password"
              hint={`At least ${minLength} characters. A long phrase works well.`}
              error={submitted && tooShort ? `Use at least ${minLength} characters.` : null}
            >
              {(control) => (
                <Input
                  {...control}
                  type="password"
                  autoComplete="new-password"
                  maxLength={128}
                  value={next}
                  onChange={(e) => {
                    setNext(e.target.value);
                  }}
                />
              )}
            </Field>
            <Field label="Repeat new password" error={submitted && mismatch ? 'The two passwords do not match.' : null}>
              {(control) => (
                <Input
                  {...control}
                  type="password"
                  autoComplete="new-password"
                  maxLength={128}
                  value={confirm}
                  onChange={(e) => {
                    setConfirm(e.target.value);
                  }}
                />
              )}
            </Field>
            <div>
              <Button type="submit" disabled={change.isPending}>
                {change.isPending ? 'Changing…' : 'Change password'}
              </Button>
            </div>
          </form>
        </Panel>

        {me.user.mustChangePassword ? null : <RecoveryCodesPanel />}

        <Panel title="Session">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-muted-foreground max-w-[60ch]">
              You are signed out automatically after {me.sessionIdleMinutes} minutes without activity.
            </p>
            <Button
              variant="outline"
              onClick={() => {
                signOut.mutate();
              }}
              disabled={signOut.isPending}
            >
              <LogOut aria-hidden="true" />
              Sign out
            </Button>
          </div>
        </Panel>
      </div>
    </div>
  );
}

/** New recovery codes replace the old set. The server needs a fresh authenticator code; the client asks for it. */
function RecoveryCodesPanel() {
  const [codes, setCodes] = useState<string[] | null>(null);
  const [saved, setSaved] = useState(false);
  const regenerate = useMutation({
    mutationFn: () => authApi.regenerateRecoveryCodes(),
    onSuccess: (result) => {
      setSaved(false);
      setCodes(result.recoveryCodes);
    },
    onError: notifyError,
  });
  return (
    <Panel title="Recovery codes">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-muted-foreground max-w-[60ch]">
          A recovery code lets you sign in if you lose your authenticator. Make a new set if you used most of yours or
          think someone else has seen them. The old codes stop working at once.
        </p>
        <Button
          variant="outline"
          disabled={regenerate.isPending}
          onClick={() => {
            regenerate.mutate();
          }}
        >
          <KeyRound aria-hidden="true" />
          {regenerate.isPending ? 'Making new codes…' : 'Make new recovery codes'}
        </Button>
      </div>
      <Dialog
        open={codes !== null}
        onOpenChange={(open) => {
          if (!open && saved) {
            setCodes(null);
          }
        }}
      >
        <DialogContent
          className="sm:max-w-md"
          showCloseButton={false}
          // The codes are shown once; the dialog closes only after the user confirms they saved them.
          onInteractOutside={(e) => {
            e.preventDefault();
          }}
          onEscapeKeyDown={(e) => {
            if (!saved) {
              e.preventDefault();
            }
          }}
        >
          <DialogHeader>
            <DialogTitle>Your new recovery codes</DialogTitle>
            <DialogDescription>
              Each code works once. They are shown only now; your previous codes no longer work.
            </DialogDescription>
          </DialogHeader>
          {codes ? <RecoveryCodesList codes={codes} /> : null}
          <div className="flex items-start gap-2">
            <Checkbox
              id="new-codes-saved"
              checked={saved}
              onCheckedChange={(v) => {
                setSaved(v === true);
              }}
              className="mt-0.5"
            />
            <Label htmlFor="new-codes-saved" className="leading-5 font-normal">
              I saved these codes somewhere safe
            </Label>
          </div>
          <DialogFooter>
            <Button
              disabled={!saved}
              onClick={() => {
                setCodes(null);
                notifySuccess('New recovery codes saved');
              }}
            >
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Panel>
  );
}
