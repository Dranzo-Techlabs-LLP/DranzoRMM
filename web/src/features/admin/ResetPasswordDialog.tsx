import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Dices } from 'lucide-react';
import { useState, type SyntheticEvent } from 'react';
import { CopyButton } from '@/components/copy-button';
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
import { errorMessage, isApiError, qk, usersApi, type User } from '@/lib/api';
import { useMe } from '@/lib/auth/session';
import { notifySuccess } from '@/lib/notify';
import { generateTemporaryPassword } from './CreateUserDialog';

/** Sets a temporary password for another user. They are signed out everywhere and must change it at next sign-in. */
export function ResetPasswordDialog({
  user,
  onOpenChange,
  onCloseAutoFocus,
}: {
  user: User | null;
  onOpenChange: (open: boolean) => void;
  onCloseAutoFocus?: (event: Event) => void;
}) {
  return (
    <Dialog open={user !== null} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg" onCloseAutoFocus={onCloseAutoFocus}>
        {user ? (
          <ResetForm
            key={user.id}
            user={user}
            onDone={() => {
              onOpenChange(false);
            }}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function ResetForm({ user, onDone }: { user: User; onDone: () => void }) {
  const queryClient = useQueryClient();
  const minLength = useMe().passwordMinLength ?? 12;
  const [password, setPassword] = useState(() => generateTemporaryPassword());
  const [touched, setTouched] = useState(false);
  const valid = password.length >= minLength && password.length <= 128;

  const reset = useMutation({
    mutationFn: () => usersApi.resetPassword(user.id, password),
    onSuccess: async () => {
      notifySuccess(`Temporary password set for ${user.displayName}. They were signed out everywhere.`);
      await queryClient.invalidateQueries({ queryKey: qk.users });
      onDone();
    },
  });
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (valid) {
      reset.mutate();
    }
  };
  const error =
    reset.error && !(isApiError(reset.error) && reset.error.code === 'step_up_cancelled')
      ? errorMessage(reset.error)
      : null;

  return (
    <form onSubmit={submit} noValidate className="grid gap-4">
      <DialogHeader>
        <DialogTitle>Temporary password for {user.displayName}</DialogTitle>
        <DialogDescription>
          Their current password stops working and they are signed out everywhere. At the next sign-in they enter this
          password, then must choose their own. Their authenticator app is not changed. You will be asked for your
          authenticator code.
        </DialogDescription>
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {error ? <InlineAlert live={false}>{error}</InlineAlert> : null}
      </div>
      <Field
        label="Temporary password"
        hint={`At least ${minLength} characters. Copy it now and pass it on over a channel you trust: it is not shown again.`}
        error={touched && !valid ? `Use ${minLength} to 128 characters.` : null}
      >
        {(control) => (
          <div className="flex gap-2">
            <Input
              {...control}
              className="ident"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              maxLength={128}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
            />
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setPassword(generateTemporaryPassword());
              }}
            >
              <Dices aria-hidden="true" />
              New
            </Button>
            <CopyButton value={password} size="default" />
          </div>
        )}
      </Field>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={reset.isPending}>
          Cancel
        </Button>
        <Button type="submit" variant="destructive" disabled={reset.isPending}>
          {reset.isPending ? 'Setting…' : 'Set temporary password'}
        </Button>
      </DialogFooter>
    </form>
  );
}
