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
import { errorMessage, qk, usersApi } from '@/lib/api';
import { useMe } from '@/lib/auth/session';
import { notifySuccess } from '@/lib/notify';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

/** Random temporary password from the platform CSPRNG; ambiguous characters (0/O, 1/l/I) are left out. */
// eslint-disable-next-line react-refresh/only-export-components
export function generateTemporaryPassword(length = 20): string {
  const out: string[] = [];
  const limit = 256 - (256 % ALPHABET.length); // rejection sampling keeps the distribution uniform
  while (out.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length * 2));
    for (const b of bytes) {
      if (b < limit && out.length < length) {
        out.push(ALPHABET.charAt(b % ALPHABET.length));
      }
    }
  }
  return (out.join('').match(/.{1,5}/g) ?? []).join('-');
}

export function CreateUserDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        {open ? (
          <CreateUserForm
            onDone={() => {
              onOpenChange(false);
            }}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function CreateUserForm({ onDone }: { onDone: () => void }) {
  const queryClient = useQueryClient();
  const minLength = useMe().passwordMinLength ?? 12;
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [touched, setTouched] = useState(false);

  const emailValid = /^\S+@\S+$/.test(email.trim()) && email.trim().length <= 254;
  const nameValid = displayName.trim().length > 0 && displayName.trim().length <= 120;
  const passwordValid = password.length >= minLength && password.length <= 128;

  const create = useMutation({
    mutationFn: () => usersApi.create({ email: email.trim(), displayName: displayName.trim(), password }),
    onSuccess: async () => {
      notifySuccess('User created. Give them a role so they can see something.');
      await queryClient.invalidateQueries({ queryKey: qk.users });
      onDone();
    },
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (emailValid && nameValid && passwordValid) {
      create.mutate();
    }
  };

  return (
    <form onSubmit={submit} noValidate className="grid gap-4">
      <DialogHeader>
        <DialogTitle>New user</DialogTitle>
        <DialogDescription>
          The user signs in with the temporary password, sets up an authenticator app, and must then choose their own
          password. New users have no access until you assign a role.
        </DialogDescription>
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {create.error ? <InlineAlert live={false}>{errorMessage(create.error)}</InlineAlert> : null}
      </div>
      <Field label="Email" error={touched && !emailValid ? 'Enter a valid email address.' : null}>
        {(control) => (
          <Input
            {...control}
            type="email"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            maxLength={254}
            autoFocus
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
            }}
          />
        )}
      </Field>
      <Field label="Name" error={touched && !nameValid ? 'Enter the person’s name.' : null}>
        {(control) => (
          <Input
            {...control}
            autoComplete="off"
            maxLength={120}
            value={displayName}
            onChange={(e) => {
              setDisplayName(e.target.value);
            }}
          />
        )}
      </Field>
      <Field
        label="Temporary password"
        hint={`At least ${minLength} characters. Pass it to the user over a channel you trust; it is not shown again after you close this dialog.`}
        error={touched && !passwordValid ? `Use ${minLength} to 128 characters.` : null}
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
              Generate
            </Button>
            {password ? <CopyButton value={password} size="default" /> : null}
          </div>
        )}
      </Field>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={create.isPending}>
          Cancel
        </Button>
        <Button type="submit" disabled={create.isPending}>
          {create.isPending ? 'Creating…' : 'Create user'}
        </Button>
      </DialogFooter>
    </form>
  );
}
