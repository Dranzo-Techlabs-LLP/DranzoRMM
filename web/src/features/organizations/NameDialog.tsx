import { useState, type SyntheticEvent, type ReactNode } from 'react';
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
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { errorMessage, UPDATE_RINGS, type UpdateRing } from '@/lib/api';
import { RING } from './consent';

export interface NameDialogValue {
  name: string;
  updateRing: UpdateRing;
}

/** Small create/rename dialog for sites and device groups. Groups also choose an update ring. */
export function NameDialog({
  open,
  onOpenChange,
  title,
  description,
  submitLabel,
  initialName = '',
  initialRing,
  pending,
  error,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  submitLabel: string;
  initialName?: string;
  /** Pass a ring to show the update-ring choice (device groups). */
  initialRing?: UpdateRing;
  pending: boolean;
  error: unknown;
  onSubmit: (value: NameDialogValue) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        {open ? (
          <NameForm
            title={title}
            description={description}
            submitLabel={submitLabel}
            initialName={initialName}
            initialRing={initialRing}
            pending={pending}
            error={error}
            onSubmit={onSubmit}
            onCancel={() => {
              onOpenChange(false);
            }}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function NameForm({
  title,
  description,
  submitLabel,
  initialName,
  initialRing,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  title: string;
  description?: ReactNode;
  submitLabel: string;
  initialName: string;
  initialRing?: UpdateRing;
  pending: boolean;
  error: unknown;
  onSubmit: (value: NameDialogValue) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(initialName);
  const [ring, setRing] = useState<UpdateRing>(initialRing ?? 'all');
  const [touched, setTouched] = useState(false);
  const trimmed = name.trim();
  const nameError =
    touched && !trimmed ? 'Enter a name.' : trimmed.length > 120 ? 'Use 120 characters or fewer.' : null;

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!trimmed || trimmed.length > 120) {
      return;
    }
    onSubmit({ name: trimmed, updateRing: ring });
  };

  return (
    <form onSubmit={submit} noValidate className="grid gap-4">
      <DialogHeader>
        <DialogTitle>{title}</DialogTitle>
        {description ? <DialogDescription>{description}</DialogDescription> : null}
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {error ? <InlineAlert live={false}>{errorMessage(error)}</InlineAlert> : null}
      </div>
      <Field label="Name" error={nameError}>
        {(control) => (
          <Input
            {...control}
            value={name}
            maxLength={120}
            autoComplete="off"
            autoFocus
            onChange={(e) => {
              setName(e.target.value);
            }}
          />
        )}
      </Field>
      {initialRing !== undefined ? (
        <Field label="Agent update ring" hint={RING[ring].explanation}>
          {(control) => (
            <NativeSelect
              {...control}
              value={ring}
              onChange={(e) => {
                setRing(e.target.value as UpdateRing);
              }}
            >
              {UPDATE_RINGS.map((r) => (
                <NativeSelectOption key={r} value={r}>
                  {RING[r].label}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        </Field>
      ) : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel} disabled={pending}>
          Cancel
        </Button>
        <Button type="submit" disabled={pending}>
          {pending ? 'Saving…' : submitLabel}
        </Button>
      </DialogFooter>
    </form>
  );
}
