import { useId, useState, type ReactNode } from 'react';
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

/**
 * Confirmation for destructive or hard-to-undo actions. With `typeToConfirm` the user must type that exact text
 * (for example the organization's name) before the action is enabled.
 */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive = false,
  typeToConfirm,
  pending = false,
  onConfirm,
  onCloseAutoFocus,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  typeToConfirm?: string;
  pending?: boolean;
  onConfirm: () => void;
  /** Where focus goes when the dialog closes; see `useReturnFocus` for dialogs opened from a row menu. */
  onCloseAutoFocus?: (event: Event) => void;
}) {
  const inputId = useId();
  const [typed, setTyped] = useState('');
  const matches = typeToConfirm === undefined || typed.trim() === typeToConfirm;

  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          setTyped('');
        }
        onOpenChange(next);
      }}
    >
      <AlertDialogContent onCloseAutoFocus={onCloseAutoFocus}>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (matches && !pending) {
              onConfirm();
            }
          }}
        >
          <AlertDialogHeader>
            <AlertDialogTitle>{title}</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="text-muted-foreground space-y-2 text-sm">{description}</div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          {typeToConfirm !== undefined ? (
            <div className="grid gap-1.5">
              <Label htmlFor={inputId}>
                Type <span className="font-semibold select-all">{typeToConfirm}</span> to confirm
              </Label>
              <Input
                id={inputId}
                value={typed}
                onChange={(e) => {
                  setTyped(e.target.value);
                }}
                autoComplete="off"
                spellCheck={false}
                autoFocus
              />
            </div>
          ) : null}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={pending}>Cancel</AlertDialogCancel>
            <Button type="submit" variant={destructive ? 'destructive' : 'default'} disabled={!matches || pending}>
              {pending ? 'Working…' : confirmLabel}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  );
}
