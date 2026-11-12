import { ShieldCheck } from 'lucide-react';
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Field } from '@/components/field';
import { api, authApi, errorMessage, isApiError } from '@/lib/api';
import { CodeInput } from './CodeInput';
import { isCompleteTotp } from './login-machine';

/**
 * Step-up re-authentication. The API client calls `requestStepUp` when a request is answered with
 * `401 step_up_required`; this dialog collects the authenticator code, calls `POST /auth/step-up`, and resolves the
 * promise so the client can retry the original request.
 */
export function StepUpProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState('');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const resolver = useRef<((ok: boolean) => void) | null>(null);

  const finish = useCallback((ok: boolean) => {
    resolver.current?.(ok);
    resolver.current = null;
    setOpen(false);
    setCode('');
    setError(null);
    setPending(false);
  }, []);

  useEffect(() => {
    const remove = api.configure({
      requestStepUp: () =>
        new Promise<boolean>((resolve) => {
          resolver.current?.(false);
          resolver.current = resolve;
          setOpen(true);
        }),
    });
    return () => {
      remove();
      resolver.current?.(false);
      resolver.current = null;
    };
  }, []);

  const submit = async () => {
    if (!isCompleteTotp(code) || pending) {
      return;
    }
    setPending(true);
    setError(null);
    try {
      await authApi.stepUp(code);
      finish(true);
    } catch (e) {
      if (isApiError(e) && e.code === 'unauthenticated') {
        finish(false);
        return;
      }
      setPending(false);
      setCode('');
      setError(
        isApiError(e) && e.code === 'invalid_code'
          ? 'That code was not accepted. Wait for a new code in your authenticator app and try again.'
          : errorMessage(e),
      );
    }
  };

  return (
    <>
      {children}
      <Dialog
        open={open}
        onOpenChange={(next) => {
          if (!next) {
            finish(false);
          }
        }}
      >
        <DialogContent className="sm:max-w-md">
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
          >
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <ShieldCheck aria-hidden="true" className="size-5" />
                Confirm it is you
              </DialogTitle>
              <DialogDescription>
                This action needs a fresh check. Enter the 6-digit code from your authenticator app to continue.
              </DialogDescription>
            </DialogHeader>
            <Field label="Authenticator code" error={error}>
              {(control) => <CodeInput {...control} value={code} onValueChange={setCode} autoFocus />}
            </Field>
            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  finish(false);
                }}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={!isCompleteTotp(code) || pending}>
                {pending ? 'Checking…' : 'Confirm and continue'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}
