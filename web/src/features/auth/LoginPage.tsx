import { useQueryClient } from '@tanstack/react-query';
import { KeyRound } from 'lucide-react';
import { useEffect, useRef, useState, type SyntheticEvent, type ReactNode } from 'react';
import { Navigate, useNavigate, useSearchParams } from 'react-router';
import { CopyButton } from '@/components/copy-button';
import { Field } from '@/components/field';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { qk } from '@/lib/api';
import { safeReturnTo, useMeQuery } from '@/lib/auth/session';
import { Brand } from './Brand';
import { CodeInput } from './CodeInput';
import { isCompleteTotp } from './login-machine';
import { QrCode } from './QrCode';
import { RecoveryCodesList } from './RecoveryCodesList';
import { useLoginFlow, type LoginFlow } from './use-login-flow';

export default function LoginPage() {
  const [params] = useSearchParams();
  const returnTo = safeReturnTo(params.get('returnTo'));
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const me = useMeQuery();
  const flow = useLoginFlow();
  const step = flow.state.step;

  // The "signed out on purpose" marker has done its job once the sign-in page is showing.
  useEffect(() => {
    queryClient.removeQueries({ queryKey: qk.signedOut });
  }, [queryClient]);

  // Signed in: load the profile (which also confirms the cookie works) and leave the sign-in page.
  useEffect(() => {
    if (step !== 'done') {
      return;
    }
    let cancelled = false;
    void queryClient.refetchQueries({ queryKey: qk.me }).finally(() => {
      if (!cancelled) {
        void navigate(returnTo, { replace: true });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [step, navigate, queryClient, returnTo]);

  // Already signed in and not in the middle of the flow (recovery codes must stay on screen until acknowledged).
  if (me.data && step === 'credentials') {
    return <Navigate to={returnTo} replace />;
  }

  return (
    <div className="flex min-h-dvh flex-col items-center px-4 py-10 sm:justify-center">
      <main className="w-full max-w-[26rem]">
        <Brand className="mb-6" />
        <div className="bg-card rounded-lg border p-6 shadow-xs">
          {step === 'credentials' ? <CredentialsStep flow={flow} /> : null}
          {step === 'mfa' ? <MfaStep flow={flow} /> : null}
          {step === 'enroll' ? <EnrollStep flow={flow} /> : null}
          {step === 'recovery-codes' ? <RecoveryCodesStep flow={flow} /> : null}
          {step === 'done' ? (
            <p role="status" className="text-muted-foreground">
              Signing you in…
            </p>
          ) : null}
        </div>
        <p className="text-muted-foreground mt-4 text-xs">
          Sign-ins and every administrative action are recorded in the audit log.
        </p>
      </main>
    </div>
  );
}

function StepHeading({ title, children }: { title: string; children?: ReactNode }) {
  const ref = useRef<HTMLHeadingElement>(null);
  // Each step replaces the previous one; move focus so keyboard and screen-reader users land on the new step.
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return (
    <div className="mb-5">
      <h1 ref={ref} tabIndex={-1} className="text-lg font-semibold tracking-tight outline-none">
        {title}
      </h1>
      {children ? <p className="text-muted-foreground mt-1">{children}</p> : null}
    </div>
  );
}

function FlowError({ flow }: { flow: LoginFlow }) {
  return (
    <div aria-live="assertive" className="empty:hidden">
      {flow.error ? (
        <InlineAlert live={false} className="mb-4">
          {flow.error}
        </InlineAlert>
      ) : null}
    </div>
  );
}

function CredentialsStep({ flow }: { flow: LoginFlow }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const notice = flow.state.step === 'credentials' ? flow.state.notice : undefined;
  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    void flow.submitCredentials(email, password);
  };
  return (
    <form onSubmit={submit} noValidate>
      <StepHeading title="Sign in" />
      {notice && !flow.error ? (
        <InlineAlert tone="warn" className="mb-4">
          {notice}
        </InlineAlert>
      ) : null}
      <FlowError flow={flow} />
      <div className="grid gap-4">
        <Field label="Email">
          {(control) => (
            <Input
              {...control}
              type="email"
              name="email"
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
              maxLength={254}
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
              }}
            />
          )}
        </Field>
        <Field label="Password">
          {(control) => (
            <Input
              {...control}
              type="password"
              name="password"
              autoComplete="current-password"
              required
              maxLength={128}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
            />
          )}
        </Field>
        <Button type="submit" disabled={flow.pending || !email.trim() || !password}>
          {flow.pending ? 'Checking…' : 'Continue'}
        </Button>
      </div>
    </form>
  );
}

function MfaStep({ flow }: { flow: LoginFlow }) {
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState('');
  const method = flow.state.step === 'mfa' ? flow.state.method : 'code';

  if (method === 'recovery') {
    return (
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void flow.submitRecoveryCode(recovery);
        }}
        noValidate
      >
        <StepHeading title="Use a recovery code">
          Enter one of the recovery codes you saved when you set up your authenticator. Each code works once.
        </StepHeading>
        <FlowError flow={flow} />
        <div className="grid gap-4">
          <Field label="Recovery code">
            {(control) => (
              <Input
                {...control}
                className="ident"
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                maxLength={64}
                value={recovery}
                onChange={(e) => {
                  setRecovery(e.target.value);
                }}
              />
            )}
          </Field>
          <Button type="submit" disabled={flow.pending || recovery.trim().length < 6}>
            {flow.pending ? 'Checking…' : 'Sign in'}
          </Button>
        </div>
        <div className="mt-4 flex flex-wrap justify-between gap-2">
          <Button type="button" variant="link" className="h-auto p-0" onClick={flow.switchToAuthenticator}>
            Use my authenticator app
          </Button>
          <Button type="button" variant="link" className="h-auto p-0" onClick={flow.restart}>
            Start again
          </Button>
        </div>
      </form>
    );
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        void flow.submitCode(code).then(() => {
          setCode('');
        });
      }}
      noValidate
    >
      <StepHeading title="Enter your authenticator code">
        Open your authenticator app and enter the 6-digit code for DranzoRMM.
      </StepHeading>
      <FlowError flow={flow} />
      <div className="grid gap-4">
        <Field label="Authenticator code">
          {(control) => <CodeInput {...control} value={code} onValueChange={setCode} autoFocus />}
        </Field>
        <Button type="submit" disabled={flow.pending || !isCompleteTotp(code)}>
          {flow.pending ? 'Checking…' : 'Sign in'}
        </Button>
      </div>
      <div className="mt-4 flex flex-wrap justify-between gap-2">
        <Button type="button" variant="link" className="h-auto p-0" onClick={flow.switchToRecoveryCode}>
          <KeyRound aria-hidden="true" />
          Use a recovery code
        </Button>
        <Button type="button" variant="link" className="h-auto p-0" onClick={flow.restart}>
          Start again
        </Button>
      </div>
    </form>
  );
}

function EnrollStep({ flow }: { flow: LoginFlow }) {
  const [code, setCode] = useState('');
  const state = flow.state.step === 'enroll' ? flow.state : null;
  const secret = state?.secret ?? null;
  const uri = state?.otpauthUri ?? null;

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        void flow.submitEnrollmentCode(code).then(() => {
          setCode('');
        });
      }}
      noValidate
    >
      <StepHeading title="Set up two-step sign-in">
        Every account uses an authenticator app. Scan the code with an app such as Microsoft Authenticator, Google
        Authenticator or 1Password, then enter the 6-digit code it shows.
      </StepHeading>
      <FlowError flow={flow} />
      {secret && uri ? (
        <div className="grid gap-4">
          <div className="flex justify-center">
            <QrCode value={uri} label="QR code for your authenticator app" />
          </div>
          <div className="grid gap-1.5">
            <p className="text-xs font-medium">Cannot scan? Enter this key in the app instead</p>
            <div className="flex items-center gap-2">
              <code className="ident bg-muted min-w-0 flex-1 rounded-md px-2 py-1.5 break-all select-all">
                {secret.replace(/(.{4})/g, '$1 ').trim()}
              </code>
              <CopyButton value={secret} label="Copy key" />
            </div>
          </div>
          <Field label="Code from the app">
            {(control) => <CodeInput {...control} value={code} onValueChange={setCode} />}
          </Field>
          <Button type="submit" disabled={flow.pending || !isCompleteTotp(code)}>
            {flow.pending ? 'Checking…' : 'Turn on two-step sign-in'}
          </Button>
        </div>
      ) : flow.error ? null : (
        <div role="status" aria-label="Preparing setup" className="grid gap-3">
          <Skeleton className="mx-auto size-[184px]" />
          <Skeleton className="h-8 w-full" />
        </div>
      )}
      <div className="mt-4">
        <Button type="button" variant="link" className="h-auto p-0" onClick={flow.restart}>
          Start again
        </Button>
      </div>
    </form>
  );
}

function RecoveryCodesStep({ flow }: { flow: LoginFlow }) {
  const [saved, setSaved] = useState(false);
  const codes = flow.state.step === 'recovery-codes' ? flow.state.codes : [];
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (saved) {
          flow.confirmRecoveryCodesSaved();
        }
      }}
    >
      <StepHeading title="Save your recovery codes">
        If you lose your phone, a recovery code is the only way to sign in without an administrator. Each code works
        once. They are shown only now.
      </StepHeading>
      <RecoveryCodesList codes={codes} />
      <div className="mb-4 flex items-start gap-2">
        <Checkbox
          id="codes-saved"
          checked={saved}
          onCheckedChange={(v) => {
            setSaved(v === true);
          }}
          className="mt-0.5"
        />
        <Label htmlFor="codes-saved" className="leading-5 font-normal">
          I saved these codes somewhere safe
        </Label>
      </div>
      <Button type="submit" disabled={!saved} className="w-full">
        Continue to the dashboard
      </Button>
    </form>
  );
}
