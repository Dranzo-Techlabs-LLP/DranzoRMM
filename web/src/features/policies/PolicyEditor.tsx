import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type SyntheticEvent } from 'react';
import { Field } from '@/components/field';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { FIREWALL_RULES_CHECK } from './firewall-rules';
import { FirewallRulesEditor } from './FirewallRulesEditor';
import { errorMessage, isApiError, type Organization } from '@/lib/api';
import { policiesApi, policyKeys, type Policy } from '@/lib/api/policies';
import { osLabel } from '@/lib/os';
import { notifySuccess } from '@/lib/notify';
import {
  availableOs,
  checkDescription,
  checkLabel,
  checkRemediation,
  MAX_INTERVAL_MINUTES,
  MIN_INTERVAL_MINUTES,
  policyToForm,
  SCRIPT_CHECK,
  SCRIPT_LANGUAGES,
  validatePolicy,
  type PolicyForm,
} from './policy-params';

/** Create or edit one policy. The check and the organization are fixed once a policy exists (server rule). */
export function PolicyEditor({
  policy,
  checks,
  organizations,
  partnerWide,
  onDone,
}: {
  policy: Policy | null;
  checks: Record<string, string[]>;
  organizations: Organization[];
  partnerWide: boolean;
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const checkIds = Object.keys(checks);
  const [form, setForm] = useState<PolicyForm>(() =>
    policyToForm(policy, {
      check: checkIds.find((c) => c !== SCRIPT_CHECK) ?? checkIds[0] ?? '',
      organizationId: partnerWide ? '' : (organizations[0]?.id ?? ''),
    }),
  );
  const [touched, setTouched] = useState(false);
  const set = (patch: Partial<PolicyForm>) => {
    setForm((old) => ({ ...old, ...patch }));
  };
  const creating = policy === null;
  const checked = validatePolicy(form, checks, creating);
  const errors = touched && !checked.ok ? checked.errors : {};
  const scopeValid = !creating || partnerWide || form.organizationId !== '';
  const os = availableOs(form, checks);
  const remediation = checkRemediation(form.check);
  const isScript = form.check === SCRIPT_CHECK;

  const save = useMutation({
    mutationFn: async () => {
      if (!checked.ok) {
        return;
      }
      if (policy) {
        await policiesApi.update(policy.id, checked.input);
      } else {
        await policiesApi.create(checked.input);
      }
    },
    onSuccess: async () => {
      notifySuccess(
        creating ? 'Policy created. Assign it to organizations, sites or groups to apply it.' : 'Policy saved',
      );
      await queryClient.invalidateQueries({ queryKey: policyKeys.list });
      onDone();
    },
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (checked.ok && scopeValid) {
      save.mutate();
    }
  };
  const serverError =
    save.error && !(isApiError(save.error) && save.error.code === 'step_up_cancelled')
      ? errorMessage(save.error)
      : null;

  return (
    <form onSubmit={submit} noValidate className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <DialogHeader>
        <DialogTitle>{creating ? 'New policy' : `Edit ${policy.name}`}</DialogTitle>
        <DialogDescription>
          A policy is a desired state that devices are checked against on a schedule. It applies to the devices of the
          organizations, sites or groups you assign it to.
        </DialogDescription>
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {serverError ? <InlineAlert live={false}>{serverError}</InlineAlert> : null}
      </div>
      <Field label="Name" error={errors.name ?? null}>
        {(control) => (
          <Input
            {...control}
            value={form.name}
            maxLength={120}
            autoComplete="off"
            autoFocus
            onChange={(e) => {
              set({ name: e.target.value });
            }}
          />
        )}
      </Field>
      <Field label="Description (optional)" error={errors.description ?? null}>
        {(control) => (
          <Textarea
            {...control}
            rows={2}
            maxLength={1000}
            value={form.description}
            onChange={(e) => {
              set({ description: e.target.value });
            }}
          />
        )}
      </Field>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Check" hint={checkDescription(form.check)} error={errors.check ?? null}>
          {(control) => (
            <NativeSelect
              {...control}
              className="w-full"
              value={form.check}
              disabled={!creating}
              onChange={(e) => {
                set({ check: e.target.value, osTargets: [], remediate: false });
              }}
            >
              {checkIds.map((c) => (
                <NativeSelectOption key={c} value={c}>
                  {checkLabel(c)} ({(checks[c] ?? []).map(osLabel).join(', ')})
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        </Field>
        <Field
          label="Owned by"
          error={touched && !scopeValid ? 'Choose an organization.' : null}
          hint={
            creating && !partnerWide
              ? 'Policies for all organizations need a role that covers all organizations.'
              : 'An organization’s policy can only be assigned inside that organization.'
          }
        >
          {(control) => (
            <NativeSelect
              {...control}
              className="w-full"
              value={form.organizationId}
              disabled={!creating}
              onChange={(e) => {
                set({ organizationId: e.target.value });
              }}
            >
              {partnerWide || policy?.organizationId === null ? (
                <NativeSelectOption value="">All organizations (shared)</NativeSelectOption>
              ) : null}
              {organizations.map((o) => (
                <NativeSelectOption key={o.id} value={o.id}>
                  {o.name}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        </Field>
      </div>

      {form.check === 'screenlock.timeout' ? (
        <Field
          label="Lock within (seconds)"
          hint="From 30 to 86400. 900 is 15 minutes."
          error={errors.maxSeconds ?? null}
        >
          {(control) => (
            <Input
              {...control}
              className="max-w-40"
              inputMode="numeric"
              maxLength={5}
              value={form.maxSeconds}
              onChange={(e) => {
                set({ maxSeconds: e.target.value });
              }}
            />
          )}
        </Field>
      ) : null}
      {form.check === FIREWALL_RULES_CHECK ? (
        <FirewallRulesEditor
          rules={form.firewallRules}
          error={errors.firewallRules ?? null}
          onChange={(firewallRules) => {
            set({ firewallRules });
          }}
        />
      ) : null}
      {form.check === 'localadmins.allowed' ? (
        <Field
          label="Allowed administrator accounts"
          hint="One account name per line, up to 100. Any other local administrator makes the device non-compliant."
          error={errors.allowed ?? null}
        >
          {(control) => (
            <Textarea
              {...control}
              rows={4}
              className="ident"
              spellCheck={false}
              value={form.allowed}
              onChange={(e) => {
                set({ allowed: e.target.value });
              }}
            />
          )}
        </Field>
      ) : null}
      {form.check === 'password.policy' ? (
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Minimum length" hint="0 to 128." error={errors.minLength ?? null}>
            {(control) => (
              <Input
                {...control}
                inputMode="numeric"
                maxLength={3}
                value={form.minLength}
                onChange={(e) => {
                  set({ minLength: e.target.value });
                }}
              />
            )}
          </Field>
          <Field label="Maximum age (days)" hint="0 means never expires." error={errors.maxAgeDays ?? null}>
            {(control) => (
              <Input
                {...control}
                inputMode="numeric"
                maxLength={3}
                value={form.maxAgeDays}
                onChange={(e) => {
                  set({ maxAgeDays: e.target.value });
                }}
              />
            )}
          </Field>
          <div className="flex items-center gap-2 pt-6">
            <Checkbox
              id="policy-complexity"
              checked={form.complexity}
              onCheckedChange={(v) => {
                set({ complexity: v === true });
              }}
            />
            <Label htmlFor="policy-complexity" className="font-normal">
              Require complex passwords
            </Label>
          </div>
        </div>
      ) : null}
      {isScript ? (
        <>
          <InlineAlert tone="warn" live={false} title="Script policies run with full control of each device">
            The check and remediation scripts run as SYSTEM on Windows and as root on macOS and Linux, on every device
            the policy is assigned to, every time it is evaluated. Saving a script policy asks for your authenticator
            code, and a hash of the scripts is kept in the audit log.
          </InlineAlert>
          <Field label="Language" error={errors.language ?? null}>
            {(control) => (
              <NativeSelect
                {...control}
                className="w-full max-w-72"
                value={form.language}
                onChange={(e) => {
                  set({ language: e.target.value, osTargets: [] });
                }}
              >
                {Object.entries(SCRIPT_LANGUAGES).map(([id, l]) => (
                  <NativeSelectOption key={id} value={id}>
                    {l.label} ({l.os.map(osLabel).join(', ')})
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            )}
          </Field>
          <Field
            label="Check script"
            hint="Exit with code 0 when the device complies, any other code when it does not. The first lines of output are shown as the detail."
            error={errors.checkScript ?? null}
          >
            {(control) => (
              <Textarea
                {...control}
                rows={8}
                className="ident text-xs"
                spellCheck={false}
                autoCapitalize="none"
                value={form.checkScript}
                onChange={(e) => {
                  set({ checkScript: e.target.value });
                }}
              />
            )}
          </Field>
          <Field
            label="Remediation script (optional)"
            hint="Runs when the check fails and automatic fixing is on; the check then runs again."
            error={errors.remediationScript ?? null}
          >
            {(control) => (
              <Textarea
                {...control}
                rows={6}
                className="ident text-xs"
                spellCheck={false}
                autoCapitalize="none"
                value={form.remediationScript}
                onChange={(e) => {
                  set({ remediationScript: e.target.value });
                }}
              />
            )}
          </Field>
        </>
      ) : null}

      <fieldset className="grid gap-2">
        <legend className="mb-1 text-sm font-medium">Operating systems</legend>
        <p className="text-muted-foreground -mt-1 text-xs">
          Leave all unticked to apply to every operating system this check exists on (
          {os.map(osLabel).join(', ') || 'none'}).
        </p>
        <div className="flex flex-wrap gap-4">
          {os.map((o) => (
            <div key={o} className="flex items-center gap-2">
              <Checkbox
                id={`policy-os-${o}`}
                checked={form.osTargets.includes(o)}
                onCheckedChange={(v) => {
                  set({ osTargets: v === true ? [...form.osTargets, o] : form.osTargets.filter((x) => x !== o) });
                }}
              />
              <Label htmlFor={`policy-os-${o}`} className="font-normal">
                {osLabel(o)}
              </Label>
            </div>
          ))}
        </div>
        {errors.osTargets ? (
          <p role="alert" className="text-danger text-xs font-medium">
            {errors.osTargets}
          </p>
        ) : null}
      </fieldset>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field
          label="Check every (minutes)"
          hint={`${MIN_INTERVAL_MINUTES} to ${MAX_INTERVAL_MINUTES}. Only online devices are checked.`}
          error={errors.intervalMinutes ?? null}
        >
          {(control) => (
            <Input
              {...control}
              className="max-w-40"
              inputMode="numeric"
              maxLength={5}
              value={form.intervalMinutes}
              onChange={(e) => {
                set({ intervalMinutes: e.target.value });
              }}
            />
          )}
        </Field>
        <div className="grid content-start gap-3 pt-1">
          <div className="flex items-start gap-2">
            <Switch
              id="policy-remediate"
              checked={form.remediate && remediation !== null}
              disabled={remediation === null}
              onCheckedChange={(v) => {
                set({ remediate: v });
              }}
            />
            <Label htmlFor="policy-remediate" className="grid gap-0.5 font-normal">
              <span>Fix automatically</span>
              <span className="text-muted-foreground text-xs">
                {remediation ?? 'This check only reports; it cannot be fixed remotely.'}
              </span>
            </Label>
          </div>
          <div className="flex items-center gap-2">
            <Switch
              id="policy-enabled"
              checked={form.enabled}
              onCheckedChange={(v) => {
                set({ enabled: v });
              }}
            />
            <Label htmlFor="policy-enabled" className="font-normal">
              Policy is on
            </Label>
          </div>
        </div>
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={save.isPending}>
          Cancel
        </Button>
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? 'Saving…' : creating ? 'Create policy' : 'Save policy'}
        </Button>
      </DialogFooter>
    </form>
  );
}
