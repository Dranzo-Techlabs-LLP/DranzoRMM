import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useId, useState, type SyntheticEvent } from 'react';
import { useNavigate } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Field } from '@/components/field';
import { InlineAlert } from '@/components/status';
import { TargetPicker } from '@/components/target-picker/TargetPicker';
import { TargetPreviewPanel } from '@/components/target-picker/TargetPreview';
import {
  describeTarget,
  deviceTarget,
  emptyTarget,
  targetProblem,
  toTargetRequest,
  type TargetDraft,
} from '@/components/target-picker/target';
import { deviceCountLabel, useTargetPreview } from '@/components/target-picker/use-target-preview';
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
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Skeleton } from '@/components/ui/skeleton';
import { useGroups, useSites } from '@/features/tenants/queries';
import { errorMessage, type Id } from '@/lib/api';
import { jobKeys, jobsApi, type RunAs, type RunScriptInput } from '@/lib/api/jobs';
import { scriptKeys, scriptsApi, type ScriptDetail } from '@/lib/api/scripts';
import { notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import { CRON_PRESETS, describeCron } from './cron';
import {
  buildParameterPayload,
  initialParameterValues,
  languageLabel,
  parseBounded,
  RUN_LIMITS,
  validateParameterValues,
  type ParameterValues,
} from './script-model';

export interface RunDevice {
  id: Id;
  hostname: string;
  os: string;
  organizationId: Id;
}

/**
 * Runs a script: on a target chosen here, or on one given device. With `scriptId` the script is fixed (optionally at
 * an older `version`); without it the user first picks a script that fits the device.
 */
export function RunScriptDialog({
  scriptId,
  version,
  device,
  onClose,
}: {
  scriptId?: Id;
  version?: number;
  device?: RunDevice;
  onClose: () => void;
}) {
  const [chosen, setChosen] = useState<Id>(scriptId ?? '');
  const library = useQuery({
    queryKey: scriptKeys.list(device?.organizationId),
    queryFn: () => scriptsApi.list(device?.organizationId),
    enabled: !scriptId,
  });
  const detail = useQuery({
    queryKey: scriptKeys.detail(chosen, version),
    queryFn: () => scriptsApi.get(chosen, version),
    enabled: Boolean(chosen),
  });
  const fitting = (library.data ?? []).filter((s) => !device || s.osTargets.includes(device.os));
  const pickerId = useId();

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) {
          onClose();
        }
      }}
    >
      <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>
            {detail.data ? `Run “${detail.data.name}”` : 'Run a script'}
            {detail.data && version && version !== detail.data.currentVersion ? ` (version ${version})` : ''}
          </DialogTitle>
          <DialogDescription>
            {device
              ? `Runs on ${device.hostname}. Output streams back live and is kept in the job history.`
              : 'Choose where it runs and how. Output streams back live and is kept in the job history.'}
          </DialogDescription>
        </DialogHeader>

        {!scriptId ? (
          <div className="grid gap-1.5">
            <label htmlFor={pickerId} className="text-sm font-medium">
              Script
            </label>
            <NativeSelect
              id={pickerId}
              className="w-full"
              value={chosen}
              disabled={library.isPending || fitting.length === 0}
              onChange={(e) => {
                setChosen(e.target.value);
              }}
            >
              <NativeSelectOption value="">
                {library.isPending ? 'Loading scripts…' : 'Choose a script…'}
              </NativeSelectOption>
              {fitting.map((s) => (
                <NativeSelectOption key={s.id} value={s.id}>
                  {s.name} ({languageLabel(s.language)}, version {s.currentVersion})
                </NativeSelectOption>
              ))}
            </NativeSelect>
            {library.isError ? (
              <p role="alert" className="text-danger text-xs font-medium">
                {errorMessage(library.error)}
              </p>
            ) : library.isSuccess && fitting.length === 0 ? (
              <p className="text-muted-foreground text-xs">
                {device
                  ? `The library has no script for ${osLabel(device.os)} that this device’s organization can use.`
                  : 'The library is empty.'}
              </p>
            ) : null}
          </div>
        ) : null}

        {!chosen ? (
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
          </DialogFooter>
        ) : detail.isPending ? (
          <div role="status" aria-label="Loading script" className="grid gap-2">
            <Skeleton className="h-9 w-full" />
            <Skeleton className="h-24 w-full" />
          </div>
        ) : detail.isError ? (
          <>
            <InlineAlert live>{errorMessage(detail.error)}</InlineAlert>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={onClose}>
                Close
              </Button>
            </DialogFooter>
          </>
        ) : (
          // Keyed so parameter values and options reset when another script is picked.
          <RunForm
            key={`${detail.data.id}:${detail.data.version}`}
            script={detail.data}
            device={device}
            onClose={onClose}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function RunForm({ script, device, onClose }: { script: ScriptDetail; device?: RunDevice; onClose: () => void }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { organizations, orgId } = useOrgFilter();
  const sites = useSites(undefined, !device);
  const groups = useGroups(undefined, !device);
  const parameters = script.parameters ?? [];

  const [target, setTarget] = useState<TargetDraft>(() =>
    device ? deviceTarget(device) : emptyTarget({ organizationId: script.organizationId ?? orgId ?? '' }),
  );
  const [values, setValues] = useState<ParameterValues>(() => initialParameterValues(parameters));
  const [runAs, setRunAs] = useState<RunAs>('system');
  const [timeout, setTimeoutText] = useState(String(RUN_LIMITS.timeoutSeconds.default));
  const [outputKb, setOutputKb] = useState(String(RUN_LIMITS.maxOutputKb.default));
  const [parallel, setParallel] = useState(String(RUN_LIMITS.maxParallel.default));
  const [scheduled, setScheduled] = useState(false);
  const [cron, setCron] = useState('0 2 * * *');
  const [name, setName] = useState('');
  const [touched, setTouched] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const ids = useId();

  const request = toTargetRequest(target);
  const problem = targetProblem(target);
  const preview = useTargetPreview(request);
  const paramErrors = validateParameterValues(parameters, values);
  const timeoutSeconds = parseBounded(timeout, RUN_LIMITS.timeoutSeconds.min, RUN_LIMITS.timeoutSeconds.max);
  const maxOutputKb = parseBounded(outputKb, RUN_LIMITS.maxOutputKb.min, RUN_LIMITS.maxOutputKb.max);
  const maxParallel = parseBounded(parallel, RUN_LIMITS.maxParallel.min, RUN_LIMITS.maxParallel.max);
  const cronPreview = describeCron(cron);
  const nameValid = name.trim().length <= 120;
  const valid =
    request !== null &&
    Object.keys(paramErrors).length === 0 &&
    timeoutSeconds !== null &&
    maxOutputKb !== null &&
    maxParallel !== null &&
    nameValid &&
    (!scheduled || cronPreview.ok);

  const count = preview.current && preview.preview ? preview.preview.deviceCount : null;
  const names = { organizations, sites: sites.data, groups: groups.data };
  const where = describeTarget(target, names);

  // The server uses the organization's time zone: the target's organization, else the first device's.
  const tzOrgId =
    target.mode === 'devices'
      ? (device?.organizationId ?? script.organizationId ?? target.devices[0]?.organizationId ?? '')
      : (script.organizationId ?? target.organizationId);
  const tzOrg = organizations.find((o) => o.id === tzOrgId);

  const run = useMutation({
    mutationFn: () => {
      const input: RunScriptInput = {
        scriptId: script.id,
        version: script.version,
        target: request ?? {},
        parameters: buildParameterPayload(parameters, values),
        runAs,
        timeoutSeconds: timeoutSeconds ?? undefined,
        maxOutputBytes: maxOutputKb !== null ? maxOutputKb * 1024 : undefined,
        maxParallel: maxParallel ?? undefined,
        name: name.trim() || undefined,
        schedule: scheduled ? { cron: cron.trim().split(/\s+/).join(' ') } : undefined,
      };
      return jobsApi.runScript(input);
    },
    onSuccess: async (created) => {
      notifySuccess(
        scheduled
          ? `Scheduled “${name.trim() || script.name}”`
          : `Started “${name.trim() || script.name}” on ${deviceCountLabel(created.deviceCount)}`,
      );
      await queryClient.invalidateQueries({ queryKey: jobKeys.all });
      await queryClient.invalidateQueries({ queryKey: jobKeys.runs });
      onClose();
      await navigate(`/jobs/${created.jobId}`);
    },
    onError: () => {
      setConfirming(false);
    },
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!valid || run.isPending) {
      return;
    }
    // One explicitly chosen device needs no second question; anything wider is confirmed with the count.
    if (target.mode === 'devices' && target.devices.length === 1 && !scheduled) {
      run.mutate();
    } else {
      setConfirming(true);
    }
  };

  const numberField = (
    label: string,
    value: string,
    set: (v: string) => void,
    parsed: number | null,
    limits: { min: number; max: number },
    hint: string,
  ) => (
    <Field
      label={label}
      hint={hint}
      error={touched && parsed === null ? `Enter a whole number from ${limits.min} to ${limits.max}.` : null}
    >
      {(control) => (
        <Input
          {...control}
          inputMode="numeric"
          value={value}
          maxLength={6}
          onChange={(e) => {
            set(e.target.value);
          }}
        />
      )}
    </Field>
  );

  return (
    <>
      <form onSubmit={submit} noValidate className="grid gap-5">
        <div aria-live="assertive" className="empty:hidden">
          {run.error ? <InlineAlert live={false}>{errorMessage(run.error)}</InlineAlert> : null}
        </div>

        <section aria-labelledby={`${ids}-target`} className="grid gap-3">
          <h3 id={`${ids}-target`} className="text-sm font-semibold">
            Target
          </h3>
          {device ? (
            <p>
              This device: <span className="ident font-medium">{device.hostname}</span> ({osLabel(device.os)})
            </p>
          ) : (
            <TargetPicker value={target} onChange={setTarget} lockedOrganizationId={script.organizationId} />
          )}
          <TargetPreviewPanel
            state={preview}
            problem={touched || target.mode === 'filter' ? problem : problem ? 'Choose what to run on.' : null}
            supportedOs={script.osTargets}
            scheduled={scheduled && target.mode !== 'devices'}
          />
          {script.organizationId ? (
            <p className="text-muted-foreground text-xs">
              This script belongs to{' '}
              {organizations.find((o) => o.id === script.organizationId)?.name ?? 'one organization'} and can only run
              on that organization’s devices.
            </p>
          ) : null}
        </section>

        {parameters.length > 0 ? (
          <section aria-labelledby={`${ids}-params`} className="grid gap-3">
            <h3 id={`${ids}-params`} className="text-sm font-semibold">
              Parameters
            </h3>
            <div className="grid gap-3 sm:grid-cols-2">
              {parameters.map((p) => {
                const error = touched ? (paramErrors[p.name] ?? null) : null;
                const label = `${p.name}${p.required ? '' : ' (optional)'}`;
                const hint =
                  p.type === 'int'
                    ? `Whole number${p.default ? `. Default ${p.default}` : ''}`
                    : p.type === 'bool'
                      ? `Yes or no${p.default ? `. Default ${p.default === 'true' ? 'yes' : 'no'}` : ''}`
                      : p.default
                        ? `Text. Default “${p.default}”`
                        : 'Text';
                return (
                  <Field key={p.name} label={label} hint={hint} error={error}>
                    {(control) =>
                      p.type === 'bool' ? (
                        <NativeSelect
                          {...control}
                          className="w-full"
                          value={values[p.name] ?? ''}
                          onChange={(e) => {
                            setValues({ ...values, [p.name]: e.target.value });
                          }}
                        >
                          <NativeSelectOption value="">{p.default ? 'Use the default' : 'Not set'}</NativeSelectOption>
                          <NativeSelectOption value="true">Yes (true)</NativeSelectOption>
                          <NativeSelectOption value="false">No (false)</NativeSelectOption>
                        </NativeSelect>
                      ) : (
                        <Input
                          {...control}
                          className={p.type === 'int' ? 'ident' : undefined}
                          inputMode={p.type === 'int' ? 'numeric' : undefined}
                          value={values[p.name] ?? ''}
                          autoComplete="off"
                          spellCheck={false}
                          onChange={(e) => {
                            setValues({ ...values, [p.name]: e.target.value });
                          }}
                        />
                      )
                    }
                  </Field>
                );
              })}
            </div>
          </section>
        ) : null}

        <section aria-labelledby={`${ids}-how`} className="grid gap-3">
          <h3 id={`${ids}-how`} className="text-sm font-semibold">
            How it runs
          </h3>
          <fieldset className="grid gap-2">
            <legend className="mb-1.5 text-sm font-medium">Run as</legend>
            {(
              [
                [
                  'system',
                  'System',
                  'The system account (SYSTEM on Windows, root on macOS and Linux). Works when nobody is signed in.',
                ],
                [
                  'user',
                  'Signed-in user',
                  'Inside the session of whoever is signed in at the device’s screen, with that person’s rights and files. If nobody is signed in, the run fails on that device.',
                ],
              ] as const
            ).map(([id, label, text]) => (
              <label key={id} className="flex cursor-pointer items-start gap-2.5">
                <input
                  type="radio"
                  name={`${ids}-runas`}
                  className="accent-primary mt-1"
                  value={id}
                  checked={runAs === id}
                  onChange={() => {
                    setRunAs(id);
                  }}
                />
                <span>
                  <span className="font-medium">{label}</span>
                  <span className="text-muted-foreground block text-xs">{text}</span>
                </span>
              </label>
            ))}
          </fieldset>
          <div className="grid gap-3 sm:grid-cols-3">
            {numberField(
              'Time limit (seconds)',
              timeout,
              setTimeoutText,
              timeoutSeconds,
              RUN_LIMITS.timeoutSeconds,
              'The run is stopped after this long.',
            )}
            {numberField(
              'Output limit (KB)',
              outputKb,
              setOutputKb,
              maxOutputKb,
              RUN_LIMITS.maxOutputKb,
              'Output beyond this is cut off and marked truncated.',
            )}
            {numberField(
              'Devices at once',
              parallel,
              setParallel,
              maxParallel,
              RUN_LIMITS.maxParallel,
              '0 means no limit for this job.',
            )}
          </div>
        </section>

        <section aria-labelledby={`${ids}-when`} className="grid gap-3">
          <h3 id={`${ids}-when`} className="text-sm font-semibold">
            When
          </h3>
          <div className="flex items-start gap-2.5">
            <Checkbox
              id={`${ids}-scheduled`}
              className="mt-0.5"
              checked={scheduled}
              onCheckedChange={(checked) => {
                setScheduled(checked === true);
              }}
            />
            <label htmlFor={`${ids}-scheduled`}>
              <span className="font-medium">Run on a schedule</span>
              <span className="text-muted-foreground block text-xs">
                Off: it runs once, now. On: it repeats, and each time it covers the devices that match the target then.
              </span>
            </label>
          </div>
          {scheduled ? (
            <div className="grid gap-3 sm:grid-cols-2">
              <Field
                label="Schedule (cron expression)"
                hint="Five fields: minute, hour, day of month, month, day of week."
                error={!cronPreview.ok ? cronPreview.error : null}
              >
                {(control) => (
                  <Input
                    {...control}
                    className="ident"
                    value={cron}
                    maxLength={100}
                    spellCheck={false}
                    autoComplete="off"
                    onChange={(e) => {
                      setCron(e.target.value);
                    }}
                  />
                )}
              </Field>
              <Field label="Common schedules">
                {(control) => (
                  <NativeSelect
                    {...control}
                    className="w-full"
                    value={CRON_PRESETS.some((p) => p.cron === cron.trim()) ? cron.trim() : ''}
                    onChange={(e) => {
                      if (e.target.value) {
                        setCron(e.target.value);
                      }
                    }}
                  >
                    <NativeSelectOption value="">Custom</NativeSelectOption>
                    {CRON_PRESETS.map((p) => (
                      <NativeSelectOption key={p.cron} value={p.cron}>
                        {p.label}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                )}
              </Field>
              <p className="bg-muted/50 rounded-md border px-3 py-2 sm:col-span-2" role="status" aria-live="polite">
                {cronPreview.ok ? (
                  <>
                    <span className="font-semibold">{cronPreview.text}</span>
                    {cronPreview.exact ? ', ' : ' '}
                    in the organization’s time zone{tzOrg ? ` (${tzOrg.timeZone}, ${tzOrg.name})` : ''}.
                  </>
                ) : (
                  <span className="text-muted-foreground">The schedule is not valid yet.</span>
                )}
              </p>
            </div>
          ) : null}
          <Field
            label="Job name (optional)"
            hint="Shown in the job list and the audit log. Defaults to the script’s name."
            error={touched && !nameValid ? 'At most 120 characters.' : null}
          >
            {(control) => (
              <Input
                {...control}
                value={name}
                maxLength={120}
                autoComplete="off"
                placeholder={script.name}
                onChange={(e) => {
                  setName(e.target.value);
                }}
              />
            )}
          </Field>
        </section>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose} disabled={run.isPending}>
            Cancel
          </Button>
          <Button type="submit" disabled={run.isPending}>
            {run.isPending
              ? 'Starting…'
              : scheduled
                ? 'Schedule…'
                : count !== null && !(target.mode === 'devices' && target.devices.length === 1)
                  ? `Run on ${deviceCountLabel(count)}…`
                  : 'Run now'}
          </Button>
        </DialogFooter>
      </form>

      {/* Outside the form: the confirmation has its own form, and React would bubble its submit into this one. */}
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title={
          scheduled
            ? `Schedule “${script.name}”?`
            : `Run “${script.name}” on ${count !== null ? deviceCountLabel(count) : where}?`
        }
        description={
          <>
            <p>
              {scheduled ? 'It will run ' : 'It runs now '}
              as {runAs === 'system' ? 'the system account' : 'the signed-in user'} on {where}
              {count !== null ? ` (${deviceCountLabel(count)} right now)` : ''}.
              {scheduled && cronPreview.ok ? ` ${cronPreview.text}${tzOrg ? `, ${tzOrg.timeZone} time` : ''}.` : ''}
            </p>
            {preview.preview?.stepUpRequired || (scheduled && target.mode !== 'devices') ? (
              <p>You will be asked for your authenticator code.</p>
            ) : null}
          </>
        }
        confirmLabel={scheduled ? 'Schedule' : count !== null ? `Run on ${deviceCountLabel(count)}` : 'Run'}
        pending={run.isPending}
        onConfirm={() => {
          run.mutate();
        }}
      />
    </>
  );
}
