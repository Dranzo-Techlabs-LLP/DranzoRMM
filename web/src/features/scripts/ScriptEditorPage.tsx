import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useId, useState, type SyntheticEvent } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { Field } from '@/components/field';
import { ErrorState, LoadingRows, PageHeader, Panel } from '@/components/page';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Textarea } from '@/components/ui/textarea';
import { AP } from '@/features/jobs/permissions';
import { errorMessage, isApiError, OS_FAMILIES } from '@/lib/api';
import { scriptKeys, scriptsApi, type ScriptDetail, type ScriptInput, type ScriptLanguage } from '@/lib/api/scripts';
import { useAccess } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import { CodeEditor } from './CodeEditor';
import { ParametersEditor } from './ParametersEditor';
import {
  allowedOs,
  clampOsTargets,
  LANGUAGES,
  MAX_BODY_CHARS,
  toParameterDrafts,
  toScriptParameters,
  validateParameterDrafts,
  type ParameterDraft,
} from './script-model';

const SHARED = '';

/** `/scripts/new` and `/scripts/:scriptId/edit`. Saving an existing script creates a new version. */
export default function ScriptEditorPage() {
  const { scriptId } = useParams();
  const access = useAccess();
  const query = useQuery({
    queryKey: scriptKeys.detail(scriptId ?? ''),
    queryFn: () => scriptsApi.get(scriptId ?? ''),
    enabled: Boolean(scriptId),
    // The form is filled once; a background refetch must not fight with what the user is typing.
    refetchOnWindowFocus: false,
    staleTime: Infinity,
  });
  useDocumentTitle(scriptId ? `Edit ${query.data?.name ?? 'script'}` : 'New script');

  if (!access.has(AP.scriptsManage)) {
    return (
      <>
        <PageHeader crumbs={[{ label: 'Scripts', to: '/scripts' }, { label: 'Edit' }]} title="Scripts" />
        <InlineAlert tone="warn" live={false}>
          Your role can view scripts but not create or change them.
        </InlineAlert>
      </>
    );
  }
  if (scriptId && query.isPending) {
    return <LoadingRows label="script" rows={10} />;
  }
  if (scriptId && query.isError) {
    return <ErrorState error={query.error} what="this script" onRetry={() => void query.refetch()} />;
  }
  return (
    <ScriptForm
      key={query.data ? `${query.data.id}:${query.data.currentVersion}` : 'new'}
      existing={query.data ?? null}
    />
  );
}

function ScriptForm({ existing }: { existing: ScriptDetail | null }) {
  const access = useAccess();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { organizations, orgId } = useOrgFilter();
  const ids = useId();
  const canShare = access.hasPartnerWide(AP.scriptsManage);

  const [name, setName] = useState(existing?.name ?? '');
  const [description, setDescription] = useState(existing?.description ?? '');
  const [language, setLanguage] = useState<string>(existing?.language ?? 'powershell');
  const [osTargets, setOsTargets] = useState<string[]>(existing?.osTargets ?? [...allowedOs('powershell')]);
  const [organizationId, setOrganizationId] = useState<string>(
    existing
      ? (existing.organizationId ?? SHARED)
      : canShare
        ? (orgId ?? SHARED)
        : (orgId ?? organizations[0]?.id ?? ''),
  );
  const [body, setBody] = useState(existing?.body ?? '');
  const [parameters, setParameters] = useState<ParameterDraft[]>(() => toParameterDrafts(existing?.parameters));
  const [changeNote, setChangeNote] = useState('');
  const [touched, setTouched] = useState(false);

  const allowed = allowedOs(language);
  const parameterErrors = validateParameterDrafts(parameters);
  const nameValid = name.trim().length > 0 && name.trim().length <= 120;
  const bodyError =
    body.length === 0
      ? 'Write the script.'
      : body.length > MAX_BODY_CHARS
        ? `The script is too long (${body.length.toLocaleString('en')} of ${MAX_BODY_CHARS.toLocaleString('en')} characters).`
        : body.includes('\0')
          ? 'The script must be text.'
          : null;
  const osValid = osTargets.length > 0 && osTargets.every((os) => allowed.includes(os));
  const scopeValid = existing !== null || organizationId !== '' || canShare;
  const valid = nameValid && bodyError === null && osValid && scopeValid && Object.keys(parameterErrors).length === 0;

  const save = useMutation({
    mutationFn: () => {
      const input: ScriptInput = {
        name: name.trim(),
        description: description.trim(),
        language,
        osTargets,
        body,
        parameters: toScriptParameters(parameters),
        changeNote: changeNote.trim() || undefined,
      };
      if (existing) {
        return scriptsApi.update(existing.id, input);
      }
      return scriptsApi.create({ ...input, organizationId: organizationId === SHARED ? null : organizationId });
    },
    onSuccess: async (saved) => {
      notifySuccess(existing ? `Saved as version ${saved.version}` : 'Script created');
      await queryClient.invalidateQueries({ queryKey: scriptKeys.all });
      await navigate(`/scripts/${saved.id}`);
    },
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (valid && !save.isPending) {
      save.mutate();
    }
  };

  const forbiddenShared =
    isApiError(save.error) &&
    save.error.status === 403 &&
    (existing ? existing.organizationId === null : organizationId === SHARED);
  const backTo = existing ? `/scripts/${existing.id}` : '/scripts';

  return (
    <form onSubmit={submit} noValidate className="grid max-w-5xl gap-4">
      <PageHeader
        crumbs={
          existing
            ? [{ label: 'Scripts', to: '/scripts' }, { label: existing.name, to: backTo }, { label: 'Edit' }]
            : [{ label: 'Scripts', to: '/scripts' }, { label: 'New script' }]
        }
        title={existing ? `Edit “${existing.name}”` : 'New script'}
        description={
          existing
            ? `Saving creates version ${existing.currentVersion + 1}. Version ${existing.currentVersion} and earlier stay in the history, and schedules keep running the version they were created with.`
            : 'Scripts are stored with their full history. Devices only run scripts the server has signed.'
        }
      />

      <div aria-live="assertive" className="empty:hidden">
        {save.error ? (
          <InlineAlert live={false} title={forbiddenShared ? 'Shared scripts need a partner-wide role' : undefined}>
            {forbiddenShared
              ? 'A shared script can run on every organization, so only people whose role covers all organizations can create or change one. Choose one organization for this script, or ask a partner administrator.'
              : errorMessage(save.error)}
          </InlineAlert>
        ) : null}
      </div>

      <Panel title="About">
        <div className="grid gap-4 md:grid-cols-2">
          <Field label="Name" error={touched && !nameValid ? 'Enter a name of up to 120 characters.' : null}>
            {(control) => (
              <Input
                {...control}
                value={name}
                maxLength={120}
                autoComplete="off"
                autoFocus={!existing}
                onChange={(e) => {
                  setName(e.target.value);
                }}
              />
            )}
          </Field>
          {existing ? (
            <div className="grid content-start gap-1.5">
              <p className="text-sm font-medium">Available to</p>
              <p className="flex min-h-9 items-center">
                {existing.organizationId
                  ? (organizations.find((o) => o.id === existing.organizationId)?.name ?? 'One organization')
                  : 'All organizations (shared)'}
              </p>
              <p className="text-muted-foreground text-xs">
                The scope of a script cannot be changed after it is created.
              </p>
            </div>
          ) : (
            <Field
              label="Available to"
              hint={
                canShare
                  ? 'A shared script can be run on devices of every organization. One for a single organization can only run there.'
                  : 'Your role covers specific organizations, so the script belongs to one of them. Shared scripts need a partner-wide role.'
              }
              error={touched && !scopeValid ? 'Choose an organization.' : null}
            >
              {(control) => (
                <NativeSelect
                  {...control}
                  className="w-full"
                  value={organizationId}
                  onChange={(e) => {
                    setOrganizationId(e.target.value);
                  }}
                >
                  {canShare ? (
                    <NativeSelectOption value={SHARED}>All organizations (shared)</NativeSelectOption>
                  ) : (
                    <NativeSelectOption value="">Choose…</NativeSelectOption>
                  )}
                  {organizations.map((o) => (
                    <NativeSelectOption key={o.id} value={o.id}>
                      {o.name} only
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              )}
            </Field>
          )}
          <Field label="Description (optional)" className="md:col-span-2">
            {(control) => (
              <Textarea
                {...control}
                value={description}
                maxLength={2000}
                rows={2}
                onChange={(e) => {
                  setDescription(e.target.value);
                }}
              />
            )}
          </Field>
          <Field label="Language" hint="The language decides which operating systems the script can run on.">
            {(control) => (
              <NativeSelect
                {...control}
                className="w-full"
                value={language}
                onChange={(e) => {
                  const next = e.target.value as ScriptLanguage;
                  setLanguage(next);
                  setOsTargets(clampOsTargets(next, osTargets));
                }}
              >
                {LANGUAGES.map((l) => (
                  <NativeSelectOption key={l.id} value={l.id}>
                    {l.label}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            )}
          </Field>
          <fieldset
            className="grid content-start gap-1.5"
            aria-describedby={`${ids}-os-hint`}
            aria-invalid={touched && !osValid ? true : undefined}
          >
            <legend className="mb-1.5 text-sm font-medium">Runs on</legend>
            <div className="flex min-h-9 flex-wrap items-center gap-x-5 gap-y-2">
              {OS_FAMILIES.map((os) => {
                const possible = allowed.includes(os);
                const id = `${ids}-os-${os}`;
                return (
                  <div key={os} className="flex items-center gap-2">
                    <Checkbox
                      id={id}
                      checked={possible && osTargets.includes(os)}
                      disabled={!possible}
                      onCheckedChange={(checked) => {
                        setOsTargets(checked === true ? [...osTargets, os] : osTargets.filter((x) => x !== os));
                      }}
                    />
                    <label htmlFor={id} className={possible ? undefined : 'text-muted-foreground'}>
                      {osLabel(os)}
                    </label>
                  </div>
                );
              })}
            </div>
            <p id={`${ids}-os-hint`} className="text-muted-foreground text-xs">
              {LANGUAGES.find((l) => l.id === language)?.label ?? language} runs on {allowed.map(osLabel).join(' and ')}
              {allowed.length < OS_FAMILIES.length ? '; the other systems are not available for it.' : '.'}
            </p>
            {touched && !osValid ? (
              <p role="alert" className="text-danger text-xs font-medium">
                Choose at least one operating system.
              </p>
            ) : null}
          </fieldset>
        </div>
      </Panel>

      <Panel
        title="Script"
        description={`${body.length.toLocaleString('en')} of ${MAX_BODY_CHARS.toLocaleString('en')} characters`}
      >
        <Field label="Script body" error={touched ? bodyError : null}>
          {(control) => <CodeEditor {...control} value={body} onChange={setBody} />}
        </Field>
      </Panel>

      <Panel
        title="Parameters"
        description="Values asked for when the script is run. They are checked against their type before the run starts."
      >
        <ParametersEditor value={parameters} onChange={setParameters} errors={parameterErrors} showErrors={touched} />
      </Panel>

      <Panel title={existing ? 'Change note' : 'Note'}>
        <Field
          label={existing ? 'What changed? (optional)' : 'Note for version 1 (optional)'}
          hint="Shown in the version history."
        >
          {(control) => (
            <Input
              {...control}
              value={changeNote}
              maxLength={500}
              autoComplete="off"
              onChange={(e) => {
                setChangeNote(e.target.value);
              }}
            />
          )}
        </Field>
      </Panel>

      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? 'Saving…' : existing ? `Save as version ${existing.currentVersion + 1}` : 'Create script'}
        </Button>
        <Button asChild variant="ghost">
          <Link to={backTo}>Cancel</Link>
        </Button>
        {touched && !valid ? (
          <p role="alert" className="text-danger text-sm font-medium">
            Some fields need attention before this can be saved.
          </p>
        ) : null}
      </div>
    </form>
  );
}
