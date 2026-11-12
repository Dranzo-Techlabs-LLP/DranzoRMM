import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
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
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { enrollmentApi, errorMessage, qk, type EnrollmentTokenCreated, type Id, type Organization } from '@/lib/api';
import { formatDateTime } from '@/lib/format';
import { EXPIRY_PRESETS, installCommands } from './tokens';

const NO_GROUP = '';

export function CreateTokenDialog({
  open,
  onOpenChange,
  organizations,
  defaultOrganizationId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organizations: Organization[];
  defaultOrganizationId: Id | null;
}) {
  const [created, setCreated] = useState<EnrollmentTokenCreated | null>(null);
  const close = () => {
    setCreated(null);
    onOpenChange(false);
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          close();
        }
      }}
    >
      <DialogContent
        className="max-h-[92dvh] overflow-y-auto sm:max-w-2xl"
        // The token is shown once: a stray click outside must not close the dialog and lose it.
        onInteractOutside={(e) => {
          if (created) {
            e.preventDefault();
          }
        }}
      >
        {!open ? null : created ? (
          <TokenCreated created={created} onDone={close} />
        ) : (
          <TokenForm
            organizations={organizations}
            defaultOrganizationId={defaultOrganizationId}
            onCreated={setCreated}
            onCancel={close}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function TokenForm({
  organizations,
  defaultOrganizationId,
  onCreated,
  onCancel,
}: {
  organizations: Organization[];
  defaultOrganizationId: Id | null;
  onCreated: (created: EnrollmentTokenCreated) => void;
  onCancel: () => void;
}) {
  const queryClient = useQueryClient();
  const [organizationId, setOrganizationId] = useState<Id>(defaultOrganizationId ?? organizations[0]?.id ?? '');
  const [siteId, setSiteId] = useState<Id>('');
  const [groupId, setGroupId] = useState<Id>(NO_GROUP);
  const [name, setName] = useState('');
  const [hours, setHours] = useState(72);
  const [maxUses, setMaxUses] = useState('25');
  const [touched, setTouched] = useState(false);

  // `/enrollment-tokens/targets` lists exactly the sites and groups this user may enroll into, without tenants.read.
  const targets = useQuery({ queryKey: qk.enrollmentTargets, queryFn: enrollmentApi.targets, staleTime: 30_000 });
  // Without the organization list (no tenants.read) every permitted site is offered directly.
  const byOrg = organizations.length > 0;
  const siteList = (targets.data?.sites ?? []).filter((s) => !byOrg || s.organizationId === organizationId);
  const sites = targets;
  // Until the user picks one, the first site of the organization is selected.
  const effectiveSiteId = siteList.some((s) => s.id === siteId) ? siteId : (siteList[0]?.id ?? '');
  const groupList = (targets.data?.groups ?? []).filter((g) => g.siteId === effectiveSiteId);
  const effectiveGroupId = groupList.some((g) => g.id === groupId) ? groupId : NO_GROUP;

  const uses = Number.parseInt(maxUses, 10);
  const usesValid = /^\d+$/.test(maxUses.trim()) && uses >= 1 && uses <= 10000;
  const nameValid = name.trim().length > 0 && name.trim().length <= 120;

  const create = useMutation({
    mutationFn: () =>
      enrollmentApi.createToken({
        siteId: effectiveSiteId,
        groupId: effectiveGroupId === NO_GROUP ? null : effectiveGroupId,
        name: name.trim(),
        expiresInHours: hours,
        maxUses: uses,
      }),
    onSuccess: async (result) => {
      onCreated(result);
      await queryClient.invalidateQueries({ queryKey: qk.tokensAll });
    },
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!nameValid || !usesValid || !effectiveSiteId) {
      return;
    }
    create.mutate();
  };

  const noSites = (!byOrg || Boolean(organizationId)) && sites.isSuccess && siteList.length === 0;

  return (
    <form onSubmit={submit} noValidate className="grid gap-4">
      <DialogHeader>
        <DialogTitle>New enrollment token</DialogTitle>
        <DialogDescription>
          The agent installer uses this token to enroll computers into a site. Anyone holding it can enroll a device
          until it expires or runs out of uses.
        </DialogDescription>
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {create.error ? <InlineAlert live={false}>{errorMessage(create.error)}</InlineAlert> : null}
      </div>
      {targets.isSuccess && targets.data.sites.length === 0 ? (
        <InlineAlert tone="warn" live={false}>
          There is no site you can enroll devices into. Create an organization and a site first.
        </InlineAlert>
      ) : null}
      {targets.isError ? <InlineAlert live={false}>{errorMessage(targets.error)}</InlineAlert> : null}
      <Field
        label="Name"
        hint="Shown in the token list and the audit log, for example “Front office laptops”."
        error={touched && !nameValid ? 'Enter a name of up to 120 characters.' : null}
      >
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
      <div className="grid gap-4 sm:grid-cols-3">
        {byOrg ? (
          <Field label="Organization">
            {(control) => (
              <NativeSelect
                {...control}
                className="w-full"
                value={organizationId}
                onChange={(e) => {
                  setOrganizationId(e.target.value);
                  setSiteId('');
                  setGroupId(NO_GROUP);
                }}
              >
                {organizations.map((o) => (
                  <NativeSelectOption key={o.id} value={o.id}>
                    {o.name}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            )}
          </Field>
        ) : null}
        <Field
          label="Site"
          error={
            noSites
              ? 'This organization has no sites. Add one on its page first.'
              : touched && !effectiveSiteId
                ? 'Choose a site.'
                : null
          }
        >
          {(control) => (
            <NativeSelect
              {...control}
              className="w-full"
              value={effectiveSiteId}
              disabled={sites.isPending || siteList.length === 0}
              onChange={(e) => {
                setSiteId(e.target.value);
                setGroupId(NO_GROUP);
              }}
            >
              {siteList.map((s) => (
                <NativeSelectOption key={s.id} value={s.id}>
                  {s.name}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        </Field>
        <Field label="Group (optional)">
          {(control) => (
            <NativeSelect
              {...control}
              className="w-full"
              value={effectiveGroupId}
              disabled={groupList.length === 0}
              onChange={(e) => {
                setGroupId(e.target.value);
              }}
            >
              <NativeSelectOption value={NO_GROUP}>No group</NativeSelectOption>
              {groupList.map((g) => (
                <NativeSelectOption key={g.id} value={g.id}>
                  {g.name}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        </Field>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Expires after">
          {(control) => (
            <NativeSelect
              {...control}
              className="w-full"
              value={String(hours)}
              onChange={(e) => {
                setHours(Number(e.target.value));
              }}
            >
              {EXPIRY_PRESETS.map((p) => (
                <NativeSelectOption key={p.hours} value={String(p.hours)}>
                  {p.label} ({p.hours} hours)
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        </Field>
        <Field
          label="Maximum devices"
          hint="How many computers can enroll with this token."
          error={touched && !usesValid ? 'Enter a whole number from 1 to 10000.' : null}
        >
          {(control) => (
            <Input
              {...control}
              inputMode="numeric"
              value={maxUses}
              maxLength={5}
              onChange={(e) => {
                setMaxUses(e.target.value);
              }}
            />
          )}
        </Field>
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onCancel} disabled={create.isPending}>
          Cancel
        </Button>
        <Button type="submit" disabled={create.isPending || noSites || !effectiveSiteId}>
          {create.isPending ? 'Creating…' : 'Create token'}
        </Button>
      </DialogFooter>
    </form>
  );
}

function TokenCreated({ created, onDone }: { created: EnrollmentTokenCreated; onDone: () => void }) {
  const info = useQuery({ queryKey: qk.installInfo, queryFn: enrollmentApi.installInfo, staleTime: 5 * 60_000 });
  const commands = info.data ? installCommands(info.data, created.token) : [];
  return (
    <div className="grid gap-4">
      <DialogHeader>
        <DialogTitle>Token created</DialogTitle>
        <DialogDescription>
          Copy the token or an install command now. For security it is not stored and cannot be shown again.
        </DialogDescription>
      </DialogHeader>
      <div className="grid gap-1.5">
        <p className="text-sm font-medium" id="token-label">
          Enrollment token
        </p>
        <div className="flex items-start gap-2">
          <code
            aria-labelledby="token-label"
            className="ident bg-muted min-w-0 flex-1 rounded-md px-2.5 py-2 break-all select-all"
          >
            {created.token}
          </code>
          <CopyButton value={created.token} label="Copy token" />
        </div>
        <p className="text-muted-foreground text-xs">
          Works for {created.maxUses} {created.maxUses === 1 ? 'device' : 'devices'} until{' '}
          {formatDateTime(created.expiresAt)}.
        </p>
      </div>

      <div className="grid gap-1.5">
        <p className="text-sm font-medium">Install the agent</p>
        {info.isPending ? (
          <Skeleton className="h-24 w-full" />
        ) : info.isError ? (
          <InlineAlert tone="warn" live={false} title="Could not load the install commands">
            {errorMessage(info.error)} The token above is still valid.
          </InlineAlert>
        ) : (
          <Tabs defaultValue={commands[0]?.id}>
            <TabsList>
              {commands.map((c) => (
                <TabsTrigger key={c.id} value={c.id}>
                  {c.label}
                </TabsTrigger>
              ))}
            </TabsList>
            {commands.map((c) => (
              <TabsContent key={c.id} value={c.id} className="grid gap-2">
                <pre className="ident bg-muted max-h-40 overflow-auto rounded-md px-3 py-2.5 break-all whitespace-pre-wrap select-all">
                  {c.command}
                </pre>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-muted-foreground text-xs">
                    Run as an administrator on the computer.
                    {c.placeholders.length > 0
                      ? ` Replace ${c.placeholders.join(' and ')} to match the installer file you downloaded.`
                      : ''}
                  </p>
                  <CopyButton value={c.command} label="Copy command" />
                </div>
              </TabsContent>
            ))}
          </Tabs>
        )}
      </div>
      <DialogFooter>
        <Button onClick={onDone}>I have copied it</Button>
      </DialogFooter>
    </div>
  );
}
