import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Search, X } from 'lucide-react';
import { useId, useState } from 'react';
import { useOrgFilter } from '@/app/org-filter';
import { Field } from '@/components/field';
import { DeviceStatus, InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { NativeSelect, NativeSelectOptGroup, NativeSelectOption } from '@/components/ui/native-select';
import { useGroups, useSites } from '@/features/tenants/queries';
import { devicesApi, errorMessage, OS_FAMILIES, qk, type Id } from '@/lib/api';
import { jobKeys, savedFiltersApi } from '@/lib/api/jobs';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { useDebounced } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import { cn } from '@/lib/utils';
import {
  describeFilter,
  filterIsUnrestricted,
  MAX_EXPLICIT_DEVICES,
  TARGET_MODES,
  toFilterSpec,
  type TargetDraft,
  type TargetMode,
} from './target';

const DEVICE_RESULTS = 25;

/**
 * Chooses what a job runs on: devices, a group, a site, an organization, a saved filter or an ad-hoc filter.
 * It only edits a {@link TargetDraft}; `toTargetRequest` turns that into the server request.
 */
export function TargetPicker({
  value,
  onChange,
  lockedOrganizationId,
  modes,
  disabled = false,
  allowSaveFilter = true,
  legend = 'Run on',
}: {
  value: TargetDraft;
  onChange: (next: TargetDraft) => void;
  /** The item being run belongs to one organization, so only its devices can be targeted. */
  lockedOrganizationId?: Id | null;
  /** Limit the offered modes (default: all). */
  modes?: readonly TargetMode[];
  disabled?: boolean;
  /** Offer "Save as filter" below the ad-hoc filter (hidden where the surrounding form saves the filter itself). */
  allowSaveFilter?: boolean;
  legend?: string;
}) {
  const access = useAccess();
  const groupName = useId();
  const { organizations, orgId: globalOrgId } = useOrgFilter();
  const canListTenants = access.has(P.tenantsRead);
  const organizationId = lockedOrganizationId ?? value.organizationId;
  const offered = TARGET_MODES.filter((m) => !modes || modes.includes(m.id));
  const set = (patch: Partial<TargetDraft>) => {
    onChange({ ...value, ...patch });
  };

  const sites = useSites(organizationId || undefined, value.mode !== 'devices' && value.mode !== 'savedFilter');
  const groups = useGroups(organizationId || undefined, value.mode === 'group' || value.mode === 'filter');
  const siteList = sites.data ?? [];
  const groupList = groups.data ?? [];

  const orgSelect = (label: string, allowAll: boolean) =>
    lockedOrganizationId ? (
      <div className="grid content-start gap-1.5">
        <p className="text-sm font-medium">{label}</p>
        <p className="flex h-9 items-center">
          {organizations.find((o) => o.id === lockedOrganizationId)?.name ?? 'This item’s organization'}
        </p>
      </div>
    ) : (
      <Field label={label}>
        {(control) => (
          <NativeSelect
            {...control}
            className="w-full"
            value={value.organizationId}
            disabled={disabled}
            onChange={(e) => {
              set({
                organizationId: e.target.value,
                siteId: '',
                groupId: '',
                filter: { ...value.filter, siteId: '', groupId: '' },
              });
            }}
          >
            <NativeSelectOption value="">{allowAll ? 'All organizations' : 'Choose…'}</NativeSelectOption>
            {organizations.map((o) => (
              <NativeSelectOption key={o.id} value={o.id}>
                {o.name}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        )}
      </Field>
    );

  return (
    <div className="grid gap-3">
      <fieldset disabled={disabled} className={offered.length <= 1 ? 'sr-only' : undefined}>
        <legend className="mb-1.5 text-sm font-medium">{legend}</legend>
        <div className="flex flex-wrap gap-1.5">
          {offered.map((m) => (
            <label
              key={m.id}
              title={m.hint}
              className={cn(
                'has-focus-visible:ring-ring/50 cursor-pointer rounded-md border px-2.5 py-1 text-sm has-focus-visible:ring-[3px]',
                value.mode === m.id
                  ? 'bg-primary text-primary-foreground border-primary font-medium'
                  : 'bg-card hover:bg-accent border-input',
              )}
            >
              <input
                type="radio"
                className="sr-only"
                name={groupName}
                value={m.id}
                checked={value.mode === m.id}
                onChange={() => {
                  set({ mode: m.id, organizationId: value.organizationId || (globalOrgId ?? '') });
                }}
              />
              {m.label}
            </label>
          ))}
        </div>
      </fieldset>

      {!canListTenants && value.mode !== 'devices' && value.mode !== 'savedFilter' ? (
        <InlineAlert tone="warn" live={false}>
          You cannot list organizations, sites and groups with your role, so only individual devices and saved filters
          can be chosen here.
        </InlineAlert>
      ) : null}

      {value.mode === 'devices' ? (
        <DevicePicker value={value} onChange={onChange} organizationId={lockedOrganizationId ?? null} />
      ) : null}

      {value.mode === 'group' ? (
        <div className="grid gap-3 sm:grid-cols-2">
          {orgSelect('Organization', false)}
          <Field
            label="Group"
            hint={
              organizationId && groups.isSuccess && groupList.length === 0
                ? 'This organization has no groups yet.'
                : undefined
            }
          >
            {(control) => (
              <NativeSelect
                {...control}
                className="w-full"
                value={value.groupId}
                disabled={disabled || !organizationId || groupList.length === 0}
                onChange={(e) => {
                  set({ groupId: e.target.value });
                }}
              >
                <NativeSelectOption value="">Choose…</NativeSelectOption>
                {siteList
                  .filter((s) => groupList.some((g) => g.siteId === s.id))
                  .map((s) => (
                    <NativeSelectOptGroup key={s.id} label={s.name}>
                      {groupList
                        .filter((g) => g.siteId === s.id)
                        .map((g) => (
                          <NativeSelectOption key={g.id} value={g.id}>
                            {g.name}
                          </NativeSelectOption>
                        ))}
                    </NativeSelectOptGroup>
                  ))}
              </NativeSelect>
            )}
          </Field>
        </div>
      ) : null}

      {value.mode === 'site' ? (
        <div className="grid gap-3 sm:grid-cols-2">
          {orgSelect('Organization', false)}
          <Field label="Site">
            {(control) => (
              <NativeSelect
                {...control}
                className="w-full"
                value={value.siteId}
                disabled={disabled || !organizationId || siteList.length === 0}
                onChange={(e) => {
                  set({ siteId: e.target.value });
                }}
              >
                <NativeSelectOption value="">Choose…</NativeSelectOption>
                {siteList.map((s) => (
                  <NativeSelectOption key={s.id} value={s.id}>
                    {s.name}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            )}
          </Field>
        </div>
      ) : null}

      {value.mode === 'organization' ? (
        <div className="grid gap-3 sm:grid-cols-2">{orgSelect('Organization', false)}</div>
      ) : null}

      {value.mode === 'savedFilter' ? (
        <SavedFilterSelect value={value} onChange={onChange} lockedOrganizationId={lockedOrganizationId ?? null} />
      ) : null}

      {value.mode === 'filter' ? (
        <>
          <div className="grid gap-3 sm:grid-cols-3">
            {orgSelect('Organization', access.hasPartnerWide(P.devicesRead))}
            <Field label="Site">
              {(control) => (
                <NativeSelect
                  {...control}
                  className="w-full"
                  value={value.filter.siteId}
                  disabled={disabled || !organizationId}
                  onChange={(e) => {
                    set({ filter: { ...value.filter, siteId: e.target.value, groupId: '' } });
                  }}
                >
                  <NativeSelectOption value="">Any site</NativeSelectOption>
                  {siteList.map((s) => (
                    <NativeSelectOption key={s.id} value={s.id}>
                      {s.name}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              )}
            </Field>
            <Field label="Group">
              {(control) => (
                <NativeSelect
                  {...control}
                  className="w-full"
                  value={value.filter.groupId}
                  disabled={disabled || !organizationId}
                  onChange={(e) => {
                    set({ filter: { ...value.filter, groupId: e.target.value } });
                  }}
                >
                  <NativeSelectOption value="">Any group</NativeSelectOption>
                  {groupList
                    .filter((g) => !value.filter.siteId || g.siteId === value.filter.siteId)
                    .map((g) => (
                      <NativeSelectOption key={g.id} value={g.id}>
                        {g.name}
                      </NativeSelectOption>
                    ))}
                </NativeSelect>
              )}
            </Field>
            <Field label="Operating system">
              {(control) => (
                <NativeSelect
                  {...control}
                  className="w-full"
                  value={value.filter.os}
                  disabled={disabled}
                  onChange={(e) => {
                    set({ filter: { ...value.filter, os: e.target.value } });
                  }}
                >
                  <NativeSelectOption value="">Any</NativeSelectOption>
                  {OS_FAMILIES.map((os) => (
                    <NativeSelectOption key={os} value={os}>
                      {osLabel(os)}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              )}
            </Field>
            <Field label="Status">
              {(control) => (
                <NativeSelect
                  {...control}
                  className="w-full"
                  value={value.filter.status}
                  disabled={disabled}
                  onChange={(e) => {
                    const status = e.target.value;
                    set({
                      filter: { ...value.filter, status: status === 'online' || status === 'offline' ? status : '' },
                    });
                  }}
                >
                  <NativeSelectOption value="">Online and offline</NativeSelectOption>
                  <NativeSelectOption value="online">Online now</NativeSelectOption>
                  <NativeSelectOption value="offline">Offline now</NativeSelectOption>
                </NativeSelect>
              )}
            </Field>
            <Field label="Tag">
              {(control) => (
                <Input
                  {...control}
                  value={value.filter.tag}
                  maxLength={48}
                  autoComplete="off"
                  disabled={disabled}
                  onChange={(e) => {
                    set({ filter: { ...value.filter, tag: e.target.value } });
                  }}
                />
              )}
            </Field>
          </div>
          <Field label="Search" hint="Matches hostname, serial, model, OS or signed-in user, like the device list.">
            {(control) => (
              <Input
                {...control}
                value={value.filter.search}
                maxLength={120}
                autoComplete="off"
                disabled={disabled}
                onChange={(e) => {
                  set({ filter: { ...value.filter, search: e.target.value } });
                }}
              />
            )}
          </Field>
          {filterIsUnrestricted(value.filter) ? (
            <p className="text-muted-foreground text-xs">
              No criteria set: this covers every device {organizationId ? 'of the organization' : 'you can reach'}.
            </p>
          ) : null}
          {allowSaveFilter && access.has(P.devicesManage) ? (
            <SaveFilterInline draft={value} organizationId={organizationId} />
          ) : null}
        </>
      ) : null}
    </div>
  );
}

function DevicePicker({
  value,
  onChange,
  organizationId,
}: {
  value: TargetDraft;
  onChange: (next: TargetDraft) => void;
  organizationId: Id | null;
}) {
  const searchId = useId();
  const { orgId: globalOrgId } = useOrgFilter();
  const [text, setText] = useState('');
  const search = useDebounced(text.trim());
  const filter = {
    organizationId: organizationId ?? globalOrgId ?? undefined,
    search: search || undefined,
    pageSize: DEVICE_RESULTS,
  };
  const query = useQuery({
    queryKey: qk.deviceList(filter),
    queryFn: ({ signal }) => devicesApi.list(filter, signal),
    placeholderData: keepPreviousData,
  });
  const picked = new Set(value.devices.map((d) => d.id));
  const full = value.devices.length >= MAX_EXPLICIT_DEVICES;
  const toggle = (device: { id: Id; hostname: string; os: string; organizationId?: Id }, on: boolean) => {
    onChange({
      ...value,
      devices: on
        ? picked.has(device.id)
          ? value.devices
          : [
              ...value.devices,
              { id: device.id, hostname: device.hostname, os: device.os, organizationId: device.organizationId },
            ]
        : value.devices.filter((d) => d.id !== device.id),
    });
  };
  const results = (query.data?.items ?? []).filter((d) => d.status !== 'revoked');

  return (
    <div className="grid gap-2">
      {value.devices.length > 0 ? (
        <ul aria-label="Selected devices" className="flex max-h-24 flex-wrap gap-1.5 overflow-y-auto">
          {value.devices.map((d) => (
            <li key={d.id} className="bg-muted inline-flex items-center gap-1 rounded-sm py-0.5 pr-0.5 pl-2">
              <span className="ident">{d.hostname}</span>
              <button
                type="button"
                aria-label={`Remove ${d.hostname}`}
                className="hover:bg-accent text-muted-foreground hover:text-foreground grid size-5 place-items-center rounded-sm"
                onClick={() => {
                  toggle({ id: d.id, hostname: d.hostname, os: d.os ?? '' }, false);
                }}
              >
                <X aria-hidden="true" className="size-3" />
              </button>
            </li>
          ))}
        </ul>
      ) : null}
      <div className="rounded-md border">
        <div className="relative border-b">
          <label htmlFor={searchId} className="sr-only">
            Find devices
          </label>
          <Search
            aria-hidden="true"
            className="text-muted-foreground absolute top-1/2 left-2.5 size-4 -translate-y-1/2"
          />
          <Input
            id={searchId}
            type="search"
            className="h-8 rounded-none border-0 pl-8 shadow-none"
            placeholder="Find devices by hostname, serial, model or user"
            value={text}
            onChange={(e) => {
              setText(e.target.value);
            }}
          />
        </div>
        <div className="max-h-44 overflow-y-auto" aria-busy={query.isFetching}>
          {query.isPending ? (
            <p role="status" className="text-muted-foreground px-3 py-2">
              Loading devices…
            </p>
          ) : query.isError ? (
            <p role="alert" className="text-danger px-3 py-2">
              {errorMessage(query.error)}
            </p>
          ) : results.length === 0 ? (
            <p className="text-muted-foreground px-3 py-2">
              {search ? 'No devices match this search.' : 'No devices to choose from.'}
            </p>
          ) : (
            <ul aria-label="Devices">
              {results.map((d) => {
                const checked = picked.has(d.id);
                const id = `${searchId}-${d.id}`;
                return (
                  <li key={d.id} className="hover:bg-muted/60 flex items-center gap-2.5 px-3 py-1.5">
                    <Checkbox
                      id={id}
                      checked={checked}
                      disabled={!checked && full}
                      onCheckedChange={(next) => {
                        toggle(d, next === true);
                      }}
                    />
                    <label htmlFor={id} className="ident min-w-0 flex-1 cursor-pointer truncate">
                      {d.hostname}
                    </label>
                    <span className="text-muted-foreground hidden text-xs sm:inline">{osLabel(d.os)}</span>
                    <DeviceStatus device={d} className="text-xs" />
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        {query.data && query.data.total > results.length ? (
          <p className="text-muted-foreground border-t px-3 py-1.5 text-xs">
            Showing the first {results.length} of {query.data.total}. Search to narrow the list.
          </p>
        ) : null}
      </div>
    </div>
  );
}

function SavedFilterSelect({
  value,
  onChange,
  lockedOrganizationId,
}: {
  value: TargetDraft;
  onChange: (next: TargetDraft) => void;
  lockedOrganizationId: Id | null;
}) {
  const { organizations } = useOrgFilter();
  const query = useQuery({ queryKey: jobKeys.savedFilters, queryFn: savedFiltersApi.list, staleTime: 30_000 });
  const filters = (query.data ?? []).filter((f) => !lockedOrganizationId || f.organizationId === lockedOrganizationId);
  const selected = filters.find((f) => f.id === value.savedFilterId);
  const orgName = (id: Id | null) =>
    id ? (organizations.find((o) => o.id === id)?.name ?? 'one organization') : 'all organizations';
  return (
    <Field
      label="Saved filter"
      error={query.isError ? errorMessage(query.error) : null}
      hint={
        selected
          ? `Matches ${describeFilter(selected.filter)} in ${orgName(selected.organizationId)}.`
          : query.isSuccess && filters.length === 0
            ? 'No saved filters yet. Build one with “Filter” and save it.'
            : undefined
      }
    >
      {(control) => (
        <NativeSelect
          {...control}
          className="w-full sm:w-1/2"
          value={selected ? value.savedFilterId : ''}
          disabled={query.isPending || filters.length === 0}
          onChange={(e) => {
            onChange({ ...value, savedFilterId: e.target.value });
          }}
        >
          <NativeSelectOption value="">Choose…</NativeSelectOption>
          {filters.map((f) => (
            <NativeSelectOption key={f.id} value={f.id}>
              {f.name}
            </NativeSelectOption>
          ))}
        </NativeSelect>
      )}
    </Field>
  );
}

/** "Save as filter": stores the current criteria (`POST /saved-filters`) so they can be reused as a target. */
function SaveFilterInline({ draft, organizationId }: { draft: TargetDraft; organizationId: string }) {
  const queryClient = useQueryClient();
  const nameId = useId();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const save = useMutation({
    mutationFn: () =>
      savedFiltersApi.create({
        name: name.trim(),
        organizationId: organizationId || undefined,
        filter: toFilterSpec(draft.filter, organizationId),
      }),
    onSuccess: async () => {
      notifySuccess(`Filter “${name.trim()}” saved`);
      setOpen(false);
      setName('');
      await queryClient.invalidateQueries({ queryKey: jobKeys.savedFilters });
    },
    onError: notifyError,
  });
  if (!open) {
    return (
      <div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            setOpen(true);
          }}
        >
          Save as filter…
        </Button>
      </div>
    );
  }
  const valid = name.trim().length > 0 && name.trim().length <= 120;
  return (
    <div className="flex flex-wrap items-end gap-2">
      <div className="grid gap-1.5">
        <label htmlFor={nameId} className="text-sm font-medium">
          Filter name
        </label>
        <Input
          id={nameId}
          className="w-64"
          value={name}
          maxLength={120}
          autoComplete="off"
          autoFocus
          onChange={(e) => {
            setName(e.target.value);
          }}
          onKeyDown={(e) => {
            // The picker sits inside another form; Enter here saves the filter instead of submitting that form.
            if (e.key === 'Enter') {
              e.preventDefault();
              if (valid && !save.isPending) {
                save.mutate();
              }
            }
          }}
        />
      </div>
      <Button
        type="button"
        size="sm"
        disabled={!valid || save.isPending}
        onClick={() => {
          save.mutate();
        }}
      >
        {save.isPending ? 'Saving…' : 'Save filter'}
      </Button>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        onClick={() => {
          setOpen(false);
        }}
      >
        Cancel
      </Button>
      {!organizationId ? (
        <p className="text-muted-foreground basis-full text-xs">
          A filter across all organizations needs a partner-wide role. Choose an organization to save it for that
          organization only.
        </p>
      ) : null}
    </div>
  );
}
