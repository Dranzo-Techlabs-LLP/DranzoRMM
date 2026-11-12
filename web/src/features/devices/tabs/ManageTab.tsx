import { useMutation, useQueryClient } from '@tanstack/react-query';
import { X } from 'lucide-react';
import { useState, type SyntheticEvent, type KeyboardEvent } from 'react';
import { Field } from '@/components/field';
import { Panel } from '@/components/page';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { useGroups, useSites } from '@/features/tenants/queries';
import { devicesApi, errorMessage, qk, type DeviceUpdateInput } from '@/lib/api';
import { notifySuccess } from '@/lib/notify';
import type { DeviceTabProps } from './registry';

const MAX_TAGS = 32;
const MAX_TAG_LENGTH = 48;
const NO_GROUP = '';

function sameTags(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((t, i) => t === b[i]);
}

/** Tags, site and group of one device (`PATCH /devices/{id}`). Moves stay inside the device's organization. */
export function ManageTab({ device }: DeviceTabProps) {
  const queryClient = useQueryClient();
  const sites = useSites(device.organizationId);
  const groups = useGroups(device.organizationId);
  const [tags, setTags] = useState<string[]>(device.tags);
  const [draft, setDraft] = useState('');
  const [tagError, setTagError] = useState<string | null>(null);
  const [siteId, setSiteId] = useState(device.siteId);
  const [groupId, setGroupId] = useState(device.groupId ?? NO_GROUP);

  const siteGroups = (groups.data ?? []).filter((g) => g.siteId === siteId);
  const dirty = !sameTags(tags, device.tags) || siteId !== device.siteId || groupId !== (device.groupId ?? NO_GROUP);

  const addTag = () => {
    const tag = draft.trim();
    if (!tag) {
      return;
    }
    if (tag.length > MAX_TAG_LENGTH) {
      setTagError(`A tag can be at most ${MAX_TAG_LENGTH} characters.`);
      return;
    }
    if (tags.includes(tag)) {
      setTagError('This device already has that tag.');
      return;
    }
    if (tags.length >= MAX_TAGS) {
      setTagError(`A device can have at most ${MAX_TAGS} tags.`);
      return;
    }
    setTags([...tags, tag]);
    setDraft('');
    setTagError(null);
  };

  const save = useMutation({
    mutationFn: () => {
      const input: DeviceUpdateInput = {};
      if (!sameTags(tags, device.tags)) {
        input.tags = tags;
      }
      if (siteId !== device.siteId) {
        input.siteId = siteId;
      }
      if (groupId === NO_GROUP) {
        if (device.groupId !== null && siteId === device.siteId) {
          input.clearGroup = true;
        }
      } else if (groupId !== device.groupId || siteId !== device.siteId) {
        input.groupId = groupId;
      }
      return devicesApi.update(device.id, input);
    },
    onSuccess: async () => {
      notifySuccess('Device saved');
      await queryClient.invalidateQueries({ queryKey: qk.devices });
    },
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    if (dirty && !save.isPending) {
      save.mutate();
    }
  };

  const onTagKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      addTag();
    }
  };

  return (
    <form onSubmit={submit} className="grid max-w-3xl gap-4">
      <div aria-live="assertive" className="empty:hidden">
        {save.error ? <InlineAlert live={false}>{errorMessage(save.error)}</InlineAlert> : null}
      </div>
      <Panel title="Tags" description="Free-form labels for filtering and targeting, for example “kiosk” or “finance”.">
        {tags.length > 0 ? (
          <ul aria-label="Tags on this device" className="mb-3 flex flex-wrap gap-1.5">
            {tags.map((t) => (
              <li key={t} className="bg-muted inline-flex items-center gap-1 rounded-sm py-0.5 pr-0.5 pl-2">
                {t}
                <button
                  type="button"
                  aria-label={`Remove tag ${t}`}
                  className="hover:bg-accent text-muted-foreground hover:text-foreground grid size-5 place-items-center rounded-sm"
                  onClick={() => {
                    setTags(tags.filter((x) => x !== t));
                  }}
                >
                  <X aria-hidden="true" className="size-3" />
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-muted-foreground mb-3">No tags.</p>
        )}
        <Field label="Add a tag" error={tagError} hint="Press Enter to add. Changes are saved with the button below.">
          {(control) => (
            <div className="flex max-w-sm gap-2">
              <Input
                {...control}
                value={draft}
                maxLength={MAX_TAG_LENGTH}
                autoComplete="off"
                onKeyDown={onTagKey}
                onChange={(e) => {
                  setDraft(e.target.value);
                  setTagError(null);
                }}
              />
              <Button type="button" variant="outline" onClick={addTag} disabled={!draft.trim()}>
                Add
              </Button>
            </div>
          )}
        </Field>
      </Panel>

      <Panel title="Site and group" description="A device can move between the sites of its organization.">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Site">
            {(control) => (
              <NativeSelect
                {...control}
                className="w-full"
                value={siteId}
                disabled={sites.isPending}
                onChange={(e) => {
                  setSiteId(e.target.value);
                  setGroupId(NO_GROUP);
                }}
              >
                {(sites.data ?? []).map((s) => (
                  <NativeSelectOption key={s.id} value={s.id}>
                    {s.name}
                  </NativeSelectOption>
                ))}
                {sites.data && !sites.data.some((s) => s.id === siteId) ? (
                  <NativeSelectOption value={siteId}>Current site</NativeSelectOption>
                ) : null}
              </NativeSelect>
            )}
          </Field>
          <Field
            label="Group"
            hint={siteGroups.length === 0 && !groups.isPending ? 'This site has no groups.' : undefined}
          >
            {(control) => (
              <NativeSelect
                {...control}
                className="w-full"
                value={groupId}
                disabled={groups.isPending}
                onChange={(e) => {
                  setGroupId(e.target.value);
                }}
              >
                <NativeSelectOption value={NO_GROUP}>No group</NativeSelectOption>
                {siteGroups.map((g) => (
                  <NativeSelectOption key={g.id} value={g.id}>
                    {g.name}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            )}
          </Field>
        </div>
      </Panel>

      <div className="flex items-center gap-3">
        <Button type="submit" disabled={!dirty || save.isPending}>
          {save.isPending ? 'Saving…' : 'Save changes'}
        </Button>
        {dirty ? (
          <Button
            type="button"
            variant="ghost"
            onClick={() => {
              setTags(device.tags);
              setSiteId(device.siteId);
              setGroupId(device.groupId ?? NO_GROUP);
              setDraft('');
              setTagError(null);
            }}
          >
            Discard
          </Button>
        ) : null}
      </div>
    </form>
  );
}
