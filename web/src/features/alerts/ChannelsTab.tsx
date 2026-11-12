import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { History, Pencil, Plus, Send, Trash2, Webhook } from 'lucide-react';
import { useState, type SyntheticEvent } from 'react';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Field } from '@/components/field';
import { EmptyState, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { InlineAlert, StatusPill } from '@/components/status';
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
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Textarea } from '@/components/ui/textarea';
import { errorMessage, type Organization } from '@/lib/api';
import { alertKeys, alertsApi, CHANNEL_TYPES, type ChannelType, type NotificationChannel } from '@/lib/api/alerts';
import { useMe } from '@/lib/auth/session';
import { formatLogTime } from '@/lib/format';
import { notifyError, notifySuccess } from '@/lib/notify';
import { CHANNEL_LABEL, validateChannel, WEBHOOK_EVENT_LABEL, type ChannelForm } from './rule-params';

const SHARED = '';

function isChannelType(value: string): value is ChannelType {
  return (CHANNEL_TYPES as readonly string[]).includes(value);
}

/** Where a channel sends to, without anything secret: recipients, or just the host name of the URL. */
function Destination({ channel }: { channel: NotificationChannel }) {
  if (channel.type === 'email') {
    return <span className="break-all">{(channel.to ?? []).join(', ') || 'No recipients'}</span>;
  }
  return (
    <>
      <span className="ident">{channel.urlHost ?? 'No URL'}</span>
      {channel.type === 'webhook' ? (
        <span className="text-muted-foreground block text-xs">
          {channel.hasSecret ? 'Signed with a secret' : 'Not signed (no secret)'}
        </span>
      ) : null}
    </>
  );
}

export function ChannelsTab() {
  const me = useMe();
  const queryClient = useQueryClient();
  const { organizations } = useOrgFilter();
  const [editing, setEditing] = useState<NotificationChannel | 'new' | null>(null);
  const [deleting, setDeleting] = useState<NotificationChannel | null>(null);
  const [history, setHistory] = useState<NotificationChannel | null>(null);

  const channels = useQuery({ queryKey: alertKeys.channels, queryFn: alertsApi.channels });
  const catalog = useQuery({ queryKey: alertKeys.catalog, queryFn: alertsApi.catalog, staleTime: 5 * 60_000 });
  const orgName = new Map(organizations.map((o) => [o.id, o.name]));
  const canChange = (c: NotificationChannel) => c.organizationId !== null || me.partnerWide;

  const test = useMutation({
    mutationFn: (c: NotificationChannel) => alertsApi.testChannel(c.id),
    onSuccess: (_, c) => {
      notifySuccess(`Test sent to ${c.name}. Its result appears under Deliveries in a few seconds.`);
      setTimeout(() => {
        void queryClient.invalidateQueries({ queryKey: alertKeys.deliveries(c.id) });
      }, 3000);
    },
    onError: notifyError,
  });
  const remove = useMutation({
    mutationFn: (c: NotificationChannel) => alertsApi.deleteChannel(c.id),
    onSuccess: async () => {
      notifySuccess('Channel deleted');
      setDeleting(null);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: alertKeys.channels }),
        queryClient.invalidateQueries({ queryKey: alertKeys.rules }),
      ]);
    },
    onError: notifyError,
  });

  const createButton = (
    <Button
      size="sm"
      onClick={() => {
        setEditing('new');
      }}
    >
      <Plus aria-hidden="true" />
      New channel
    </Button>
  );

  return (
    <>
      <Panel
        title="Notification channels"
        description="Where alerts and events are sent. Addresses of webhooks and their secrets are stored encrypted and never shown again."
        actions={createButton}
        flush
      >
        <QueryView
          query={channels}
          what="notification channels"
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyState icon={Webhook} title="No notification channels" action={createButton}>
              Alerts still appear in the dashboard. Add a channel to be told by email, webhook, Microsoft Teams or
              Slack.
            </EmptyState>
          }
        >
          {(list) => (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Channel</TableHead>
                    <TableHead scope="col">Type</TableHead>
                    <TableHead scope="col">Sends to</TableHead>
                    <TableHead scope="col">Events</TableHead>
                    <TableHead scope="col">Scope</TableHead>
                    <TableHead scope="col">Status</TableHead>
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.map((c) => (
                    <TableRow key={c.id}>
                      <TableHead
                        scope="row"
                        className="text-foreground h-auto py-2 text-sm font-medium whitespace-normal"
                      >
                        {c.name}
                      </TableHead>
                      <TableCell>{CHANNEL_LABEL[c.type] ?? c.type}</TableCell>
                      <TableCell className="max-w-64 whitespace-normal">
                        <Destination channel={c} />
                      </TableCell>
                      <TableCell className="max-w-56 whitespace-normal">
                        {c.type === 'webhook' ? (
                          c.eventTypes.length > 0 ? (
                            <span className="ident text-xs">{c.eventTypes.join(', ')}</span>
                          ) : (
                            <span className="text-muted-foreground">Only alerts from rules that name it</span>
                          )
                        ) : (
                          <span className="text-muted-foreground">Alerts from rules that name it</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {c.organizationId === null
                          ? 'All organizations'
                          : (orgName.get(c.organizationId) ?? 'One organization')}
                      </TableCell>
                      <TableCell>
                        <StatusPill tone={c.enabled ? 'ok' : 'idle'}>{c.enabled ? 'On' : 'Off'}</StatusPill>
                      </TableCell>
                      <TableCell className="py-1 text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={test.isPending || !c.enabled}
                            title={c.enabled ? undefined : 'Turn the channel on to test it'}
                            onClick={() => {
                              test.mutate(c);
                            }}
                          >
                            <Send aria-hidden="true" />
                            Test<span className="sr-only"> {c.name}</span>
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setHistory(c);
                            }}
                          >
                            <History aria-hidden="true" />
                            Deliveries<span className="sr-only"> of {c.name}</span>
                          </Button>
                          {canChange(c) ? (
                            <>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => {
                                  setEditing(c);
                                }}
                              >
                                <Pencil aria-hidden="true" />
                                Edit<span className="sr-only"> {c.name}</span>
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                className="text-destructive hover:text-destructive"
                                onClick={() => {
                                  setDeleting(c);
                                }}
                              >
                                <Trash2 aria-hidden="true" />
                                Delete<span className="sr-only"> {c.name}</span>
                              </Button>
                            </>
                          ) : null}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </QueryView>
      </Panel>

      <Dialog
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setEditing(null);
          }
        }}
      >
        <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-xl">
          {editing !== null ? (
            <ChannelFormView
              channel={editing === 'new' ? null : editing}
              organizations={organizations}
              webhookEvents={catalog.data?.webhookEvents ?? []}
              partnerWide={me.partnerWide}
              onDone={() => {
                setEditing(null);
              }}
            />
          ) : null}
        </DialogContent>
      </Dialog>

      <Dialog
        open={history !== null}
        onOpenChange={(open) => {
          if (!open) {
            setHistory(null);
          }
        }}
      >
        <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-2xl">
          {history ? <Deliveries channel={history} /> : null}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
          }
        }}
        title={`Delete the channel ${deleting?.name ?? ''}?`}
        description={<p>Rules that notify this channel keep working but no longer send anything to it.</p>}
        confirmLabel="Delete channel"
        destructive
        pending={remove.isPending}
        onConfirm={() => {
          if (deleting) {
            remove.mutate(deleting);
          }
        }}
      />
    </>
  );
}

function Deliveries({ channel }: { channel: NotificationChannel }) {
  const deliveries = useQuery({
    queryKey: alertKeys.deliveries(channel.id),
    queryFn: () => alertsApi.deliveries(channel.id),
    refetchInterval: 5000,
  });
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <DialogHeader>
        <DialogTitle>Deliveries to {channel.name}</DialogTitle>
        <DialogDescription>
          The 50 most recent notifications. A failed delivery is tried again a few times; the last error is shown.
        </DialogDescription>
      </DialogHeader>
      <QueryView
        query={deliveries}
        what="deliveries"
        isEmpty={(d) => d.length === 0}
        empty={<EmptyState title="Nothing has been sent to this channel yet" />}
        rows={4}
      >
        {(list) => (
          <div className="overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Created</TableHead>
                  <TableHead scope="col">Event</TableHead>
                  <TableHead scope="col">Result</TableHead>
                  <TableHead scope="col" className="text-right">
                    Attempts
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="whitespace-nowrap">{formatLogTime(d.createdAt)}</TableCell>
                    <TableCell className="ident">{d.eventType}</TableCell>
                    <TableCell className="whitespace-normal">
                      {d.deliveredAt ? (
                        <StatusPill tone="ok">
                          Delivered <RelativeTime value={d.deliveredAt} />
                        </StatusPill>
                      ) : d.lastError ? (
                        <>
                          <StatusPill tone="danger">Failed</StatusPill>
                          <span className="mt-1 block text-xs break-words">{d.lastError}</span>
                        </>
                      ) : (
                        <StatusPill tone="info">Waiting to be sent</StatusPill>
                      )}
                    </TableCell>
                    <TableCell className="text-right">{d.attempts}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </QueryView>
    </div>
  );
}

function ChannelFormView({
  channel,
  organizations,
  webhookEvents,
  partnerWide,
  onDone,
}: {
  channel: NotificationChannel | null;
  organizations: Organization[];
  webhookEvents: string[];
  partnerWide: boolean;
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<ChannelForm>({
    type: channel && isChannelType(channel.type) ? channel.type : 'email',
    name: channel?.name ?? '',
    recipients: (channel?.to ?? []).join('\n'),
    url: '',
    secret: '',
    eventTypes: channel?.eventTypes ?? [],
  });
  const [organizationId, setOrganizationId] = useState(
    channel ? (channel.organizationId ?? SHARED) : partnerWide ? SHARED : (organizations[0]?.id ?? SHARED),
  );
  const [enabled, setEnabled] = useState(channel?.enabled ?? true);
  const [touched, setTouched] = useState(false);
  const set = (patch: Partial<ChannelForm>) => {
    setForm((old) => ({ ...old, ...patch }));
  };

  const editing = channel !== null;
  const checked = validateChannel(form, editing);
  const errors = touched && !checked.ok ? checked.errors : {};
  const scopeValid = editing || partnerWide || organizationId !== SHARED;

  const save = useMutation({
    mutationFn: async () => {
      if (!checked.ok) {
        return;
      }
      if (channel) {
        await alertsApi.updateChannel(channel.id, { ...checked.input, enabled });
      } else {
        await alertsApi.createChannel({
          ...checked.input,
          type: form.type,
          enabled,
          organizationId: organizationId === SHARED ? null : organizationId,
        });
      }
    },
    onSuccess: async () => {
      notifySuccess(channel ? 'Channel saved' : 'Channel created. Use Test to check that it arrives.');
      await queryClient.invalidateQueries({ queryKey: alertKeys.channels });
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

  const urlLabel =
    form.type === 'teams' ? 'Teams webhook URL' : form.type === 'slack' ? 'Slack webhook URL' : 'Webhook URL';

  return (
    <form onSubmit={submit} noValidate className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <DialogHeader>
        <DialogTitle>{channel ? 'Edit notification channel' : 'New notification channel'}</DialogTitle>
        <DialogDescription>
          {channel
            ? 'The type and organization of a channel cannot be changed.'
            : 'A channel does nothing until an alert rule names it, or (for webhooks) until you choose events below.'}
        </DialogDescription>
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {save.error ? <InlineAlert live={false}>{errorMessage(save.error)}</InlineAlert> : null}
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Type">
          {(control) => (
            <NativeSelect
              {...control}
              className="w-full"
              value={form.type}
              disabled={editing}
              onChange={(e) => {
                if (isChannelType(e.target.value)) {
                  set({ type: e.target.value });
                }
              }}
            >
              {CHANNEL_TYPES.map((t) => (
                <NativeSelectOption key={t} value={t}>
                  {CHANNEL_LABEL[t]}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        </Field>
        <Field label="Scope" error={touched && !scopeValid ? 'Choose an organization.' : null}>
          {(control) => (
            <NativeSelect
              {...control}
              className="w-full"
              value={organizationId}
              disabled={editing}
              onChange={(e) => {
                setOrganizationId(e.target.value);
              }}
            >
              {partnerWide || channel?.organizationId === null ? (
                <NativeSelectOption value={SHARED}>All organizations</NativeSelectOption>
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

      {form.type === 'email' ? (
        <Field label="Recipients" hint="Up to 20 addresses, one per line." error={errors.recipients ?? null}>
          {(control) => (
            <Textarea
              {...control}
              rows={3}
              value={form.recipients}
              spellCheck={false}
              autoCapitalize="none"
              onChange={(e) => {
                set({ recipients: e.target.value });
              }}
            />
          )}
        </Field>
      ) : (
        <Field
          label={urlLabel}
          hint={
            editing
              ? `Currently sends to ${channel.urlHost ?? 'an address'} (the full address is not shown). Leave empty to keep it.`
              : 'The full address, starting with https://. It is stored encrypted and not shown again.'
          }
          error={errors.url ?? null}
        >
          {(control) => (
            <Input
              {...control}
              type="url"
              className="ident"
              value={form.url}
              maxLength={2000}
              autoComplete="off"
              spellCheck={false}
              placeholder={editing ? 'Unchanged' : 'https://'}
              onChange={(e) => {
                set({ url: e.target.value });
              }}
            />
          )}
        </Field>
      )}

      {form.type === 'webhook' ? (
        <>
          <Field
            label="Signing secret (optional)"
            hint={
              editing
                ? channel.hasSecret
                  ? 'A secret is set. Leave empty to keep it; type a new one to replace it.'
                  : 'No secret is set. Type one to start signing requests.'
                : 'With a secret, every request is signed so the receiver can check that it came from this server.'
            }
            error={errors.secret ?? null}
          >
            {(control) => (
              <Input
                {...control}
                type="password"
                className="ident"
                value={form.secret}
                maxLength={256}
                autoComplete="new-password"
                placeholder={editing && channel.hasSecret ? 'Unchanged' : ''}
                onChange={(e) => {
                  set({ secret: e.target.value });
                }}
              />
            )}
          </Field>
          <div className="bg-muted rounded-md px-3 py-2 text-sm">
            <p className="font-medium">How the receiver checks the signature</p>
            <p className="text-muted-foreground mt-1">
              Each request carries <span className="ident">X-Dranzo-Timestamp</span> and{' '}
              <span className="ident">X-Dranzo-Signature: sha256=&lt;hex&gt;</span>. The hex value is HMAC-SHA256, keyed
              with the secret, of the timestamp, a full stop and the raw request body:
            </p>
            <pre className="ident mt-1 overflow-x-auto text-xs">
              {'sha256=HMAC_SHA256(secret, "<timestamp>.<body>")'}
            </pre>
            <p className="text-muted-foreground mt-1">
              Reject requests whose signature does not match or whose timestamp is old.{' '}
              <span className="ident">X-Dranzo-Event</span> names the event and{' '}
              <span className="ident">X-Dranzo-Delivery</span> identifies the delivery.
            </p>
          </div>
          <fieldset className="grid gap-2">
            <legend className="mb-1 text-sm font-medium">Also send these events</legend>
            <p className="text-muted-foreground -mt-1 text-xs">
              Sent for every organization this channel covers, whether or not an alert rule names the channel.
            </p>
            <div className="grid gap-2 sm:grid-cols-2">
              {webhookEvents.map((event) => (
                <div key={event} className="flex items-start gap-2">
                  <Checkbox
                    id={`channel-event-${event}`}
                    className="mt-0.5"
                    checked={form.eventTypes.includes(event)}
                    onCheckedChange={(v) => {
                      set({
                        eventTypes:
                          v === true ? [...form.eventTypes, event] : form.eventTypes.filter((x) => x !== event),
                      });
                    }}
                  />
                  <Label htmlFor={`channel-event-${event}`} className="grid gap-0 font-normal">
                    <span>{WEBHOOK_EVENT_LABEL[event] ?? event}</span>
                    <span className="ident text-muted-foreground text-xs">{event}</span>
                  </Label>
                </div>
              ))}
            </div>
          </fieldset>
        </>
      ) : null}

      <div className="flex items-center gap-2">
        <Switch id="channel-enabled" checked={enabled} onCheckedChange={setEnabled} />
        <Label htmlFor="channel-enabled" className="font-normal">
          Channel is on
        </Label>
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={save.isPending}>
          Cancel
        </Button>
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? 'Saving…' : channel ? 'Save channel' : 'Create channel'}
        </Button>
      </DialogFooter>
    </form>
  );
}
