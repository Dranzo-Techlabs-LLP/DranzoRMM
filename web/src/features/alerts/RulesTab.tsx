import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Pencil, Plus, SlidersHorizontal, Trash2 } from 'lucide-react';
import { useState, type SyntheticEvent } from 'react';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Field } from '@/components/field';
import { EmptyState, Panel, QueryView } from '@/components/page';
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
import { errorMessage, type Organization } from '@/lib/api';
import {
  alertKeys,
  alertsApi,
  type AlertCatalog,
  type AlertRule,
  type AlertRuleInput,
  type NotificationChannel,
} from '@/lib/api/alerts';
import { P } from '@/lib/auth/permissions';
import { useAccess, useMe } from '@/lib/auth/session';
import { notifyError, notifySuccess } from '@/lib/notify';
import {
  alertTypeDescription,
  alertTypeLabel,
  CHANNEL_LABEL,
  describeRuleParams,
  paramsToForm,
  parseRuleParams,
  ruleParamFields,
  severityLook,
} from './rule-params';

const SHARED = '';

export function RulesTab() {
  const access = useAccess();
  const me = useMe();
  const queryClient = useQueryClient();
  const { organizations } = useOrgFilter();
  const canManage = access.has(P.alertsManage);
  const canSeeChannels = access.has(P.notificationsManage);
  const [editing, setEditing] = useState<AlertRule | 'new' | null>(null);
  const [deleting, setDeleting] = useState<AlertRule | null>(null);

  const rules = useQuery({ queryKey: alertKeys.rules, queryFn: alertsApi.rules });
  const catalog = useQuery({ queryKey: alertKeys.catalog, queryFn: alertsApi.catalog, staleTime: 5 * 60_000 });
  const channels = useQuery({ queryKey: alertKeys.channels, queryFn: alertsApi.channels, enabled: canSeeChannels });
  const orgName = new Map(organizations.map((o) => [o.id, o.name]));
  const channelName = new Map((channels.data ?? []).map((c) => [c.id, c.name]));
  // Shared rules (no organization) can only be changed with partner-wide scope.
  const canChange = (rule: AlertRule) => canManage && (rule.organizationId !== null || me.partnerWide);

  const toggle = useMutation({
    mutationFn: (rule: AlertRule) => alertsApi.updateRule(rule.id, { enabled: !rule.enabled }),
    onSuccess: async (_, rule) => {
      notifySuccess(rule.enabled ? 'Rule turned off' : 'Rule turned on');
      await queryClient.invalidateQueries({ queryKey: alertKeys.rules });
    },
    onError: notifyError,
  });
  const remove = useMutation({
    mutationFn: (rule: AlertRule) => alertsApi.deleteRule(rule.id),
    onSuccess: async () => {
      notifySuccess('Rule deleted');
      setDeleting(null);
      await queryClient.invalidateQueries({ queryKey: alertKeys.rules });
    },
    onError: notifyError,
  });

  const createButton = canManage ? (
    <Button
      size="sm"
      disabled={!catalog.data}
      onClick={() => {
        setEditing('new');
      }}
    >
      <Plus aria-hidden="true" />
      New rule
    </Button>
  ) : null;

  return (
    <>
      <Panel
        title="Alert rules"
        description="A rule opens an alert on every device it covers when its condition is met."
        actions={createButton}
        flush
      >
        <QueryView
          query={rules}
          what="alert rules"
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyState icon={SlidersHorizontal} title="No alert rules" action={createButton}>
              Without rules, no alerts are raised.
            </EmptyState>
          }
        >
          {(list) => (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Rule</TableHead>
                    <TableHead scope="col">Condition</TableHead>
                    <TableHead scope="col">Severity</TableHead>
                    <TableHead scope="col">Applies to</TableHead>
                    <TableHead scope="col">Notifies</TableHead>
                    <TableHead scope="col">On</TableHead>
                    {canManage ? (
                      <TableHead scope="col">
                        <span className="sr-only">Actions</span>
                      </TableHead>
                    ) : null}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.map((r) => {
                    const look = severityLook(r.severity);
                    const settings = describeRuleParams(r.type, r.params);
                    return (
                      <TableRow key={r.id}>
                        <TableHead
                          scope="row"
                          className="text-foreground h-auto py-2 text-sm font-medium whitespace-normal"
                        >
                          {r.name}
                        </TableHead>
                        <TableCell className="whitespace-normal">
                          <div>{alertTypeLabel(r.type)}</div>
                          {settings ? <div className="text-muted-foreground text-xs">{settings}</div> : null}
                        </TableCell>
                        <TableCell>
                          <StatusPill tone={look.tone}>{look.label}</StatusPill>
                        </TableCell>
                        <TableCell>
                          {r.organizationId === null
                            ? 'All organizations'
                            : (orgName.get(r.organizationId) ?? 'One organization')}
                        </TableCell>
                        <TableCell className="whitespace-normal">
                          {r.channelIds.length === 0 ? (
                            <span className="text-muted-foreground">Nobody</span>
                          ) : canSeeChannels ? (
                            r.channelIds.map((id) => channelName.get(id) ?? 'Unknown channel').join(', ')
                          ) : (
                            `${r.channelIds.length} ${r.channelIds.length === 1 ? 'channel' : 'channels'}`
                          )}
                        </TableCell>
                        <TableCell>
                          {canChange(r) ? (
                            <Switch
                              checked={r.enabled}
                              disabled={toggle.isPending}
                              aria-label={`${r.name} is ${r.enabled ? 'on' : 'off'}`}
                              onCheckedChange={() => {
                                toggle.mutate(r);
                              }}
                            />
                          ) : r.enabled ? (
                            'On'
                          ) : (
                            <span className="text-muted-foreground">Off</span>
                          )}
                        </TableCell>
                        {canManage ? (
                          <TableCell className="py-1 text-right">
                            {canChange(r) ? (
                              <div className="flex justify-end gap-1">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => {
                                    setEditing(r);
                                  }}
                                >
                                  <Pencil aria-hidden="true" />
                                  Edit<span className="sr-only"> {r.name}</span>
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="text-destructive hover:text-destructive"
                                  onClick={() => {
                                    setDeleting(r);
                                  }}
                                >
                                  <Trash2 aria-hidden="true" />
                                  Delete<span className="sr-only"> {r.name}</span>
                                </Button>
                              </div>
                            ) : null}
                          </TableCell>
                        ) : null}
                      </TableRow>
                    );
                  })}
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
          {editing !== null && catalog.data ? (
            <RuleForm
              rule={editing === 'new' ? null : editing}
              catalog={catalog.data}
              organizations={organizations}
              channels={canSeeChannels ? (channels.data ?? []) : null}
              partnerWide={me.partnerWide}
              onDone={() => {
                setEditing(null);
              }}
            />
          ) : null}
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
          }
        }}
        title={`Delete the rule ${deleting?.name ?? ''}?`}
        description={
          <p>
            No new alerts are raised for this condition. Alerts it already opened stay in the list until they are
            resolved.
          </p>
        }
        confirmLabel="Delete rule"
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

function RuleForm({
  rule,
  catalog,
  organizations,
  channels,
  partnerWide,
  onDone,
}: {
  rule: AlertRule | null;
  catalog: AlertCatalog;
  organizations: Organization[];
  /** `null` when the user may not list channels: the rule's channels are then left as they are. */
  channels: NotificationChannel[] | null;
  partnerWide: boolean;
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(rule?.name ?? '');
  const [type, setType] = useState(rule?.type ?? catalog.types[0] ?? '');
  const [severity, setSeverity] = useState(rule?.severity ?? 'warning');
  const [organizationId, setOrganizationId] = useState(
    rule ? (rule.organizationId ?? SHARED) : partnerWide ? SHARED : (organizations[0]?.id ?? SHARED),
  );
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [channelIds, setChannelIds] = useState<string[]>(rule?.channelIds ?? []);
  const [form, setForm] = useState(() => paramsToForm(type, rule?.params));
  const [touched, setTouched] = useState(false);

  const fields = ruleParamFields(type);
  const parsed = parseRuleParams(type, form);
  const nameValid = name.trim().length > 0 && name.trim().length <= 120;
  const scopeValid = rule !== null || partnerWide || organizationId !== SHARED;
  // Channels a rule may use: shared ones and those of the rule's own organization.
  const usable = (channels ?? []).filter(
    (c) => c.organizationId === null || organizationId === SHARED || c.organizationId === organizationId,
  );

  const save = useMutation({
    mutationFn: async () => {
      const input: AlertRuleInput = {
        name: name.trim(),
        severity,
        enabled,
        params: parsed.ok ? parsed.params : {},
        ...(channels ? { channelIds: channelIds.filter((id) => usable.some((c) => c.id === id)) } : {}),
      };
      if (rule) {
        await alertsApi.updateRule(rule.id, input);
      } else {
        await alertsApi.createRule({
          ...input,
          type,
          organizationId: organizationId === SHARED ? null : organizationId,
        });
      }
    },
    onSuccess: async () => {
      notifySuccess(rule ? 'Rule saved' : 'Rule created');
      await queryClient.invalidateQueries({ queryKey: alertKeys.rules });
      onDone();
    },
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (nameValid && parsed.ok && scopeValid) {
      save.mutate();
    }
  };

  return (
    <form onSubmit={submit} noValidate className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <DialogHeader>
        <DialogTitle>{rule ? 'Edit alert rule' : 'New alert rule'}</DialogTitle>
        <DialogDescription>
          {rule
            ? 'The condition type and the organization of a rule cannot be changed. Create a new rule for those.'
            : 'Choose what to watch for, how serious it is and who should hear about it.'}
        </DialogDescription>
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {save.error ? <InlineAlert live={false}>{errorMessage(save.error)}</InlineAlert> : null}
      </div>
      <Field label="Name" error={touched && !nameValid ? 'Enter a name of up to 120 characters.' : null}>
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
      <Field label="Condition" hint={alertTypeDescription(type)}>
        {(control) => (
          <NativeSelect
            {...control}
            className="w-full"
            value={type}
            disabled={rule !== null}
            onChange={(e) => {
              setType(e.target.value);
              setForm(paramsToForm(e.target.value, null));
            }}
          >
            {catalog.types.map((t) => (
              <NativeSelectOption key={t} value={t}>
                {alertTypeLabel(t)}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        )}
      </Field>
      {fields.map((f) => (
        <Field
          key={f.key}
          label={`${f.label} (${f.unit})`}
          hint={f.hint}
          error={touched && !parsed.ok ? (parsed.errors[f.key] ?? null) : null}
        >
          {(control) => (
            <Input
              {...control}
              className="max-w-40"
              inputMode={f.integer ? 'numeric' : 'decimal'}
              value={form[f.key] ?? ''}
              maxLength={8}
              onChange={(e) => {
                setForm((old) => ({ ...old, [f.key]: e.target.value }));
              }}
            />
          )}
        </Field>
      ))}
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Severity">
          {(control) => (
            <NativeSelect
              {...control}
              className="w-full"
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
              }}
            >
              {catalog.severities.map((s) => (
                <NativeSelectOption key={s} value={s}>
                  {severityLook(s).label}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        </Field>
        <Field
          label="Applies to"
          error={touched && !scopeValid ? 'Choose an organization.' : null}
          hint={
            !partnerWide && !rule ? 'Rules for all organizations need a role that covers all organizations.' : undefined
          }
        >
          {(control) => (
            <NativeSelect
              {...control}
              className="w-full"
              value={organizationId}
              disabled={rule !== null}
              onChange={(e) => {
                setOrganizationId(e.target.value);
              }}
            >
              {partnerWide || rule?.organizationId === null ? (
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
      {channels ? (
        <fieldset className="grid gap-2">
          <legend className="mb-1 text-sm font-medium">Notify these channels when an alert opens</legend>
          {usable.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              No notification channels yet. The alert still appears in the dashboard; add a channel on the Notification
              channels tab to be told by email, webhook, Teams or Slack.
            </p>
          ) : (
            usable.map((c) => (
              <div key={c.id} className="flex items-center gap-2">
                <Checkbox
                  id={`rule-channel-${c.id}`}
                  checked={channelIds.includes(c.id)}
                  onCheckedChange={(v) => {
                    setChannelIds((ids) => (v === true ? [...ids, c.id] : ids.filter((id) => id !== c.id)));
                  }}
                />
                <Label htmlFor={`rule-channel-${c.id}`} className="font-normal">
                  {c.name}{' '}
                  <span className="text-muted-foreground">
                    ({CHANNEL_LABEL[c.type] ?? c.type}
                    {c.enabled ? '' : ', turned off'})
                  </span>
                </Label>
              </div>
            ))
          )}
        </fieldset>
      ) : null}
      <div className="flex items-center gap-2">
        <Switch id="rule-enabled" checked={enabled} onCheckedChange={setEnabled} />
        <Label htmlFor="rule-enabled" className="font-normal">
          Rule is on
        </Label>
      </div>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={save.isPending}>
          Cancel
        </Button>
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? 'Saving…' : rule ? 'Save rule' : 'Create rule'}
        </Button>
      </DialogFooter>
    </form>
  );
}
