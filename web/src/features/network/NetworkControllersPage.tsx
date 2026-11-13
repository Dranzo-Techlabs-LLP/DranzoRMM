import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Plus, RefreshCw, RotateCw, Router, Trash2, Wifi } from 'lucide-react';
import { useState } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { Field } from '@/components/field';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useOrgFilter } from '@/app/org-filter';
import { useSites } from '@/features/tenants/queries';
import { errorMessage } from '@/lib/api';
import { controllersApi, networkKeys, type NetworkController } from '@/lib/api/network';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { formatDuration } from '@/lib/format';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { controllerProblem, wifiProblem, type ControllerForm, type WifiForm } from './model';

function ControllerDialog({
  controller,
  defaultOrg,
  onDone,
}: {
  controller: NetworkController | null;
  defaultOrg: string;
  onDone: () => void;
}) {
  const { organizations } = useOrgFilter();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<ControllerForm>({
    organizationId: controller?.organizationId ?? defaultOrg,
    siteId: controller?.siteId ?? '',
    name: controller?.name ?? '',
    baseUrl: controller?.baseUrl ?? 'https://',
    unifiSite: controller?.unifiSite ?? 'default',
    unifiOs: controller?.unifiOs ?? true,
    authMode: controller?.authMode ?? 'apikey',
    username: controller?.username ?? '',
    secret: '',
    certificateSha256: '',
  });
  const sites = useSites(form.organizationId || undefined, Boolean(form.organizationId));
  const [problem, setProblem] = useState<string | null>(null);
  const set = (patch: Partial<ControllerForm>) => {
    setForm((f) => ({ ...f, ...patch }));
  };
  const save = useMutation({
    mutationFn: () => {
      const input = {
        siteId: form.siteId || (controller ? '00000000-0000-0000-0000-000000000000' : null),
        name: form.name.trim(),
        baseUrl: form.baseUrl.trim(),
        unifiSite: form.unifiSite,
        unifiOs: form.unifiOs,
        authMode: form.authMode,
        username: form.authMode === 'password' ? form.username.trim() : undefined,
        secret: form.secret || undefined,
        certificateSha256: form.certificateSha256 || undefined,
      };
      return controller
        ? controllersApi.update(controller.id, input)
        : controllersApi.create({ ...input, organizationId: form.organizationId });
    },
    onSuccess: async () => {
      notifySuccess(controller ? 'Controller updated.' : 'Controller added. Use "Sync now" to check the connection.');
      await queryClient.invalidateQueries({ queryKey: networkKeys.all });
      onDone();
    },
    onError: (e) => {
      setProblem(errorMessage(e));
      notifyError(e);
    },
  });
  return (
    <form
      className="grid gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        const p = controllerProblem(form, controller === null);
        setProblem(p);
        if (!p) {
          save.mutate();
        }
      }}
    >
      <DialogHeader>
        <DialogTitle>{controller ? `Edit ${controller.name}` : 'Add a UniFi controller'}</DialogTitle>
        <DialogDescription>
          DranzoRMM connects to the UniFi Network application on your console (UDM, Cloud Key, UniFi OS Server) to set
          up Wi-Fi, list network devices and block clients. Create an API key in UniFi Network: Settings → Control Plane
          → Integrations. The key is stored encrypted and never shown again. You will be asked for your authenticator
          code.
        </DialogDescription>
      </DialogHeader>
      {!controller ? (
        <Field label="Organization">
          {(control) => (
            <NativeSelect
              {...control}
              value={form.organizationId}
              onChange={(e) => {
                set({ organizationId: e.target.value, siteId: '' });
              }}
            >
              <NativeSelectOption value="">Choose…</NativeSelectOption>
              {organizations.map((o) => (
                <NativeSelectOption key={o.id} value={o.id}>
                  {o.name}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        </Field>
      ) : null}
      <Field label="Site" hint="Its discovered devices are linked to this controller's Wi-Fi clients.">
        {(control) => (
          <NativeSelect
            {...control}
            value={form.siteId}
            onChange={(e) => {
              set({ siteId: e.target.value });
            }}
          >
            <NativeSelectOption value="">No site</NativeSelectOption>
            {(sites.data ?? []).map((s) => (
              <NativeSelectOption key={s.id} value={s.id}>
                {s.name}
              </NativeSelectOption>
            ))}
          </NativeSelect>
        )}
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name">
          {(control) => (
            <Input
              {...control}
              value={form.name}
              maxLength={100}
              onChange={(e) => {
                set({ name: e.target.value });
              }}
            />
          )}
        </Field>
        <Field label="Address" hint="https://192.168.1.1 or https://unifi.example.com:8443">
          {(control) => (
            <Input
              {...control}
              className="ident"
              value={form.baseUrl}
              onChange={(e) => {
                set({ baseUrl: e.target.value });
              }}
            />
          )}
        </Field>
        <Field label="UniFi site id" hint='Usually "default".'>
          {(control) => (
            <Input
              {...control}
              className="ident"
              value={form.unifiSite}
              onChange={(e) => {
                set({ unifiSite: e.target.value });
              }}
            />
          )}
        </Field>
        <Field label="Sign in with">
          {(control) => (
            <NativeSelect
              {...control}
              value={form.authMode}
              onChange={(e) => {
                set({ authMode: e.target.value as ControllerForm['authMode'] });
              }}
            >
              <NativeSelectOption value="apikey">API key (recommended)</NativeSelectOption>
              <NativeSelectOption value="password">Local account and password</NativeSelectOption>
            </NativeSelect>
          )}
        </Field>
        {form.authMode === 'password' ? (
          <Field label="Account">
            {(control) => (
              <Input
                {...control}
                autoComplete="off"
                value={form.username}
                onChange={(e) => {
                  set({ username: e.target.value });
                }}
              />
            )}
          </Field>
        ) : null}
        <Field
          label={form.authMode === 'apikey' ? 'API key' : 'Password'}
          hint={controller ? 'Leave empty to keep the stored one.' : undefined}
        >
          {(control) => (
            <Input
              {...control}
              type="password"
              autoComplete="new-password"
              value={form.secret}
              onChange={(e) => {
                set({ secret: e.target.value });
              }}
            />
          )}
        </Field>
      </div>
      <Field
        label="Certificate fingerprint (SHA-256, optional)"
        hint={
          controller?.pinned
            ? 'A fingerprint is set. Enter a new one to replace it.'
            : 'Needed when the console uses its own self-signed certificate.'
        }
      >
        {(control) => (
          <Input
            {...control}
            className="ident"
            value={form.certificateSha256}
            onChange={(e) => {
              set({ certificateSha256: e.target.value });
            }}
          />
        )}
      </Field>
      <div className="flex items-center gap-2">
        <Checkbox
          id="unifi-os"
          checked={form.unifiOs}
          onCheckedChange={(v) => {
            set({ unifiOs: v === true });
          }}
        />
        <Label htmlFor="unifi-os" className="font-normal">
          UniFi OS console (UDM, Cloud Key Gen2+, UniFi OS Server). Turn off for a classic self-hosted controller.
        </Label>
      </div>
      {problem ? <InlineAlert title="Check the details">{problem}</InlineAlert> : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={save.isPending}>
          Cancel
        </Button>
        <Button type="submit" disabled={save.isPending}>
          {save.isPending ? 'Saving…' : 'Save'}
        </Button>
      </DialogFooter>
    </form>
  );
}

const EMPTY_WIFI = (guest: boolean): WifiForm => ({
  enabled: true,
  ssid: guest ? 'Guest' : 'Office',
  passphrase: '',
  vlan: guest ? '20' : '10',
  subnet: guest ? '192.168.20.1/24' : '192.168.10.1/24',
  clientIsolation: true,
});

function WifiFields({
  label,
  value,
  onChange,
  guest,
}: {
  label: string;
  value: WifiForm;
  onChange: (w: WifiForm) => void;
  guest: boolean;
}) {
  const id = guest ? 'guest' : 'office';
  return (
    <fieldset className="grid gap-2 rounded-md border p-3">
      <div className="flex items-center gap-2">
        <Checkbox
          id={`${id}-on`}
          checked={value.enabled}
          onCheckedChange={(v) => {
            onChange({ ...value, enabled: v === true });
          }}
        />
        <Label htmlFor={`${id}-on`} className="font-medium">
          {label}
        </Label>
      </div>
      {value.enabled ? (
        <div className="grid gap-2 sm:grid-cols-2">
          <Field label="Network name (SSID)">
            {(control) => (
              <Input
                {...control}
                value={value.ssid}
                maxLength={32}
                onChange={(e) => {
                  onChange({ ...value, ssid: e.target.value });
                }}
              />
            )}
          </Field>
          <Field label={guest ? 'Password (empty: open network)' : 'Password'}>
            {(control) => (
              <Input
                {...control}
                type="password"
                autoComplete="new-password"
                value={value.passphrase}
                maxLength={63}
                onChange={(e) => {
                  onChange({ ...value, passphrase: e.target.value });
                }}
              />
            )}
          </Field>
          <Field label="VLAN">
            {(control) => (
              <Input
                {...control}
                inputMode="numeric"
                value={value.vlan}
                onChange={(e) => {
                  onChange({ ...value, vlan: e.target.value });
                }}
              />
            )}
          </Field>
          <Field label="Gateway and subnet">
            {(control) => (
              <Input
                {...control}
                className="ident"
                value={value.subnet}
                onChange={(e) => {
                  onChange({ ...value, subnet: e.target.value });
                }}
              />
            )}
          </Field>
          {guest ? (
            <div className="flex items-center gap-2 sm:col-span-2">
              <Checkbox
                id="guest-iso"
                checked={value.clientIsolation}
                onCheckedChange={(v) => {
                  onChange({ ...value, clientIsolation: v === true });
                }}
              />
              <Label htmlFor="guest-iso" className="font-normal">
                Guests cannot see each other&apos;s devices (client isolation)
              </Label>
            </div>
          ) : null}
        </div>
      ) : null}
    </fieldset>
  );
}

function WifiSetupDialog({ controller, onDone }: { controller: NetworkController; onDone: () => void }) {
  const queryClient = useQueryClient();
  const [office, setOffice] = useState(EMPTY_WIFI(false));
  const [guest, setGuest] = useState(EMPTY_WIFI(true));
  const [problem, setProblem] = useState<string | null>(null);
  const [steps, setSteps] = useState<string[] | null>(null);
  const run = useMutation({
    mutationFn: () => {
      const toInput = (w: WifiForm) =>
        w.enabled
          ? {
              ssid: w.ssid,
              passphrase: w.passphrase || undefined,
              vlan: Number(w.vlan),
              subnet: w.subnet.trim(),
              clientIsolation: w.clientIsolation,
            }
          : undefined;
      return controllersApi.wifiSetup(controller.id, { office: toInput(office), guest: toInput(guest) });
    },
    onSuccess: async (r) => {
      setSteps(r.steps);
      await queryClient.invalidateQueries({ queryKey: networkKeys.overview(controller.id) });
    },
    onError: (e) => {
      setProblem(errorMessage(e));
    },
  });
  if (steps) {
    return (
      <div className="grid gap-3">
        <DialogHeader>
          <DialogTitle>Wi-Fi set up</DialogTitle>
        </DialogHeader>
        <ul className="list-disc pl-5 text-sm">
          {steps.map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ul>
        <DialogFooter>
          <Button onClick={onDone}>Done</Button>
        </DialogFooter>
      </div>
    );
  }
  return (
    <form
      className="grid gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        const p =
          (!office.enabled && !guest.enabled ? 'Choose at least one network.' : null) ??
          wifiProblem('Office', office, true) ??
          wifiProblem('Guest', guest, false) ??
          (office.enabled && guest.enabled && office.vlan === guest.vlan
            ? 'Office and guest need different VLANs.'
            : null);
        setProblem(p);
        if (!p) {
          run.mutate();
        }
      }}
    >
      <DialogHeader>
        <DialogTitle>Separate office and guest Wi-Fi</DialogTitle>
        <DialogDescription>
          Creates each network on its own VLAN and subnet on {controller.name}. The guest network uses UniFi&apos;s
          guest policies, so guests reach the internet but not the office network. Existing networks with the same VLAN
          or name are reused, never changed. Passwords are sent to the controller only and not stored by DranzoRMM. You
          will be asked for your authenticator code.
        </DialogDescription>
      </DialogHeader>
      <WifiFields label="Office network" value={office} onChange={setOffice} guest={false} />
      <WifiFields label="Guest network" value={guest} onChange={setGuest} guest />
      {problem ? <InlineAlert title="Check the details">{problem}</InlineAlert> : null}
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={run.isPending}>
          Cancel
        </Button>
        <Button type="submit" disabled={run.isPending}>
          {run.isPending ? 'Setting up…' : 'Set up'}
        </Button>
      </DialogFooter>
    </form>
  );
}

function ControllerPanel({ controller }: { controller: NetworkController }) {
  const access = useAccess();
  const canConfigure = access.hasPartnerWide(P.networkConfigure);
  const canManage = access.has(P.networkManage);
  const queryClient = useQueryClient();
  const [dialog, setDialog] = useState<'edit' | 'wifi' | 'delete' | null>(null);
  const overview = useQuery({
    queryKey: networkKeys.overview(controller.id),
    queryFn: () => controllersApi.overview(controller.id),
  });
  const sync = useMutation({
    mutationFn: () => controllersApi.sync(controller.id),
    onSuccess: async (c) => {
      if (c.lastError) {
        notifyError(new Error(c.lastError));
      } else {
        notifySuccess('Synchronised with the controller.');
      }
      await queryClient.invalidateQueries({ queryKey: networkKeys.all });
    },
    onError: notifyError,
  });
  const restart = useMutation({
    mutationFn: (mac: string) => controllersApi.restartDevice(controller.id, mac),
    onSuccess: () => {
      notifySuccess('Restart requested. The device is back in a few minutes.');
    },
    onError: notifyError,
  });
  const remove = useMutation({
    mutationFn: () => controllersApi.remove(controller.id),
    onSuccess: async () => {
      setDialog(null);
      await queryClient.invalidateQueries({ queryKey: networkKeys.all });
    },
    onError: notifyError,
  });
  return (
    <Panel
      title={controller.name}
      description={
        <>
          {controller.baseUrl} · site {controller.unifiSite} ·{' '}
          {controller.lastSyncAt ? (
            <>
              synchronised <RelativeTime value={controller.lastSyncAt} />
            </>
          ) : (
            'not synchronised yet'
          )}
        </>
      }
      actions={
        <div className="flex flex-wrap gap-2">
          {canManage ? (
            <Button
              size="sm"
              variant="outline"
              disabled={sync.isPending}
              onClick={() => {
                sync.mutate();
              }}
            >
              <RefreshCw aria-hidden="true" />
              Sync now
            </Button>
          ) : null}
          {canConfigure ? (
            <>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setDialog('wifi');
                }}
              >
                <Wifi aria-hidden="true" />
                Guest &amp; office Wi-Fi
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setDialog('edit');
                }}
              >
                Edit
              </Button>
              <Button
                size="icon"
                variant="ghost"
                aria-label={`Remove ${controller.name}`}
                onClick={() => {
                  setDialog('delete');
                }}
              >
                <Trash2 aria-hidden="true" />
              </Button>
            </>
          ) : null}
        </div>
      }
    >
      {controller.lastError ? (
        <InlineAlert title="Last synchronisation failed">{controller.lastError}</InlineAlert>
      ) : null}
      <QueryView query={overview} what="controller data">
        {(data) =>
          !data.reachable ? (
            <InlineAlert title="The controller cannot be reached">{data.error}</InlineAlert>
          ) : (
            <div className="grid gap-4">
              <p className="text-muted-foreground text-sm">
                {String(data.clientCount ?? 0)} clients connected, {String(data.guestClientCount ?? 0)} on guest
                networks.
              </p>
              <div>
                <h3 className="mb-1 text-sm font-semibold">Network devices</h3>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead>Model</TableHead>
                      <TableHead>IP</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Clients</TableHead>
                      <TableHead>Firmware</TableHead>
                      {canManage ? <TableHead className="text-right">Actions</TableHead> : null}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(data.devices ?? []).map((d) => (
                      <TableRow key={d.mac}>
                        <TableCell className="font-medium">{d.name || d.mac}</TableCell>
                        <TableCell>{d.model}</TableCell>
                        <TableCell className="ident">{d.ip}</TableCell>
                        <TableCell>
                          <StatusPill tone={d.state === 'online' ? 'ok' : d.state === 'offline' ? 'danger' : 'warn'}>
                            {d.state}
                          </StatusPill>
                          {d.uptimeSeconds ? (
                            <div className="text-muted-foreground text-xs">up {formatDuration(d.uptimeSeconds)}</div>
                          ) : null}
                        </TableCell>
                        <TableCell className="tabular-nums">{d.clients ?? '—'}</TableCell>
                        <TableCell>
                          {d.version}
                          {d.upgradable ? <div className="text-warn text-xs">Update available</div> : null}
                        </TableCell>
                        {canManage ? (
                          <TableCell className="text-right">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => {
                                restart.mutate(d.mac);
                              }}
                            >
                              <RotateCw aria-hidden="true" />
                              Restart<span className="sr-only"> {d.name}</span>
                            </Button>
                          </TableCell>
                        ) : null}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <h3 className="mb-1 text-sm font-semibold">Wi-Fi networks</h3>
                  <ul className="grid gap-1 text-sm">
                    {(data.wlans ?? []).map((w) => (
                      <li key={w.id} className="flex flex-wrap items-center gap-2">
                        <Wifi aria-hidden="true" className="text-muted-foreground size-4" />
                        <span className="font-medium">{w.name}</span>
                        {w.isGuest ? (
                          <StatusPill tone="info">Guest</StatusPill>
                        ) : (
                          <StatusPill tone="ok">Office</StatusPill>
                        )}
                        <span className="text-muted-foreground text-xs">
                          {w.security === 'open' ? 'open' : w.security === 'wpaeap' ? '802.1X' : 'password'}
                          {w.network ? ` · ${w.network}` : ''}
                          {w.clientIsolation ? ' · client isolation' : ''}
                          {!w.enabled ? ' · off' : ''}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h3 className="mb-1 text-sm font-semibold">Networks (VLANs)</h3>
                  <ul className="grid gap-1 text-sm">
                    {(data.networks ?? []).map((n) => (
                      <li key={n.id}>
                        <span className="font-medium">{n.name}</span>{' '}
                        <span className="text-muted-foreground text-xs">
                          {n.purpose}
                          {n.vlan ? ` · VLAN ${String(n.vlan)}` : ''}
                          {n.subnet ? ` · ${n.subnet}` : ''}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )
        }
      </QueryView>
      <Dialog
        open={dialog === 'edit' || dialog === 'wifi'}
        onOpenChange={(open) => {
          if (!open) {
            setDialog(null);
          }
        }}
      >
        <DialogContent className="sm:max-w-2xl">
          {dialog === 'edit' ? (
            <ControllerDialog
              controller={controller}
              defaultOrg=""
              onDone={() => {
                setDialog(null);
              }}
            />
          ) : null}
          {dialog === 'wifi' ? (
            <WifiSetupDialog
              controller={controller}
              onDone={() => {
                setDialog(null);
              }}
            />
          ) : null}
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={dialog === 'delete'}
        onOpenChange={(open) => {
          if (!open) {
            setDialog(null);
          }
        }}
        title={`Remove ${controller.name}?`}
        description="DranzoRMM forgets the controller and its key. Nothing changes on the controller itself. You will be asked for your authenticator code."
        confirmLabel="Remove"
        destructive
        pending={remove.isPending}
        onConfirm={() => {
          remove.mutate();
        }}
      />
    </Panel>
  );
}

export default function NetworkControllersPage() {
  useDocumentTitle('Wi-Fi & controllers');
  const access = useAccess();
  const { orgId } = useOrgFilter();
  const [adding, setAdding] = useState(false);
  const controllers = useQuery({
    queryKey: networkKeys.controllers(orgId ?? undefined),
    queryFn: () => controllersApi.list(orgId ?? undefined),
  });
  const canConfigure = access.hasPartnerWide(P.networkConfigure);
  return (
    <>
      <PageHeader
        title="Wi-Fi & controllers"
        description="Central network administration through your UniFi controller: access points, switches and gateways, separate office and guest Wi-Fi, and blocking devices from the network."
        actions={
          canConfigure ? (
            <Button
              size="sm"
              onClick={() => {
                setAdding(true);
              }}
            >
              <Plus aria-hidden="true" />
              Add controller
            </Button>
          ) : null
        }
      />
      <QueryView
        query={controllers}
        what="network controllers"
        isEmpty={(d) => d.length === 0}
        empty={
          <Panel>
            <EmptyState icon={Router} title="No controller connected">
              Connect your UniFi console to manage Wi-Fi networks and network devices from DranzoRMM.
            </EmptyState>
          </Panel>
        }
      >
        {(list) => (
          <div className="grid gap-4">
            {list.map((c) => (
              <ControllerPanel key={c.id} controller={c} />
            ))}
          </div>
        )}
      </QueryView>
      <Dialog open={adding} onOpenChange={setAdding}>
        <DialogContent className="sm:max-w-2xl">
          {adding ? (
            <ControllerDialog
              controller={null}
              defaultOrg={orgId ?? ''}
              onDone={() => {
                setAdding(false);
              }}
            />
          ) : null}
        </DialogContent>
      </Dialog>
    </>
  );
}
