import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, KeyRound, ShieldCheck, Wifi } from 'lucide-react';
import { useState } from 'react';
import { Field } from '@/components/field';
import { Panel } from '@/components/page';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { useOrgFilter } from '@/app/org-filter';
import { errorMessage } from '@/lib/api';
import { controllersApi, networkKeys, radiusApi, type RadiusStatus } from '@/lib/api/network';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { notifyError, notifySuccess } from '@/lib/notify';
import { radiusProblem } from './model';

function Configured({ config }: { config: RadiusStatus }) {
  const access = useAccess();
  const canConfigure = access.hasPartnerWide(P.networkConfigure);
  const controllers = useQuery({
    queryKey: networkKeys.controllers(config.organizationId),
    queryFn: () => controllersApi.list(config.organizationId),
  });
  const [controllerId, setControllerId] = useState('');
  const [radiusHost, setRadiusHost] = useState('');
  const queryClient = useQueryClient();
  const download = useMutation({ mutationFn: () => radiusApi.downloadBundle(config.id), onError: notifyError });
  const enroll = useMutation({
    mutationFn: () => radiusApi.enroll(config.id),
    onSuccess: (r) => {
      notifySuccess(
        `Enrolling ${String(r.deviceCount)} devices: each creates its key, receives a certificate and the "${config.officeSsid}" profile.`,
      );
      for (const delay of [10000, 30000]) {
        setTimeout(() => void queryClient.invalidateQueries({ queryKey: networkKeys.all }), delay);
      }
    },
    onError: notifyError,
  });
  const unifi = useMutation({
    mutationFn: () => radiusApi.useOnUnifi(config.id, { controllerId, radiusHost: radiusHost.trim() }),
    onSuccess: (r) => {
      notifySuccess(`"${r.ssid}" now uses ${r.security}. Only enrolled company devices can join it.`);
    },
    onError: notifyError,
  });
  const chosen = controllerId || controllers.data?.[0]?.id || '';
  return (
    <div className="grid gap-3">
      <p className="text-sm">
        Office Wi-Fi <span className="font-medium">{config.officeSsid}</span> · access points {config.clientsCidr} ·{' '}
        {config.installedCertificates} of {config.activeCertificates} device certificates installed ·{' '}
        {config.revokedCertificates} revoked
      </p>
      {canConfigure ? (
        <ol className="grid gap-3 text-sm">
          <li className="grid gap-1">
            <span className="font-medium">1. Run the RADIUS server</span>
            <span className="text-muted-foreground">
              Download the FreeRADIUS folder and run it with Docker on an always-on machine on the office network. It
              contains a private key and the shared secret.
            </span>
            <div>
              <Button
                size="sm"
                variant="outline"
                disabled={download.isPending}
                onClick={() => {
                  download.mutate();
                }}
              >
                <Download aria-hidden="true" />
                Download RADIUS server
              </Button>
            </div>
          </li>
          <li className="grid gap-1">
            <span className="font-medium">2. Use it for the office Wi-Fi</span>
            <div className="flex flex-wrap items-end gap-2">
              <Field label="Controller">
                {(control) => (
                  <NativeSelect
                    {...control}
                    value={chosen}
                    onChange={(e) => {
                      setControllerId(e.target.value);
                    }}
                  >
                    {(controllers.data ?? []).map((c) => (
                      <NativeSelectOption key={c.id} value={c.id}>
                        {c.name}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                )}
              </Field>
              <Field label="RADIUS server IP">
                {(control) => (
                  <Input
                    {...control}
                    className="ident w-40"
                    placeholder="192.168.1.5"
                    value={radiusHost}
                    onChange={(e) => {
                      setRadiusHost(e.target.value);
                    }}
                  />
                )}
              </Field>
              <Button
                size="sm"
                variant="outline"
                disabled={!chosen || !radiusHost || unifi.isPending}
                onClick={() => {
                  unifi.mutate();
                }}
              >
                <Wifi aria-hidden="true" />
                Switch to 802.1X
              </Button>
            </div>
          </li>
          <li className="grid gap-1">
            <span className="font-medium">3. Enroll company devices</span>
            <span className="text-muted-foreground">
              Windows and Linux devices get a certificate (the key never leaves the device) and the Wi-Fi profile. macOS
              needs a configuration profile and is not enrolled yet. Revoked, deleted and blocked devices lose access
              within 5 minutes.
            </span>
            <div>
              <Button
                size="sm"
                variant="outline"
                disabled={enroll.isPending}
                onClick={() => {
                  enroll.mutate();
                }}
              >
                <KeyRound aria-hidden="true" />
                Enroll all devices
              </Button>
            </div>
          </li>
        </ol>
      ) : null}
    </div>
  );
}

/** 802.1X (EAP-TLS): only company devices with a DranzoRMM certificate join the office Wi-Fi. */
export function RadiusPanel() {
  const access = useAccess();
  const canConfigure = access.hasPartnerWide(P.networkConfigure);
  const { orgId, organization } = useOrgFilter();
  const queryClient = useQueryClient();
  const radius = useQuery({
    queryKey: networkKeys.radius(orgId ?? undefined),
    queryFn: () => radiusApi.list(orgId ?? undefined),
  });
  const [cidr, setCidr] = useState('192.168.1.0/24');
  const [ssid, setSsid] = useState('Office');
  const [problem, setProblem] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () => radiusApi.save({ organizationId: orgId ?? '', clientsCidr: cidr.trim(), officeSsid: ssid }),
    onSuccess: async () => {
      notifySuccess('802.1X enabled. Download the RADIUS server next.');
      await queryClient.invalidateQueries({ queryKey: networkKeys.all });
    },
    onError: (e) => {
      setProblem(errorMessage(e));
    },
  });
  const configs = radius.data ?? [];
  return (
    <Panel
      title={
        <span className="inline-flex items-center gap-1.5">
          <ShieldCheck aria-hidden="true" className="size-4" />
          802.1X: company devices only on office Wi-Fi
        </span>
      }
      description="Each company device gets its own certificate; the office Wi-Fi checks it through a RADIUS server instead of a shared password."
    >
      {configs.length > 0 ? (
        <div className="grid gap-4">
          {configs.map((c) => (
            <Configured key={c.id} config={c} />
          ))}
        </div>
      ) : !orgId ? (
        <p className="text-muted-foreground text-sm">Choose an organization in the top bar to set up 802.1X.</p>
      ) : canConfigure ? (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            const p = radiusProblem(cidr, ssid);
            setProblem(p);
            if (!p) {
              save.mutate();
            }
          }}
        >
          <Field label="Access point range">
            {(control) => (
              <Input
                {...control}
                className="ident w-44"
                value={cidr}
                onChange={(e) => {
                  setCidr(e.target.value);
                }}
              />
            )}
          </Field>
          <Field label="Office Wi-Fi name">
            {(control) => (
              <Input
                {...control}
                className="w-44"
                maxLength={32}
                value={ssid}
                onChange={(e) => {
                  setSsid(e.target.value);
                }}
              />
            )}
          </Field>
          <Button type="submit" size="sm" disabled={save.isPending}>
            Enable 802.1X for {organization?.name ?? 'this organization'}
          </Button>
          {problem ? <InlineAlert title="Check the details">{problem}</InlineAlert> : null}
        </form>
      ) : (
        <p className="text-muted-foreground text-sm">Not set up for this organization.</p>
      )}
    </Panel>
  );
}
