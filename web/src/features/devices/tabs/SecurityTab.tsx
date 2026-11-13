import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ScanSearch, ShieldQuestion } from 'lucide-react';
import type { ReactNode } from 'react';
import { EmptyState, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { InlineAlert, StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { CveLink, KnownExploitedBadge, TriStateMark, VulnSeverity } from '@/features/security/posture';
import { scoreTone } from '@/features/security/posture-model';
import { cn } from '@/lib/utils';
import { securityApi, securityKeys, type DevicePosture } from '@/lib/api/security';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { formatDuration } from '@/lib/format';
import { notifyError, notifySuccess } from '@/lib/notify';
import type { DeviceTabProps } from './registry';

const METHOD: Record<string, string> = { bitlocker: 'BitLocker', filevault: 'FileVault', luks: 'LUKS', none: 'None' };
const VOLUME_STATUS: Record<string, { value: boolean | null; label: string }> = {
  encrypted: { value: true, label: 'Encrypted' },
  in_progress: { value: true, label: 'Encrypting now' },
  decrypted: { value: false, label: 'Not encrypted' },
  unknown: { value: null, label: 'Unknown' },
};
const UNSUPPORTED_LABEL: Record<string, string> = {
  antivirus: 'antivirus',
  firewall: 'firewall',
  diskEncryption: 'disk encryption',
  localAdmins: 'local administrators',
  screenLock: 'screen lock',
  listeningPorts: 'listening ports',
  lastPatchDate: 'last update date',
};

function Section({ title, summary, children }: { title: string; summary?: ReactNode; children: ReactNode }) {
  return (
    <Panel title={title} actions={summary}>
      {children}
    </Panel>
  );
}

const COMPONENT_TONE = { ok: 'ok', warn: 'warn', bad: 'danger', unknown: 'idle' } as const;
const SCORE_TEXT = { ok: 'text-ok', warn: 'text-warn', danger: 'text-danger', idle: 'text-muted-foreground' } as const;
const COMPONENT_WORD = { ok: 'OK', warn: 'Attention', bad: 'Problem', unknown: 'Unknown' } as const;

function ScoreCard({ deviceId }: { deviceId: string }) {
  const score = useQuery({
    queryKey: securityKeys.deviceScore(deviceId),
    queryFn: () => securityApi.deviceScore(deviceId),
    refetchInterval: 60_000,
  });
  if (!score.data) {
    return null;
  }
  const s = score.data;
  return (
    <Panel
      title="Security score"
      description="Antivirus, firewall, disk encryption, updates, policy compliance and vulnerabilities. Unknown parts are left out of the score."
    >
      <div className="flex flex-wrap items-start gap-6">
        <div className="min-w-24">
          <div className={cn('text-4xl font-semibold tabular-nums', SCORE_TEXT[scoreTone(s.score)])}>
            {s.score ?? '–'}
          </div>
          <div className="text-muted-foreground text-xs">
            {s.score === null ? 'Not enough data yet' : `Grade ${s.grade} of A–F`}
          </div>
        </div>
        <ul className="grid flex-1 gap-1.5 sm:grid-cols-2">
          {s.components.map((c) => (
            <li key={c.key} className="flex items-start justify-between gap-3 rounded-md border px-3 py-2">
              <div>
                <div className="font-medium">{c.label}</div>
                <div className="text-muted-foreground text-xs">{c.reason}</div>
              </div>
              <div className="text-right">
                <StatusPill tone={COMPONENT_TONE[c.status]}>{COMPONENT_WORD[c.status]}</StatusPill>
                <div className="text-muted-foreground mt-0.5 text-xs tabular-nums">
                  {c.earned === null ? '—' : `${String(Math.round(c.earned * 10) / 10)} / ${String(c.weight)}`}
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </Panel>
  );
}

function PostureDetails({ posture }: { posture: DevicePosture }) {
  const data = posture.data ?? {};
  const unsupported = new Set(data.unsupported ?? []);
  const antivirus = data.antivirus ?? [];
  const volumes = data.diskEncryption ?? [];
  const ports = [...(data.listeningPorts ?? [])].sort((a, b) => (a.port ?? 0) - (b.port ?? 0));
  const admins = data.localAdmins ?? posture.localAdmins;
  const lock = data.screenLock;
  const notSupported = <p className="text-muted-foreground">Not available on this operating system.</p>;

  return (
    <>
      {unsupported.size > 0 ? (
        <InlineAlert tone="info" live={false} title="Some items cannot be collected on this operating system">
          Not collected: {[...unsupported].map((u) => UNSUPPORTED_LABEL[u] ?? u).join(', ')}.
        </InlineAlert>
      ) : null}
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Antivirus" summary={<TriStateMark value={posture.antivirusOk} />}>
          {unsupported.has('antivirus') ? (
            notSupported
          ) : antivirus.length === 0 ? (
            <p className="text-muted-foreground">No antivirus product was reported.</p>
          ) : (
            <ul className="divide-y">
              {antivirus.map((av, i) => (
                <li
                  key={`${av.name ?? ''}-${i}`}
                  className="flex flex-wrap items-baseline justify-between gap-x-4 py-1.5 first:pt-0 last:pb-0"
                >
                  <span className="font-medium">{av.name || 'Unnamed product'}</span>
                  <span className="flex flex-wrap gap-x-3 text-xs">
                    <TriStateMark value={av.enabled ?? null} okLabel="Enabled" issueLabel="Disabled" />
                    <TriStateMark
                      value={av.upToDate ?? null}
                      okLabel="Up to date"
                      issueLabel="Out of date"
                      unknownLabel="Update state unknown"
                    />
                    {av.signatureVersion ? (
                      <span className="text-muted-foreground">
                        Definitions <span className="ident">{av.signatureVersion}</span>
                      </span>
                    ) : null}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Firewall" summary={<TriStateMark value={posture.firewallOk} okLabel="On" issueLabel="Off" />}>
          {unsupported.has('firewall') ? (
            notSupported
          ) : (
            <p className={data.firewall?.detail ? undefined : 'text-muted-foreground'}>
              {data.firewall?.detail || 'No further detail reported.'}
            </p>
          )}
        </Section>

        <Section
          title="Disk encryption"
          summary={<TriStateMark value={posture.encryptionOk} okLabel="Encrypted" issueLabel="Not encrypted" />}
        >
          {unsupported.has('diskEncryption') ? (
            notSupported
          ) : volumes.length === 0 ? (
            <p className="text-muted-foreground">No volumes were reported.</p>
          ) : (
            <ul className="divide-y">
              {volumes.map((v, i) => {
                const status = VOLUME_STATUS[v.status ?? 'unknown'] ?? { value: null, label: v.status ?? 'Unknown' };
                return (
                  <li
                    key={`${v.volume ?? ''}-${i}`}
                    className="flex flex-wrap items-baseline justify-between gap-x-4 py-1.5 first:pt-0 last:pb-0"
                  >
                    <span className="ident font-medium break-all">{v.volume || 'Volume'}</span>
                    <span className="flex flex-wrap gap-x-3 text-xs">
                      <span className="text-muted-foreground">{METHOD[v.method ?? ''] ?? v.method ?? ''}</span>
                      <TriStateMark
                        value={status.value}
                        okLabel={status.label}
                        issueLabel={status.label}
                        unknownLabel={status.label}
                      />
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </Section>

        <Section title="Screen lock">
          {unsupported.has('screenLock') ? (
            notSupported
          ) : !lock ? (
            <p className="text-muted-foreground">Not reported.</p>
          ) : (
            <p className="flex flex-wrap items-baseline gap-x-3">
              <TriStateMark
                value={lock.enabled ?? null}
                okLabel="Locks automatically"
                issueLabel="Does not lock automatically"
              />
              {typeof lock.timeoutSeconds === 'number' && lock.timeoutSeconds > 0 ? (
                <span className="text-muted-foreground">
                  after{' '}
                  {lock.timeoutSeconds < 60 ? `${lock.timeoutSeconds} seconds` : formatDuration(lock.timeoutSeconds)}{' '}
                  without activity
                </span>
              ) : null}
            </p>
          )}
        </Section>

        <Section title={`Local administrators (${admins.length})`}>
          {unsupported.has('localAdmins') ? (
            notSupported
          ) : admins.length === 0 ? (
            <p className="text-muted-foreground">None reported.</p>
          ) : (
            <ul className="flex flex-wrap gap-1.5">
              {admins.map((a) => (
                <li key={a} className="ident bg-muted rounded-sm px-1.5 py-0.5 text-xs break-all">
                  {a}
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Updates">
          <dl className="grid grid-cols-[minmax(7rem,34%)_1fr] gap-x-4 gap-y-1.5">
            <dt className="text-muted-foreground">Last update installed</dt>
            <dd>
              <RelativeTime value={data.lastPatchDate} fallback="Not reported" />
            </dd>
            <dt className="text-muted-foreground">Restart</dt>
            <dd>{data.pendingReboot ? <span className="text-warn font-medium">Pending</span> : 'Not needed'}</dd>
          </dl>
        </Section>
      </div>

      <Panel
        title={`Listening ports (${ports.length})`}
        description="Programs on this device that accept network connections."
        flush
      >
        {unsupported.has('listeningPorts') ? (
          <div className="p-4">{notSupported}</div>
        ) : ports.length === 0 ? (
          <p className="text-muted-foreground p-4">None reported.</p>
        ) : (
          <div className="max-h-96 overflow-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col" className="text-right">
                    Port
                  </TableHead>
                  <TableHead scope="col">Protocol</TableHead>
                  <TableHead scope="col">Address</TableHead>
                  <TableHead scope="col">Program</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ports.map((p, i) => (
                  <TableRow key={`${p.protocol ?? ''}-${p.address ?? ''}-${p.port ?? 0}-${i}`}>
                    <TableHead
                      scope="row"
                      className="ident text-foreground h-auto py-1.5 text-right text-sm font-medium"
                    >
                      {p.port}
                    </TableHead>
                    <TableCell className="uppercase">{p.protocol}</TableCell>
                    <TableCell className="ident">{p.address}</TableCell>
                    <TableCell className="break-all whitespace-normal">
                      {p.process || <span className="text-muted-foreground">Unknown</span>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </Panel>
    </>
  );
}

/** Security posture of one device, as its agent last reported it, and vulnerabilities matched to its software. */
export function SecurityTab({ device }: DeviceTabProps) {
  const access = useAccess();
  const queryClient = useQueryClient();
  const posture = useQuery({
    queryKey: securityKeys.devicePosture(device.id),
    queryFn: () => securityApi.devicePosture(device.id),
    refetchInterval: 60_000,
  });
  const vulnerabilities = useQuery({
    queryKey: securityKeys.deviceVulnerabilities(device.id),
    queryFn: () => securityApi.deviceVulnerabilities(device.id),
  });

  const scan = useMutation({
    mutationFn: () => securityApi.scan({ deviceIds: [device.id] }),
    onSuccess: () => {
      notifySuccess(
        device.isOnline
          ? 'Scan requested. The new report appears here in a few seconds.'
          : 'Scan requested. The device is offline and will report when it reconnects.',
      );
      // The agent answers asynchronously; look again shortly instead of waiting for the next regular refresh.
      for (const delay of [4000, 12000]) {
        setTimeout(() => {
          void queryClient.invalidateQueries({ queryKey: securityKeys.devicePosture(device.id) });
        }, delay);
      }
    },
    onError: notifyError,
  });

  const scanButton =
    access.has(P.devicesManage) && device.status !== 'revoked' ? (
      <Button
        variant="outline"
        size="sm"
        disabled={scan.isPending}
        onClick={() => {
          scan.mutate();
        }}
      >
        <ScanSearch aria-hidden="true" />
        {scan.isPending ? 'Requesting…' : 'Scan now'}
      </Button>
    ) : null;

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <ScoreCard deviceId={device.id} />
      <QueryView query={posture} what="security posture">
        {(data) =>
          data === null ? (
            <Panel>
              <EmptyState icon={ShieldQuestion} title="No security report yet" action={scanButton}>
                The agent reports antivirus, firewall, disk encryption and related settings shortly after it connects,
                then on a regular schedule.
              </EmptyState>
            </Panel>
          ) : (
            <>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-muted-foreground text-xs">
                  Reported by the agent <RelativeTime value={data.collectedAt} />.
                </p>
                {scanButton}
              </div>
              <PostureDetails posture={data} />
            </>
          )
        }
      </QueryView>

      <Panel
        title="Vulnerabilities in installed software"
        description="Matches are heuristic: software name and version compared with public CVE data. Packages from the operating system's own package manager and the operating system itself are not matched."
        flush
      >
        <QueryView
          query={vulnerabilities}
          what="vulnerabilities"
          isEmpty={(d) => d.length === 0}
          empty={<p className="text-muted-foreground px-4 py-6 text-center">No known vulnerabilities matched.</p>}
          rows={3}
        >
          {(list) => (
            <div className="max-h-[32rem] overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">CVE</TableHead>
                    <TableHead scope="col">Severity</TableHead>
                    <TableHead scope="col" className="text-right">
                      CVSS
                    </TableHead>
                    <TableHead scope="col">Software</TableHead>
                    <TableHead scope="col">Found</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.map((v) => (
                    <TableRow key={`${v.cveId}:${v.softwareName}:${v.softwareVersion}`}>
                      <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-normal">
                        <span className="flex flex-wrap items-center gap-2">
                          <CveLink cveId={v.cveId} />
                          {v.knownExploited ? <KnownExploitedBadge /> : null}
                        </span>
                      </TableHead>
                      <TableCell>
                        <VulnSeverity severity={v.severity} />
                      </TableCell>
                      <TableCell className="text-right tabular-nums">
                        {v.cvssScore === null ? (
                          <span className="text-muted-foreground">None</span>
                        ) : (
                          v.cvssScore.toFixed(1)
                        )}
                      </TableCell>
                      <TableCell className="whitespace-normal">
                        {v.softwareName} <span className="ident text-muted-foreground">{v.softwareVersion}</span>
                      </TableCell>
                      <TableCell>
                        <RelativeTime value={v.detectedAt} />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </QueryView>
      </Panel>
    </div>
  );
}
