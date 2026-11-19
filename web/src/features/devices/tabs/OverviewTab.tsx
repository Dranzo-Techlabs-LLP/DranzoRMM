import { HardDrive } from 'lucide-react';
import type { ReactNode } from 'react';
import { EmptyState, Panel } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { InlineAlert } from '@/components/status';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { currentUptimeSeconds, formatBytes, formatDateTime, formatDuration, formatPercent } from '@/lib/format';
import { cn } from '@/lib/utils';
import type { DeviceTabProps } from './registry';

function Facts({ children }: { children: ReactNode }) {
  return <dl className="grid grid-cols-[minmax(7rem,34%)_1fr] gap-x-4 gap-y-1.5">{children}</dl>;
}

function Fact({ label, children, ident = false }: { label: string; children: ReactNode; ident?: boolean }) {
  const empty = children === null || children === undefined || children === '' || children === false;
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={cn('min-w-0 break-words', ident && !empty && 'ident')}>
        {empty ? <span className="text-muted-foreground">Not reported</span> : children}
      </dd>
    </>
  );
}

/** Disk usage as a bar plus exact numbers; the fill turns to the warning/danger tone with a text flag. */
function DiskRow({ disk }: { disk: NonNullable<NonNullable<DeviceTabProps['device']['inventory']>['disks']>[number] }) {
  const total = disk.totalBytes ?? 0;
  const free = disk.freeBytes ?? 0;
  const used = Math.max(0, total - free);
  const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
  const level = pct >= 95 ? 'danger' : pct >= 85 ? 'warn' : 'ok';
  const name = disk.mountPoint || disk.device || 'Disk';
  return (
    <li className="py-2.5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4">
        <p className="min-w-0">
          <span className="ident font-medium">{name}</span>
          <span className="text-muted-foreground ml-2 text-xs">
            {[disk.device && disk.device !== name ? disk.device : null, disk.fsType].filter(Boolean).join(', ')}
          </span>
        </p>
        <p className="text-xs">
          {total > 0 ? (
            <>
              {formatBytes(used)} of {formatBytes(total)} used ({Math.round(pct)}%), {formatBytes(free)} free
              {level !== 'ok' ? (
                <span className={cn('ml-2 font-semibold', level === 'danger' ? 'text-danger' : 'text-warn')}>
                  {level === 'danger' ? 'Almost full' : 'Filling up'}
                </span>
              ) : null}
            </>
          ) : (
            <span className="text-muted-foreground">Size not reported</span>
          )}
        </p>
      </div>
      <div
        role="meter"
        aria-label={`${name} used space`}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(pct)}
        aria-valuetext={`${Math.round(pct)}% used`}
        className="bg-idle-surface mt-1.5 h-2 overflow-hidden rounded-[3px]"
      >
        <div
          className={cn(
            'h-full',
            level === 'danger' ? 'bg-danger-mark' : level === 'warn' ? 'bg-warn-mark' : 'bg-foreground/55',
          )}
          style={{ width: `${pct}%` }}
        />
      </div>
    </li>
  );
}

export function OverviewTab({ device }: DeviceTabProps) {
  const inv = device.inventory;
  if (!inv) {
    return (
      <Panel>
        <EmptyState icon={HardDrive} title="No inventory yet">
          The agent sends hardware and system details shortly after it first connects, then on a regular schedule.
        </EmptyState>
      </Panel>
    );
  }
  const disks = inv.disks ?? [];
  const network = inv.network ?? [];
  const users = inv.loggedInUsers ?? [];
  const unsupported = inv.unsupported ?? [];
  const uptime = currentUptimeSeconds(inv.bootTime, inv.uptimeSeconds, device.isOnline);

  return (
    <div className="grid gap-4">
      <p className="text-muted-foreground text-xs">
        Inventory collected <RelativeTime value={device.inventoryCollectedAt ?? inv.collectedAt} />.
      </p>
      {unsupported.length > 0 ? (
        <InlineAlert tone="info" live={false} title="Some details are not available on this operating system">
          Not collected: {unsupported.join(', ')}.
        </InlineAlert>
      ) : null}
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Hardware">
          <Facts>
            <Fact label="Manufacturer">{inv.manufacturer || device.manufacturer}</Fact>
            <Fact label="Model">{inv.model || device.model}</Fact>
            <Fact label="Serial number" ident>
              {inv.serial || device.serial}
            </Fact>
            <Fact label="Processor">{inv.cpu?.model}</Fact>
            <Fact label="Cores">
              {inv.cpu?.cores ? `${inv.cpu.cores} cores, ${inv.cpu.logicalCores ?? inv.cpu.cores} threads` : null}
            </Fact>
            <Fact label="Memory">
              {inv.memoryBytes ? (
                <>
                  {formatBytes(inv.memoryBytes)}
                  {device.memUsedPercent !== null ? (
                    <span className="text-muted-foreground"> ({formatPercent(device.memUsedPercent)} in use)</span>
                  ) : null}
                </>
              ) : null}
            </Fact>
            <Fact label="Architecture">{inv.arch || device.arch}</Fact>
          </Facts>
        </Panel>

        <Panel title="Operating system">
          <Facts>
            <Fact label="Name">{inv.os?.name || device.osName}</Fact>
            <Fact label="Version">{inv.os?.version || device.osVersion}</Fact>
            <Fact label="Build">{inv.os?.build}</Fact>
            <Fact label="Kernel" ident>
              {inv.os?.kernel}
            </Fact>
            <Fact label="Time zone">{inv.timezone}</Fact>
            <Fact label="Uptime">
              {uptime !== undefined ? formatDuration(uptime) : null}
              {inv.bootTime ? (
                <span className="text-muted-foreground"> (started {formatDateTime(inv.bootTime)})</span>
              ) : null}
            </Fact>
            <Fact label="Restart">
              {device.pendingReboot ? 'Pending. A restart is needed to finish updates.' : 'Not needed'}
            </Fact>
          </Facts>
        </Panel>

        <Panel title="Users">
          <Facts>
            <Fact label="At the console">{inv.consoleUser || device.consoleUser || 'Nobody'}</Fact>
            <Fact label="Signed in">{users.length > 0 ? users.join(', ') : 'Nobody'}</Fact>
          </Facts>
        </Panel>

        <Panel title="Agent">
          <Facts>
            <Fact label="Version" ident>
              {inv.agent?.version || device.agentVersion}
            </Fact>
            <Fact label="Processor use">{formatPercent(inv.agent?.cpuPercent)}</Fact>
            <Fact label="Memory use">{formatBytes(inv.agent?.rssBytes ?? device.agentRssBytes)}</Fact>
            <Fact label="Enrolled">{formatDateTime(device.enrolledAt)}</Fact>
            <Fact label="Certificate expires">{formatDateTime(device.certNotAfter)}</Fact>
            <Fact label="Last address" ident>
              {device.lastIp}
            </Fact>
            <Fact label="Machine ID" ident>
              {device.machineId}
            </Fact>
          </Facts>
        </Panel>
      </div>

      <Panel title="Disks">
        {disks.length === 0 ? (
          <p className="text-muted-foreground">No disks reported.</p>
        ) : (
          <ul className="-my-2.5 divide-y">
            {disks.map((d, i) => (
              <DiskRow key={`${d.device ?? ''}-${d.mountPoint ?? ''}-${i}`} disk={d} />
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Network" flush>
        {network.length === 0 ? (
          <p className="text-muted-foreground p-4">No network interfaces reported.</p>
        ) : (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Interface</TableHead>
                  <TableHead scope="col">MAC address</TableHead>
                  <TableHead scope="col">IPv4</TableHead>
                  <TableHead scope="col">IPv6</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {network.map((n, i) => (
                  <TableRow key={`${n.name ?? ''}-${n.mac ?? ''}-${i}`}>
                    <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-medium">
                      {n.name || 'Unnamed'}
                    </TableHead>
                    <TableCell className="ident">{n.mac}</TableCell>
                    <TableCell className="ident whitespace-normal">{(n.ipv4 ?? []).join(', ')}</TableCell>
                    <TableCell className="ident whitespace-normal break-all">{(n.ipv6 ?? []).join(', ')}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </Panel>
    </div>
  );
}
