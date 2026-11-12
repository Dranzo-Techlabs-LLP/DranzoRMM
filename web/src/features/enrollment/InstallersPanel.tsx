import { useQuery } from '@tanstack/react-query';
import { Download, PackageOpen } from 'lucide-react';
import { CopyButton } from '@/components/copy-button';
import { EmptyState, Panel, QueryView } from '@/components/page';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { enrollmentApi, qk } from '@/lib/api';
import { formatBytes } from '@/lib/format';
import { osLabel } from '@/lib/os';
import { TrustFiles } from './CreateTokenDialog';
import { installCommands } from './tokens';

/**
 * Installer packages of the newest agent release that has them, with SHA-256 so the file can be checked after
 * download, and the per-OS commands (with a placeholder where the one-time token goes).
 */
export function InstallersPanel() {
  const installers = useQuery({ queryKey: qk.installers, queryFn: enrollmentApi.installers, staleTime: 60_000 });
  const info = useQuery({ queryKey: qk.installInfo, queryFn: enrollmentApi.installInfo, staleTime: 5 * 60_000 });
  const commands = info.data ? installCommands(info.data, '<token>') : [];

  return (
    <Panel
      className="mt-4"
      title="Agent installers"
      description="Download the installer for each computer, then run the install command with a token from above."
      flush
    >
      <QueryView
        query={installers}
        what="installers"
        isEmpty={(d) => d.installers.length === 0}
        empty={
          <EmptyState icon={PackageOpen} title="No installer packages published yet">
            A Partner Admin adds them under Admin, Agent releases, by uploading .msi, .pkg, .deb or .rpm files with a
            release.
          </EmptyState>
        }
        rows={3}
      >
        {(data) => (
          <div className="overflow-x-auto">
            <p className="px-4 pt-3 text-sm">
              Version <span className="ident font-medium">{data.version}</span>
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">File</TableHead>
                  <TableHead scope="col">For</TableHead>
                  <TableHead scope="col" className="text-right">
                    Size
                  </TableHead>
                  <TableHead scope="col">SHA-256</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.installers.map((i) => (
                  <TableRow key={i.id}>
                    <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-normal">
                      <a
                        href={i.url}
                        download={i.fileName}
                        className="ident text-link inline-flex items-center gap-1.5 font-medium hover:underline"
                      >
                        <Download aria-hidden="true" className="size-4" />
                        {i.fileName}
                      </a>
                    </TableHead>
                    <TableCell>
                      {osLabel(i.os)} {i.arch} (.{i.kind})
                    </TableCell>
                    <TableCell className="text-right">{formatBytes(i.sizeBytes)}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="ident text-xs break-all">{i.sha256}</span>
                        <CopyButton value={i.sha256} label="Copy" size="xs" variant="ghost" />
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </QueryView>
      {info.data ? (
        <div className="border-t px-4 py-3">
          <TrustFiles info={info.data} />
        </div>
      ) : null}
      {commands.length > 0 ? (
        <div className="border-t px-4 py-3">
          <p className="mb-2 text-sm font-medium">Install commands</p>
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
                    Run as an administrator. Replace {c.placeholders.join(' and ')} (the token is shown once, when you
                    create it).
                  </p>
                  <CopyButton value={c.command} label="Copy command" />
                </div>
              </TabsContent>
            ))}
          </Tabs>
        </div>
      ) : null}
    </Panel>
  );
}
