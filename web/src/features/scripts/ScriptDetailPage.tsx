import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { History, Pencil, Play, Trash2 } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { CopyButton } from '@/components/copy-button';
import { OsIcon } from '@/components/os';
import { ErrorState, LoadingRows, PageHeader, Panel } from '@/components/page';
import { InlineAlert, StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { AP } from '@/features/jobs/permissions';
import { scriptKeys, scriptsApi, type ScriptDetail } from '@/lib/api/scripts';
import { useAccess } from '@/lib/auth/session';
import { formatDateTime } from '@/lib/format';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import { cn } from '@/lib/utils';
import { CodeEditor } from './CodeEditor';
import { RunScriptDialog } from './RunScriptDialog';
import { languageLabel, PARAMETER_TYPES } from './script-model';

export default function ScriptDetailPage() {
  const { scriptId = '' } = useParams();
  const [params] = useSearchParams();
  const requested = Number.parseInt(params.get('version') ?? '', 10);
  const version = Number.isInteger(requested) && requested > 0 ? requested : undefined;
  const query = useQuery({
    queryKey: scriptKeys.detail(scriptId, version),
    queryFn: () => scriptsApi.get(scriptId, version),
    placeholderData: keepPreviousData,
  });
  useDocumentTitle(query.data?.name ?? 'Script');

  if (query.isPending) {
    return <LoadingRows label="script" rows={10} />;
  }
  if (query.isError) {
    return <ErrorState error={query.error} what="this script" onRetry={() => void query.refetch()} />;
  }
  return <ScriptView script={query.data} loadingVersion={query.isPlaceholderData} />;
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className="mt-0.5 break-words">{children}</dd>
    </div>
  );
}

function ScriptView({ script, loadingVersion }: { script: ScriptDetail; loadingVersion: boolean }) {
  const access = useAccess();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { organizations } = useOrgFilter();
  const [, setParams] = useSearchParams();
  const [runVersion, setRunVersion] = useState<number | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const isCurrent = script.version === script.currentVersion;
  const canRun = access.has(AP.scriptsRun);
  // Shared scripts can only be changed with a partner-wide role (the server answers "not found" otherwise).
  const canManage = script.organizationId ? access.has(AP.scriptsManage) : access.hasPartnerWide(AP.scriptsManage);
  const parameters = script.parameters ?? [];
  const viewed = script.versions.find((v) => v.version === script.version);

  const remove = useMutation({
    mutationFn: () => scriptsApi.remove(script.id),
    onSuccess: async () => {
      notifySuccess(`Script “${script.name}” deleted`);
      await queryClient.invalidateQueries({ queryKey: scriptKeys.all });
      await navigate('/scripts');
    },
    onError: (error) => {
      notifyError(error);
      setConfirmDelete(false);
    },
  });

  const show = (version: number) => {
    setParams(version === script.currentVersion ? {} : { version: String(version) }, { replace: true });
  };

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Scripts', to: '/scripts' }, { label: script.name }]}
        title={script.name}
        description={script.description || undefined}
        actions={
          <>
            {canRun ? (
              <Button
                onClick={() => {
                  setRunVersion(script.version);
                }}
              >
                <Play aria-hidden="true" />
                {isCurrent ? 'Run' : `Run version ${script.version}`}
              </Button>
            ) : null}
            {canManage ? (
              <>
                <Button asChild variant="outline">
                  <Link to={`/scripts/${script.id}/edit`}>
                    <Pencil aria-hidden="true" />
                    Edit
                  </Link>
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    setConfirmDelete(true);
                  }}
                >
                  <Trash2 aria-hidden="true" />
                  Delete
                </Button>
              </>
            ) : null}
          </>
        }
      />

      {!isCurrent ? (
        <InlineAlert
          tone="warn"
          live={false}
          className="mb-4"
          title={`You are viewing version ${script.version}, not the current one`}
        >
          The current version is {script.currentVersion}.{' '}
          <button
            type="button"
            className="text-link underline"
            onClick={() => {
              show(script.currentVersion);
            }}
          >
            Show the current version
          </button>
        </InlineAlert>
      ) : null}

      <dl className="bg-card mb-4 grid grid-cols-2 gap-x-6 gap-y-3 rounded-lg border px-4 py-3 md:grid-cols-4">
        <Fact label="Language">{languageLabel(script.language)}</Fact>
        <Fact label="Runs on">
          <span className="inline-flex flex-wrap items-center gap-x-2.5 gap-y-1">
            {script.osTargets.map((os) => (
              <span key={os} className="inline-flex items-center gap-1">
                <OsIcon os={os} className="text-muted-foreground size-3.5" />
                {osLabel(os)}
              </span>
            ))}
          </span>
        </Fact>
        <Fact label="Available to">
          {script.organizationId ? (
            (organizations.find((o) => o.id === script.organizationId)?.name ?? 'One organization')
          ) : (
            <StatusPill tone="info">Shared with all organizations</StatusPill>
          )}
        </Fact>
        <Fact label="Current version">
          {script.currentVersion}
          <span className="text-muted-foreground block text-xs">Updated {formatDateTime(script.updatedAt)}</span>
        </Fact>
      </dl>

      <div className={cn('grid gap-4', loadingVersion && 'opacity-60')} aria-busy={loadingVersion}>
        <Panel
          title={`Script body, version ${script.version}`}
          description={
            viewed
              ? `Saved ${formatDateTime(viewed.createdAt)}${viewed.changeNote ? `: ${viewed.changeNote}` : ''}`
              : undefined
          }
          actions={<CopyButton value={script.body} label="Copy script" />}
        >
          <CodeEditor
            value={script.body}
            readOnly
            rows={Math.min(24, Math.max(6, script.body.split('\n').length + 1))}
            aria-label={`Script body, version ${script.version}`}
          />
          <p className="text-muted-foreground mt-2 text-xs">
            SHA-256 <span className="ident break-all">{script.bodySha256}</span>. Jobs and the audit log record this
            hash, so you can tell exactly which text ran.
          </p>
        </Panel>

        <Panel title="Parameters" flush={parameters.length > 0}>
          {parameters.length === 0 ? (
            <p className="text-muted-foreground">This version takes no parameters.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Name</TableHead>
                  <TableHead scope="col">Type</TableHead>
                  <TableHead scope="col">Required</TableHead>
                  <TableHead scope="col">Default</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {parameters.map((p) => (
                  <TableRow key={p.name}>
                    <TableHead scope="row" className="ident text-foreground h-auto py-2 font-medium">
                      {p.name}
                    </TableHead>
                    <TableCell>{PARAMETER_TYPES.find((t) => t.id === p.type)?.label ?? p.type}</TableCell>
                    <TableCell>{p.required ? 'Yes' : 'No'}</TableCell>
                    <TableCell className="ident max-w-80 truncate">
                      {p.default ?? <span className="text-muted-foreground font-sans">None</span>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Panel>
      </div>

      <Panel
        flush
        className="mt-4"
        title={
          <span className="inline-flex items-center gap-1.5">
            <History aria-hidden="true" className="size-4" />
            Version history
          </span>
        }
        description="Versions are never changed or removed. Viewing or running an old one does not make it current."
      >
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead scope="col">Version</TableHead>
              <TableHead scope="col">Saved</TableHead>
              <TableHead scope="col">Change note</TableHead>
              <TableHead scope="col" className="hidden lg:table-cell">
                SHA-256
              </TableHead>
              <TableHead scope="col">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {script.versions.map((v) => {
              const shown = v.version === script.version;
              return (
                <TableRow key={v.version} data-state={shown ? 'selected' : undefined}>
                  <TableHead scope="row" className="text-foreground h-auto py-2 font-medium">
                    {v.version}
                    {v.version === script.currentVersion ? (
                      <StatusPill tone="ok" className="ml-2">
                        Current
                      </StatusPill>
                    ) : null}
                  </TableHead>
                  <TableCell>
                    <time dateTime={v.createdAt}>{formatDateTime(v.createdAt)}</time>
                  </TableCell>
                  <TableCell className="max-w-96 whitespace-normal">
                    {v.changeNote || <span className="text-muted-foreground">No note</span>}
                  </TableCell>
                  <TableCell className="ident hidden text-xs lg:table-cell" title={v.bodySha256}>
                    {v.bodySha256.slice(0, 16)}…
                  </TableCell>
                  <TableCell className="text-right">
                    <span className="inline-flex gap-1.5">
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-pressed={shown}
                        disabled={shown}
                        onClick={() => {
                          show(v.version);
                        }}
                      >
                        {shown ? 'Shown above' : 'View'}
                        <span className="sr-only"> version {v.version}</span>
                      </Button>
                      {canRun ? (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setRunVersion(v.version);
                          }}
                        >
                          <Play aria-hidden="true" />
                          Run this version<span className="sr-only"> ({v.version})</span>
                        </Button>
                      ) : null}
                    </span>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Panel>

      {runVersion !== null ? (
        <RunScriptDialog
          scriptId={script.id}
          version={runVersion}
          onClose={() => {
            setRunVersion(null);
          }}
        />
      ) : null}

      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={`Delete the script “${script.name}”?`}
        description={
          <>
            <p>It disappears from the library and can no longer be run. Schedules that use it are switched off.</p>
            <p>Past runs, their output and the audit log entries stay.</p>
          </>
        }
        confirmLabel="Delete script"
        destructive
        pending={remove.isPending}
        onConfirm={() => {
          remove.mutate();
        }}
      />
    </>
  );
}
