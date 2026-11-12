import { useQuery } from '@tanstack/react-query';
import { Play, Plus, Search, SquareTerminal } from 'lucide-react';
import { useState } from 'react';
import { Link } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { OsIcon } from '@/components/os';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { AP } from '@/features/jobs/permissions';
import { scriptKeys, scriptsApi, type ScriptListItem } from '@/lib/api/scripts';
import { useAccess } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { osLabel } from '@/lib/os';
import { RunScriptDialog } from './RunScriptDialog';
import { languageLabel, LANGUAGES } from './script-model';

export default function ScriptsPage() {
  useDocumentTitle('Scripts');
  const access = useAccess();
  const { orgId, organization, organizations } = useOrgFilter();
  const [search, setSearch] = useState('');
  const [language, setLanguage] = useState('');
  const [running, setRunning] = useState<ScriptListItem | null>(null);
  const query = useQuery({
    queryKey: scriptKeys.list(orgId),
    queryFn: () => scriptsApi.list(orgId ?? undefined),
  });
  const canManage = access.has(AP.scriptsManage);
  const canRun = access.has(AP.scriptsRun);
  const needle = search.trim().toLowerCase();
  const orgName = (id: string) => organizations.find((o) => o.id === id)?.name ?? 'One organization';

  return (
    <>
      <PageHeader
        title="Scripts"
        description="The script library. Every save creates a new version; earlier versions stay available for history and audit."
        actions={
          canManage ? (
            <Button asChild>
              <Link to="/scripts/new">
                <Plus aria-hidden="true" />
                New script
              </Link>
            </Button>
          ) : undefined
        }
      />
      <Panel flush>
        <form
          role="search"
          aria-label="Filter scripts"
          className="flex flex-wrap items-end gap-3 border-b px-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
          }}
        >
          <div className="grid min-w-52 flex-1 gap-1">
            <Label htmlFor="script-search" className="text-xs">
              Search
            </Label>
            <div className="relative">
              <Search
                aria-hidden="true"
                className="text-muted-foreground absolute top-1/2 left-2.5 size-4 -translate-y-1/2"
              />
              <Input
                id="script-search"
                type="search"
                className="h-8 pl-8"
                placeholder="Name or description"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                }}
              />
            </div>
          </div>
          <div className="grid gap-1">
            <Label htmlFor="script-language" className="text-xs">
              Language
            </Label>
            <NativeSelect
              id="script-language"
              size="sm"
              value={language}
              onChange={(e) => {
                setLanguage(e.target.value);
              }}
            >
              <NativeSelectOption value="">All languages</NativeSelectOption>
              {LANGUAGES.map((l) => (
                <NativeSelectOption key={l.id} value={l.id}>
                  {l.label}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
          <p className="text-muted-foreground ml-auto self-center text-xs">
            {organization ? `Shared scripts and scripts of ${organization.name}.` : 'Scripts of all organizations.'}
          </p>
        </form>
        <QueryView
          query={query}
          what="scripts"
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyState
              icon={SquareTerminal}
              title="No scripts yet"
              action={
                canManage ? (
                  <Button asChild variant="outline" size="sm">
                    <Link to="/scripts/new">Write the first script</Link>
                  </Button>
                ) : undefined
              }
            >
              Scripts run on devices as the system account or as the signed-in user, now or on a schedule.
            </EmptyState>
          }
        >
          {(scripts) => {
            const rows = scripts.filter(
              (s) =>
                (!language || s.language === language) &&
                (!needle || s.name.toLowerCase().includes(needle) || s.description.toLowerCase().includes(needle)),
            );
            if (rows.length === 0) {
              return (
                <EmptyState
                  icon={SquareTerminal}
                  title="No scripts match these filters"
                  action={
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setSearch('');
                        setLanguage('');
                      }}
                    >
                      Clear filters
                    </Button>
                  }
                />
              );
            }
            return (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Name</TableHead>
                    <TableHead scope="col">Language</TableHead>
                    <TableHead scope="col">Runs on</TableHead>
                    <TableHead scope="col" className="text-right">
                      Version
                    </TableHead>
                    <TableHead scope="col" className="hidden md:table-cell">
                      Scope
                    </TableHead>
                    <TableHead scope="col" className="hidden lg:table-cell">
                      Updated
                    </TableHead>
                    {canRun ? (
                      <TableHead scope="col">
                        <span className="sr-only">Actions</span>
                      </TableHead>
                    ) : null}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((s) => (
                    <TableRow key={s.id}>
                      <TableHead
                        scope="row"
                        className="text-foreground h-auto max-w-96 py-2 font-medium whitespace-normal"
                      >
                        <Link to={`/scripts/${s.id}`} className="text-link hover:underline">
                          {s.name}
                        </Link>
                        {s.description ? (
                          <span className="text-muted-foreground line-clamp-1 text-xs font-normal">
                            {s.description}
                          </span>
                        ) : null}
                      </TableHead>
                      <TableCell>{languageLabel(s.language)}</TableCell>
                      <TableCell>
                        <span className="inline-flex flex-wrap items-center gap-x-2.5 gap-y-1">
                          {s.osTargets.map((os) => (
                            <span key={os} className="inline-flex items-center gap-1">
                              <OsIcon os={os} className="text-muted-foreground size-3.5" />
                              {osLabel(os)}
                            </span>
                          ))}
                        </span>
                      </TableCell>
                      <TableCell className="text-right">{s.currentVersion}</TableCell>
                      <TableCell className="hidden md:table-cell">
                        {s.organizationId ? orgName(s.organizationId) : <StatusPill tone="info">Shared</StatusPill>}
                      </TableCell>
                      <TableCell className="hidden lg:table-cell">
                        <RelativeTime value={s.updatedAt} />
                      </TableCell>
                      {canRun ? (
                        <TableCell className="text-right">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setRunning(s);
                            }}
                          >
                            <Play aria-hidden="true" />
                            Run<span className="sr-only"> {s.name}</span>
                          </Button>
                        </TableCell>
                      ) : null}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            );
          }}
        </QueryView>
      </Panel>
      {running ? (
        <RunScriptDialog
          scriptId={running.id}
          onClose={() => {
            setRunning(null);
          }}
        />
      ) : null}
    </>
  );
}
