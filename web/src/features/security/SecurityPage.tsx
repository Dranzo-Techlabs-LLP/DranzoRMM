import { keepPreviousData, useMutation, useQuery } from '@tanstack/react-query';
import { RotateCw, ScanSearch, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { OsIcon } from '@/components/os';
import { EmptyState, ErrorState, LoadingRows, PageHeader, Panel, QueryView } from '@/components/page';
import { Pagination } from '@/components/pagination';
import { RelativeTime } from '@/components/relative-time';
import { InlineAlert, PendingRebootBadge } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { securityApi, securityKeys, type PostureOverview, type VulnerabilityFilter } from '@/lib/api/security';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { formatDateTime } from '@/lib/format';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { cn } from '@/lib/utils';
import { CveLink, KnownExploitedBadge, ScoreBadge, TriStateMark, VulnSeverity } from './posture';
import { LOW_SCORE, matchesPostureFilter, VULN_SEVERITIES, type PostureFilter } from './posture-model';

const PAGE_SIZE = 50;
type Section = 'posture' | 'vulnerabilities' | 'feeds';
const SECTIONS: { id: Section; label: string }[] = [
  { id: 'posture', label: 'Posture' },
  { id: 'vulnerabilities', label: 'Vulnerabilities' },
  { id: 'feeds', label: 'Vulnerability data' },
];

export default function SecurityPage() {
  useDocumentTitle('Security');
  const [params, setParams] = useSearchParams();
  const section = SECTIONS.find((s) => s.id === params.get('tab'))?.id ?? 'posture';
  return (
    <>
      <PageHeader
        title="Security"
        description="What devices report about their own protection, and known vulnerabilities in the software installed on them."
      />
      <Tabs
        value={section}
        onValueChange={(next) => {
          setParams(next === 'posture' ? {} : { tab: next }, { replace: true });
        }}
      >
        <TabsList variant="line" className="mb-4 w-full justify-start border-b">
          {SECTIONS.map((s) => (
            <TabsTrigger key={s.id} value={s.id} className="flex-none px-3">
              {s.label}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="posture">
          <PostureSection />
        </TabsContent>
        <TabsContent value="vulnerabilities">
          <VulnerabilitySection />
        </TabsContent>
        <TabsContent value="feeds">
          <FeedSection />
        </TabsContent>
      </Tabs>
    </>
  );
}

const CARDS: {
  filter: Exclude<PostureFilter, ''>;
  label: string;
  count: (d: PostureOverview) => number;
  note: string;
}[] = [
  {
    filter: 'antivirus',
    label: 'Antivirus problems',
    count: (d) => d.antivirusIssues,
    note: 'Off, missing or out of date',
  },
  { filter: 'firewall', label: 'Firewall off', count: (d) => d.firewallIssues, note: 'Host firewall reports disabled' },
  {
    filter: 'encryption',
    label: 'Disk not encrypted',
    count: (d) => d.encryptionIssues,
    note: 'At least one volume unencrypted',
  },
  {
    filter: 'not-reporting',
    label: 'Not reporting',
    count: (d) => d.notReporting,
    note: 'No posture report received yet',
  },
  {
    filter: 'known-exploited',
    label: 'Known exploited vulnerabilities',
    count: (d) => d.withKnownExploited,
    note: 'Devices with at least one',
  },
  {
    filter: 'low-score',
    label: 'Low security score',
    count: (d) => d.items.filter((i) => i.score !== null && i.score < LOW_SCORE).length,
    note: `Score below ${String(LOW_SCORE)}`,
  },
];

function PostureSection() {
  const access = useAccess();
  const { orgId, organization, organizations, available: orgsAvailable } = useOrgFilter();
  const [filter, setFilter] = useState<PostureFilter>('');
  const [page, setPage] = useState(1);
  const posture = useQuery({
    queryKey: securityKeys.posture(orgId ?? undefined),
    queryFn: () => securityApi.posture(orgId ?? undefined),
    refetchInterval: 60_000,
  });
  const orgName = new Map(organizations.map((o) => [o.id, o.name]));

  const scan = useMutation({
    mutationFn: (data: PostureOverview) =>
      securityApi.scan(orgId ? { organizationId: orgId } : { deviceIds: data.items.slice(0, 5000).map((d) => d.id) }),
    onSuccess: (result) => {
      notifySuccess(
        `Asked ${result.deviceCount} ${result.deviceCount === 1 ? 'device' : 'devices'} to report. Online devices answer within a minute; offline ones when they reconnect.`,
      );
    },
    onError: notifyError,
  });

  return (
    <QueryView query={posture} what="security posture">
      {(data) => {
        const rows = data.items
          .filter((r) => matchesPostureFilter(r, filter))
          .sort((a, b) => (a.score ?? 101) - (b.score ?? 101) || a.hostname.localeCompare(b.hostname));
        const pageRows = rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
        return (
          <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
            <ul className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
              {CARDS.map((card) => {
                const count = card.count(data);
                const selected = filter === card.filter;
                return (
                  <li key={card.filter}>
                    <button
                      type="button"
                      aria-pressed={selected}
                      className={cn(
                        'bg-card hover:bg-accent/60 h-full w-full rounded-lg border px-4 py-3 text-left',
                        selected && 'ring-ring ring-2',
                      )}
                      onClick={() => {
                        setFilter(selected ? '' : card.filter);
                        setPage(1);
                      }}
                    >
                      <span className="text-muted-foreground block text-xs">{card.label}</span>
                      <span
                        className={cn(
                          'block text-2xl leading-8 font-semibold tracking-tight',
                          count > 0 && 'text-danger',
                        )}
                      >
                        {count.toLocaleString('en')}
                      </span>
                      <span className="text-muted-foreground block text-xs">
                        {count > 0 ? card.note : 'None'}
                        <span className="sr-only">
                          {selected ? '. Showing only these devices.' : '. Show only these devices.'}
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>

            <Panel
              title={`${filter ? `${rows.length} of ${data.total}` : data.total} ${data.total === 1 ? 'device' : 'devices'}${organization ? ` in ${organization.name}` : ''}`}
              description={`${data.averageScore === null ? '' : `Average security score ${String(data.averageScore)}. `}Lowest score first. Unknown means the device has not reported that item, or its operating system cannot.`}
              actions={
                <>
                  {filter ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setFilter('');
                        setPage(1);
                      }}
                    >
                      Show all
                    </Button>
                  ) : null}
                  {access.has(P.devicesManage) && data.total > 0 ? (
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={scan.isPending}
                      onClick={() => {
                        scan.mutate(data);
                      }}
                    >
                      <ScanSearch aria-hidden="true" />
                      {scan.isPending ? 'Asking…' : 'Scan now'}
                    </Button>
                  ) : null}
                </>
              }
              flush
            >
              {data.total === 0 ? (
                <EmptyState icon={ShieldCheck} title="No devices to show">
                  Posture appears here once devices are enrolled and have reported.
                </EmptyState>
              ) : rows.length === 0 ? (
                <EmptyState title="No device matches this filter" />
              ) : (
                <>
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead scope="col">Device</TableHead>
                          <TableHead scope="col">Score</TableHead>
                          <TableHead scope="col">Antivirus</TableHead>
                          <TableHead scope="col">Firewall</TableHead>
                          <TableHead scope="col">Disk encryption</TableHead>
                          <TableHead scope="col">Local administrators</TableHead>
                          <TableHead scope="col">Vulnerabilities</TableHead>
                          <TableHead scope="col">Last update installed</TableHead>
                          <TableHead scope="col">Reported</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {pageRows.map((r) => (
                          <TableRow key={r.id}>
                            <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-normal">
                              <div className="flex items-center gap-2">
                                <OsIcon os={r.os} className="text-muted-foreground" />
                                <Link
                                  to={`/devices/${r.id}?tab=security`}
                                  className="ident font-medium hover:underline"
                                >
                                  {r.hostname}
                                </Link>
                                {r.pendingReboot ? <PendingRebootBadge /> : null}
                              </div>
                              <div className="text-muted-foreground text-xs">
                                {[
                                  orgsAvailable && !orgId ? orgName.get(r.organizationId) : null,
                                  r.isOnline ? 'Online' : 'Offline',
                                ]
                                  .filter(Boolean)
                                  .join(' · ')}
                              </div>
                            </TableHead>
                            <TableCell>
                              <ScoreBadge score={r.score} grade={r.grade} />
                            </TableCell>
                            <TableCell>
                              <TriStateMark value={r.antivirusOk} />
                            </TableCell>
                            <TableCell>
                              <TriStateMark value={r.firewallOk} okLabel="On" issueLabel="Off" />
                            </TableCell>
                            <TableCell>
                              <TriStateMark value={r.encryptionOk} okLabel="Encrypted" issueLabel="Not encrypted" />
                            </TableCell>
                            <TableCell className="max-w-56 whitespace-normal">
                              {r.collectedAt === null ? (
                                <span className="text-muted-foreground">Unknown</span>
                              ) : r.localAdmins.length === 0 ? (
                                <span className="text-muted-foreground">None reported</span>
                              ) : (
                                <span title={r.localAdmins.join(', ')}>
                                  <span className="font-medium">{r.localAdmins.length}</span>
                                  <span className="text-muted-foreground">
                                    : {r.localAdmins.slice(0, 3).join(', ')}
                                    {r.localAdmins.length > 3 ? ` and ${r.localAdmins.length - 3} more` : ''}
                                  </span>
                                </span>
                              )}
                            </TableCell>
                            <TableCell className="whitespace-normal">
                              {r.vulnerabilities === 0 ? (
                                <span className="text-muted-foreground">None found</span>
                              ) : (
                                <div className="flex flex-wrap items-center gap-1.5">
                                  <span>
                                    {r.vulnerabilities}
                                    {r.criticalVulnerabilities > 0 ? ` (${r.criticalVulnerabilities} critical)` : ''}
                                  </span>
                                  {r.knownExploited > 0 ? <KnownExploitedBadge /> : null}
                                </div>
                              )}
                            </TableCell>
                            <TableCell>
                              <RelativeTime value={r.lastPatchDate} fallback="Unknown" />
                            </TableCell>
                            <TableCell>
                              <RelativeTime value={r.collectedAt} fallback="Never" />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                  {rows.length > PAGE_SIZE ? (
                    <Pagination
                      page={page}
                      pageSize={PAGE_SIZE}
                      total={rows.length}
                      noun="devices"
                      onPageChange={setPage}
                    />
                  ) : null}
                </>
              )}
            </Panel>
          </div>
        );
      }}
    </QueryView>
  );
}

function VulnerabilitySection() {
  const { orgId } = useOrgFilter();
  const [severity, setSeverity] = useState('');
  const [exploitedOnly, setExploitedOnly] = useState(false);
  const [page, setPage] = useState(1);
  const filter: VulnerabilityFilter = {
    organizationId: orgId ?? undefined,
    severity: severity || undefined,
    knownExploited: exploitedOnly ? true : undefined,
    page,
    pageSize: PAGE_SIZE,
  };
  const query = useQuery({
    queryKey: securityKeys.vulnerabilities(filter),
    queryFn: () => securityApi.vulnerabilities(filter),
    placeholderData: keepPreviousData,
  });
  const filtered = Boolean(severity || exploitedOnly);

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
      {query.data ? (
        <InlineAlert tone="info" live={false} title="How to read this list">
          {query.data.note}
        </InlineAlert>
      ) : null}
      <Panel flush>
        <form
          role="search"
          aria-label="Filter vulnerabilities"
          className="flex flex-wrap items-end gap-x-4 gap-y-2 border-b px-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
          }}
        >
          <div className="grid gap-1">
            <Label htmlFor="vuln-severity" className="text-xs">
              Severity
            </Label>
            <NativeSelect
              id="vuln-severity"
              size="sm"
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(1);
              }}
            >
              <NativeSelectOption value="">Any</NativeSelectOption>
              {VULN_SEVERITIES.map((s) => (
                <NativeSelectOption key={s} value={s}>
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
          <div className="flex h-8 items-center gap-2">
            <Checkbox
              id="vuln-kev"
              checked={exploitedOnly}
              onCheckedChange={(v) => {
                setExploitedOnly(v === true);
                setPage(1);
              }}
            />
            <Label htmlFor="vuln-kev" className="font-normal">
              Known exploited only
            </Label>
          </div>
        </form>
        {query.isPending ? (
          <LoadingRows label="vulnerabilities" rows={8} />
        ) : query.isError ? (
          <ErrorState error={query.error} what="vulnerabilities" onRetry={() => void query.refetch()} />
        ) : query.data.total === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title={filtered ? 'No vulnerabilities match these filters' : 'No vulnerabilities found'}
          >
            {filtered
              ? 'Try a broader filter.'
              : 'Nothing installed on these devices matched the vulnerability data. See the Vulnerability data tab for when it was last updated.'}
          </EmptyState>
        ) : (
          <>
            <div
              className={cn('overflow-x-auto', query.isPlaceholderData && 'opacity-60')}
              aria-busy={query.isFetching}
            >
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">CVE</TableHead>
                    <TableHead scope="col">Severity</TableHead>
                    <TableHead scope="col" className="text-right">
                      CVSS
                    </TableHead>
                    <TableHead scope="col" className="text-right">
                      Devices
                    </TableHead>
                    <TableHead scope="col">Software</TableHead>
                    <TableHead scope="col">Summary</TableHead>
                    <TableHead scope="col">Published</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {query.data.items.map((v) => (
                    <TableRow key={`${v.cveId}:${v.severity}:${v.cvssScore ?? ''}`}>
                      <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-normal">
                        <CveLink cveId={v.cveId} />
                        {v.knownExploited ? (
                          <div className="mt-1">
                            <KnownExploitedBadge />
                          </div>
                        ) : null}
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
                      <TableCell className="text-right tabular-nums">{v.devices}</TableCell>
                      <TableCell className="max-w-48 whitespace-normal">{v.software}</TableCell>
                      <TableCell className="text-muted-foreground max-w-md min-w-64 text-xs whitespace-normal">
                        <span className="line-clamp-3" title={v.summary ?? undefined}>
                          {v.summary || 'No summary available.'}
                        </span>
                      </TableCell>
                      <TableCell className="whitespace-nowrap">
                        {v.published ? formatDateTime(v.published).split(',').slice(0, 2).join(',') : ''}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <Pagination
              page={query.data.page}
              pageSize={query.data.pageSize || PAGE_SIZE}
              total={query.data.total}
              noun="vulnerabilities"
              onPageChange={setPage}
            />
          </>
        )}
      </Panel>
    </div>
  );
}

function FeedSection() {
  const feeds = useQuery({ queryKey: securityKeys.feedStatus, queryFn: securityApi.feedStatus });
  return (
    <QueryView query={feeds} what="vulnerability data status">
      {(data) => (
        <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
          <Panel>
            <dl className="grid grid-cols-2 gap-x-8 gap-y-4 md:grid-cols-4">
              <div>
                <dt className="text-muted-foreground text-xs">Vulnerabilities known to the server</dt>
                <dd className="text-2xl leading-8 font-semibold tracking-tight">
                  {data.cveCount.toLocaleString('en')}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground text-xs">Of those, known exploited</dt>
                <dd className="text-2xl leading-8 font-semibold tracking-tight">
                  {data.knownExploited.toLocaleString('en')}
                </dd>
              </div>
            </dl>
            <p className="text-muted-foreground mt-3 max-w-[75ch] text-xs">
              The server downloads public vulnerability data (the NVD CVE feed and the CISA Known Exploited
              Vulnerabilities list) and compares it with the software each device reports. If no data has been
              downloaded, the vulnerability list stays empty.
            </p>
          </Panel>
          <Panel title="Data sources" flush>
            {data.feeds.length === 0 ? (
              <EmptyState icon={RotateCw} title="No vulnerability data downloaded yet">
                The server has not completed a download. Until it does, no vulnerabilities can be matched.
              </EmptyState>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Source</TableHead>
                    <TableHead scope="col">Last download</TableHead>
                    <TableHead scope="col" className="text-right">
                      Entries
                    </TableHead>
                    <TableHead scope="col">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.feeds.map((f) => (
                    <TableRow key={f.name}>
                      <TableHead scope="row" className="ident text-foreground h-auto py-2 text-sm font-medium">
                        {f.name}
                      </TableHead>
                      <TableCell>
                        <RelativeTime value={f.lastSyncedAt} fallback="Never" />
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{f.items.toLocaleString('en')}</TableCell>
                      <TableCell className="whitespace-normal">
                        {f.lastError ? (
                          <span className="text-danger">
                            <span className="font-medium">Last download failed: </span>
                            <span className="break-words">{f.lastError}</span>
                          </span>
                        ) : (
                          <TriStateMark
                            value={f.lastSyncedAt ? true : null}
                            okLabel="Working"
                            unknownLabel="Not downloaded yet"
                          />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Panel>
        </div>
      )}
    </QueryView>
  );
}
