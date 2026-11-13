import { useQuery } from '@tanstack/react-query';
import { FileSpreadsheet, FileText, ShieldAlert, UserCheck } from 'lucide-react';
import { useMemo, useState } from 'react';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { groupPermissions } from '@/features/admin/permission-catalog';
import { principalStatus, reviewSummary } from '@/features/admin/access/review';
import { accessApi, accessKeys } from '@/lib/api/access';
import { reportsApi } from '@/lib/api/reports';
import { formatDateTime } from '@/lib/format';
import { useDocumentTitle } from '@/lib/hooks';

function Permissions({ permissions, total }: { permissions: string[]; total: number }) {
  if (permissions.length === 0) {
    return <span className="text-muted-foreground">None</span>;
  }
  return (
    <details>
      <summary className="cursor-pointer whitespace-nowrap">
        {permissions.length} of {total}
      </summary>
      <ul className="mt-1 grid gap-1 text-xs">
        {groupPermissions(permissions).map((g) => (
          <li key={g.area}>
            <span className="font-medium">{g.label}:</span> {g.items.map((i) => i.label).join(', ')}
          </li>
        ))}
      </ul>
    </details>
  );
}

export default function AccessReviewPage() {
  useDocumentTitle('Access review');
  const [onlyFindings, setOnlyFindings] = useState(false);
  const review = useQuery({ queryKey: accessKeys.review, queryFn: accessApi.review });
  const summary = useMemo(() => reviewSummary(review.data?.principals ?? []), [review.data]);

  return (
    <>
      <PageHeader
        title="Access review"
        description="Who can do what: every user and API key with roles, where they apply, effective permissions and anything worth a second look. Viewing this page is recorded in the audit log."
        actions={
          <>
            <Button asChild variant="outline" size="sm">
              <a href={reportsApi.downloadUrl('access-review', 'csv')} download>
                <FileSpreadsheet aria-hidden="true" />
                CSV
              </a>
            </Button>
            <Button asChild variant="outline" size="sm">
              <a href={reportsApi.downloadUrl('access-review', 'pdf')} download>
                <FileText aria-hidden="true" />
                PDF
              </a>
            </Button>
          </>
        }
      />
      <dl className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
        {[
          ['Users', summary.users],
          ['API keys', summary.apiKeys],
          ['With findings', summary.withFindings],
          ['Full admins', summary.fullAdmins],
        ].map(([label, value]) => (
          <div key={label} className="bg-card rounded-md border p-3">
            <dt className="text-muted-foreground text-xs">{label}</dt>
            <dd className="text-xl font-semibold tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>
      <Panel
        flush
        title="Users and API keys"
        description={review.data ? `Generated ${formatDateTime(review.data.generatedAt)}` : undefined}
        actions={
          <div className="flex items-center gap-2">
            <Switch id="only-findings" checked={onlyFindings} onCheckedChange={setOnlyFindings} />
            <Label htmlFor="only-findings">Only with findings</Label>
          </div>
        }
      >
        <QueryView query={review} what="access review" rows={8}>
          {(data) => {
            const rows = data.principals.filter((p) => !onlyFindings || p.findings.length > 0);
            if (rows.length === 0) {
              return (
                <EmptyState icon={UserCheck} title="Nothing to review">
                  No user or API key has a finding right now.
                </EmptyState>
              );
            }
            return (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>MFA</TableHead>
                    <TableHead>Last active</TableHead>
                    <TableHead>Roles</TableHead>
                    <TableHead>Permissions</TableHead>
                    <TableHead>Findings</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.map((p) => {
                    const status = principalStatus(p);
                    return (
                      <TableRow key={`${p.kind}-${p.id}`}>
                        <TableCell>
                          <div className="font-medium">{p.name}</div>
                          <div className="text-muted-foreground text-xs">
                            {p.kind === 'apikey' ? 'API key' : p.email}
                          </div>
                        </TableCell>
                        <TableCell>
                          <StatusPill tone={status.tone}>{status.label}</StatusPill>
                        </TableCell>
                        <TableCell>
                          {p.mfaEnabled === null ? (
                            <span className="text-muted-foreground">n/a</span>
                          ) : p.mfaEnabled ? (
                            'Yes'
                          ) : (
                            <StatusPill tone="warn">No</StatusPill>
                          )}
                        </TableCell>
                        <TableCell>
                          <RelativeTime value={p.lastActiveAt} />
                        </TableCell>
                        <TableCell>
                          {p.grants.length === 0 ? (
                            <span className="text-muted-foreground">No role</span>
                          ) : (
                            <ul className="grid gap-0.5">
                              {p.grants.map((g) => (
                                <li key={`${g.role}-${g.scope}-${g.scopeName}`}>
                                  {g.role} <span className="text-muted-foreground">({g.scopeName})</span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </TableCell>
                        <TableCell>
                          <Permissions permissions={p.permissions} total={data.totalPermissions} />
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {p.findings.map((f) => (
                              <StatusPill key={f} tone="warn" icon={ShieldAlert}>
                                {f}
                              </StatusPill>
                            ))}
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            );
          }}
        </QueryView>
      </Panel>
    </>
  );
}
