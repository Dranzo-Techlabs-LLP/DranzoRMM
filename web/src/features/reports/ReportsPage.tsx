import { useQuery } from '@tanstack/react-query';
import { FileBarChart, FileSpreadsheet, FileText } from 'lucide-react';
import { useOrgFilter } from '@/app/org-filter';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { reportKeys, reportsApi } from '@/lib/api/reports';
import { useAccess } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';

const DESCRIPTIONS: Record<string, string> = {
  'device-inventory':
    'Every device with operating system, model, serial number, agent version and when it was last seen.',
  'patch-compliance': 'Missing, critical and failed updates per device, with the last scan and install.',
  'security-posture':
    'Antivirus, firewall and disk encryption state, local administrators and vulnerabilities per device.',
  software: 'Software installed on each device, with version and publisher.',
  'audit-log': 'Every recorded action with its hash chain, newest first (up to 100,000 entries).',
};

const ALL = '';

/**
 * Downloadable reports. The links are plain same-origin downloads: the browser sends the session cookie and saves
 * the file the server returns. Generating a report is recorded in the audit log.
 */
export default function ReportsPage() {
  useDocumentTitle('Reports');
  const access = useAccess();
  const { orgId, setOrgId, organizations, available: orgsAvailable } = useOrgFilter();
  const reports = useQuery({ queryKey: reportKeys.list, queryFn: reportsApi.list, staleTime: 5 * 60_000 });

  return (
    <>
      <PageHeader
        title="Reports"
        description="CSV for spreadsheets, PDF for sharing. Each report covers the devices you can see."
        actions={
          orgsAvailable ? (
            <div className="grid gap-1">
              <Label htmlFor="report-org" className="text-xs">
                Organization
              </Label>
              <NativeSelect
                id="report-org"
                size="sm"
                value={orgId ?? ALL}
                onChange={(e) => {
                  setOrgId(e.target.value === ALL ? null : e.target.value);
                }}
              >
                <NativeSelectOption value={ALL}>All organizations</NativeSelectOption>
                {organizations.map((o) => (
                  <NativeSelectOption key={o.id} value={o.id}>
                    {o.name}
                  </NativeSelectOption>
                ))}
              </NativeSelect>
            </div>
          ) : null
        }
      />
      <QueryView
        query={reports}
        what="reports"
        isEmpty={(d) => d.filter((r) => access.has(r.permission)).length === 0}
        empty={<EmptyState icon={FileBarChart} title="No reports available to you" />}
      >
        {(list) => (
          <ul className="grid gap-3 md:grid-cols-2">
            {list
              .filter((r) => access.has(r.permission))
              .map((r) => (
                <li key={r.id}>
                  <Panel className="h-full">
                    <div className="flex h-full flex-col gap-3">
                      <div>
                        <h2 className="font-semibold">{r.name}</h2>
                        <p className="text-muted-foreground mt-0.5 text-sm">{DESCRIPTIONS[r.id] ?? ''}</p>
                      </div>
                      <div className="mt-auto flex flex-wrap gap-2">
                        <Button asChild variant="outline" size="sm">
                          <a href={reportsApi.downloadUrl(r.id, 'csv', orgId)} download>
                            <FileSpreadsheet aria-hidden="true" />
                            Download CSV<span className="sr-only"> of {r.name}</span>
                          </a>
                        </Button>
                        <Button asChild variant="outline" size="sm">
                          <a href={reportsApi.downloadUrl(r.id, 'pdf', orgId)} download>
                            <FileText aria-hidden="true" />
                            Download PDF<span className="sr-only"> of {r.name}</span>
                          </a>
                        </Button>
                      </div>
                    </div>
                  </Panel>
                </li>
              ))}
          </ul>
        )}
      </QueryView>
    </>
  );
}
