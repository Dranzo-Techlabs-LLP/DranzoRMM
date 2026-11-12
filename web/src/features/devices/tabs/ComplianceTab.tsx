import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ClipboardCheck, Play } from 'lucide-react';
import { EmptyState, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { checkLabel } from '@/features/policies/policy-params';
import { TriStateMark } from '@/features/security/posture';
import { policiesApi, policyKeys } from '@/lib/api/policies';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { notifyError, notifySuccess } from '@/lib/notify';
import type { DeviceTabProps } from './registry';

/** Policy results of one device. */
export function ComplianceTab({ device }: DeviceTabProps) {
  const access = useAccess();
  const queryClient = useQueryClient();
  const results = useQuery({
    queryKey: policyKeys.deviceCompliance(device.id),
    queryFn: () => policiesApi.deviceCompliance(device.id),
    refetchInterval: 60_000,
  });
  const evaluate = useMutation({
    mutationFn: () => policiesApi.evaluate({ deviceIds: [device.id] }),
    onSuccess: (r) => {
      notifySuccess(
        r.deviceCount === 0
          ? 'Nothing to check: no policy applies to this device, or it is offline.'
          : 'Checking now. Results appear here shortly.',
      );
      for (const delay of [5000, 15000]) {
        setTimeout(() => {
          void queryClient.invalidateQueries({ queryKey: policyKeys.deviceCompliance(device.id) });
        }, delay);
      }
    },
    onError: notifyError,
  });
  const button =
    access.has(P.policiesManage) && device.isOnline ? (
      <Button
        variant="outline"
        size="sm"
        disabled={evaluate.isPending}
        onClick={() => {
          evaluate.mutate();
        }}
      >
        <Play aria-hidden="true" />
        {evaluate.isPending ? 'Requesting…' : 'Evaluate now'}
      </Button>
    ) : null;

  return (
    <Panel title="Policy compliance" actions={button} flush>
      <QueryView
        query={results}
        what="compliance results"
        isEmpty={(d) => d.length === 0}
        empty={
          <EmptyState icon={ClipboardCheck} title="No results for this device">
            No policy has been checked here yet. Policies apply through assignments to its organization, site or group.
          </EmptyState>
        }
      >
        {(rows) => (
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Policy</TableHead>
                  <TableHead scope="col">Result</TableHead>
                  <TableHead scope="col">Detail</TableHead>
                  <TableHead scope="col">Not compliant since</TableHead>
                  <TableHead scope="col">Last checked</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {[...rows]
                  .sort(
                    (a, b) =>
                      Number(a.compliant) - Number(b.compliant) || (a.policy ?? '').localeCompare(b.policy ?? ''),
                  )
                  .map((r) => (
                    <TableRow key={r.policyId}>
                      <TableHead
                        scope="row"
                        className="text-foreground h-auto py-2 text-sm font-normal whitespace-normal"
                      >
                        <div className="font-medium">{r.policy ?? 'Deleted policy'}</div>
                        <div className="text-muted-foreground text-xs">{checkLabel(r.check)}</div>
                      </TableHead>
                      <TableCell>
                        <TriStateMark
                          value={r.supported === false ? null : r.compliant}
                          okLabel={r.remediated ? 'Compliant (fixed)' : 'Compliant'}
                          issueLabel="Not compliant"
                          unknownLabel="Not supported"
                        />
                      </TableCell>
                      <TableCell className="max-w-md text-xs break-words whitespace-pre-wrap">{r.detail}</TableCell>
                      <TableCell>
                        {r.nonCompliantSince ? (
                          <RelativeTime value={r.nonCompliantSince} />
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <RelativeTime value={r.evaluatedAt} />
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </div>
        )}
      </QueryView>
    </Panel>
  );
}
