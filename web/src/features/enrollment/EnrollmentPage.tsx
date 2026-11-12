import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Plus } from 'lucide-react';
import { InstallersPanel } from './InstallersPanel';
import { useState } from 'react';
import { useOrgFilter } from '@/app/org-filter';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { enrollmentApi, qk, type EnrollmentToken } from '@/lib/api';
import { useDocumentTitle } from '@/lib/hooks';
import { notifyError, notifySuccess } from '@/lib/notify';
import { CreateTokenDialog } from './CreateTokenDialog';
import { TOKEN_STATE, tokenState } from './tokens';

export default function EnrollmentPage() {
  useDocumentTitle('Enrollment');
  const queryClient = useQueryClient();
  const { orgId, organization, organizations } = useOrgFilter();
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<EnrollmentToken | null>(null);

  const tokens = useQuery({
    queryKey: qk.tokens(orgId ?? undefined),
    queryFn: () => enrollmentApi.listTokens(orgId ?? undefined),
  });
  const orgName = new Map(organizations.map((o) => [o.id, o.name]));

  const revoke = useMutation({
    mutationFn: (id: string) => enrollmentApi.revokeToken(id),
    onSuccess: async () => {
      notifySuccess('Token revoked');
      setRevoking(null);
      await queryClient.invalidateQueries({ queryKey: qk.tokensAll });
    },
    onError: notifyError,
  });

  const createButton = (
    <Button
      size="sm"
      onClick={() => {
        setCreating(true);
      }}
    >
      <Plus aria-hidden="true" />
      New token
    </Button>
  );

  return (
    <>
      <PageHeader
        title="Enrollment"
        description="Tokens let the agent installer add computers to a site. Only the first characters of a token are kept, so a token can be recognised but not reused from here."
        actions={createButton}
      />
      <Panel title={organization ? `Tokens for ${organization.name}` : 'Tokens for all organizations'} flush>
        <QueryView
          query={tokens}
          what="enrollment tokens"
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyState icon={KeyRound} title="No enrollment tokens" action={createButton}>
              Create a token, then run the install command on each computer you want to manage.
            </EmptyState>
          }
        >
          {(list) => (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead scope="col">Name</TableHead>
                    <TableHead scope="col">Status</TableHead>
                    <TableHead scope="col">Token starts with</TableHead>
                    <TableHead scope="col">Enrolls into</TableHead>
                    <TableHead scope="col" className="text-right">
                      Used
                    </TableHead>
                    <TableHead scope="col">Expires</TableHead>
                    <TableHead scope="col">Created</TableHead>
                    <TableHead scope="col">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {list.map((t) => {
                    const state = tokenState(t);
                    const target = [
                      orgId ? null : (orgName.get(t.organizationId) ?? null),
                      t.siteName ?? 'Site',
                      t.groupId ? (t.groupName ?? 'Group') : null,
                    ]
                      .filter(Boolean)
                      .join(' / ');
                    return (
                      <TableRow key={t.id}>
                        <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-medium">
                          {t.name}
                        </TableHead>
                        <TableCell>
                          <StatusPill tone={TOKEN_STATE[state].tone}>{TOKEN_STATE[state].label}</StatusPill>
                        </TableCell>
                        <TableCell className="ident">{t.tokenPrefix}…</TableCell>
                        <TableCell>{target}</TableCell>
                        <TableCell className="text-right">
                          {t.uses} of {t.maxUses}
                        </TableCell>
                        <TableCell>
                          <RelativeTime value={t.expiresAt} />
                        </TableCell>
                        <TableCell>
                          <RelativeTime value={t.createdAt} />
                        </TableCell>
                        <TableCell className="py-1 text-right">
                          {state === 'active' ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-destructive hover:text-destructive"
                              onClick={() => {
                                setRevoking(t);
                              }}
                            >
                              Revoke<span className="sr-only"> {t.name}</span>
                            </Button>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </QueryView>
      </Panel>

      <InstallersPanel />

      <CreateTokenDialog
        open={creating}
        onOpenChange={setCreating}
        organizations={organizations}
        defaultOrganizationId={orgId}
      />
      <ConfirmDialog
        open={revoking !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRevoking(null);
          }
        }}
        title={`Revoke ${revoking?.name ?? 'token'}?`}
        description={
          <p>Installers using this token can no longer enroll. Devices that already enrolled with it stay connected.</p>
        }
        confirmLabel="Revoke token"
        destructive
        pending={revoke.isPending}
        onConfirm={() => {
          if (revoking) {
            revoke.mutate(revoking.id);
          }
        }}
      />
    </>
  );
}
