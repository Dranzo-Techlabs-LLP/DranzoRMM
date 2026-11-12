import { useOrganizationsQuery } from '@/features/tenants/queries';
import { Building2, MoreHorizontal, Pencil, Plus, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router';
import { EmptyState, PageHeader, Panel, QueryView } from '@/components/page';
import { StatusPill } from '@/components/status';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import type { Organization } from '@/lib/api';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { useDocumentTitle } from '@/lib/hooks';
import { CONSENT } from './consent';
import { DeleteOrganizationDialog } from './DeleteOrganizationDialog';
import { OrganizationFormDialog } from './OrganizationFormDialog';

export default function OrganizationsPage() {
  useDocumentTitle('Organizations');
  const access = useAccess();
  const navigate = useNavigate();
  const query = useOrganizationsQuery();
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<Organization | null>(null);
  const [deleting, setDeleting] = useState<Organization | null>(null);

  const canEdit = access.has(P.tenantsManage);
  // Creating and deleting organizations needs tenants.manage for the whole partner.
  const canCreateDelete = access.hasPartnerWide(P.tenantsManage);

  const createButton = canCreateDelete ? (
    <Button
      size="sm"
      onClick={() => {
        setCreating(true);
      }}
    >
      <Plus aria-hidden="true" />
      New organization
    </Button>
  ) : null;

  return (
    <>
      <PageHeader
        title="Organizations"
        description="The client businesses you manage. Each has its own sites, device groups and settings."
        actions={createButton}
      />
      <Panel flush>
        <QueryView
          query={query}
          what="organizations"
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyState icon={Building2} title="No organizations yet" action={createButton}>
              {canCreateDelete
                ? 'Add the first client business to start enrolling its computers.'
                : 'No organization has been shared with you yet.'}
            </EmptyState>
          }
        >
          {(orgs) => (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Name</TableHead>
                  <TableHead scope="col" className="text-right">
                    Devices
                  </TableHead>
                  <TableHead scope="col" className="text-right">
                    Online
                  </TableHead>
                  <TableHead scope="col">Time zone</TableHead>
                  <TableHead scope="col">Remote sessions</TableHead>
                  <TableHead scope="col">PowerShell</TableHead>
                  {canEdit ? (
                    <TableHead scope="col" className="w-10">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  ) : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {orgs.map((o) => (
                  <TableRow key={o.id}>
                    <TableHead scope="row" className="text-foreground h-auto py-2 text-sm font-medium">
                      <Link to={`/organizations/${o.id}`} className="hover:underline">
                        {o.name}
                      </Link>
                    </TableHead>
                    <TableCell className="text-right">{o.deviceCount}</TableCell>
                    <TableCell className="text-right">{o.onlineCount}</TableCell>
                    <TableCell>{o.timeZone.replaceAll('_', ' ')}</TableCell>
                    <TableCell>{CONSENT[o.consentMode].label}</TableCell>
                    <TableCell>
                      {o.requireSignedPowerShell ? (
                        <StatusPill tone="info">Signed only</StatusPill>
                      ) : (
                        <span className="text-muted-foreground">Any script</span>
                      )}
                    </TableCell>
                    {canEdit ? (
                      <TableCell className="py-1 text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon-sm" aria-label={`Actions for ${o.name}`}>
                              <MoreHorizontal aria-hidden="true" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              onSelect={() => {
                                setEditing(o);
                              }}
                            >
                              <Pencil aria-hidden="true" />
                              Edit
                            </DropdownMenuItem>
                            {canCreateDelete ? (
                              <DropdownMenuItem
                                variant="destructive"
                                onSelect={() => {
                                  setDeleting(o);
                                }}
                              >
                                <Trash2 aria-hidden="true" />
                                Delete
                              </DropdownMenuItem>
                            ) : null}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </QueryView>
      </Panel>

      <OrganizationFormDialog
        open={creating}
        onOpenChange={setCreating}
        onCreated={(id) => void navigate(`/organizations/${id}`)}
      />
      <OrganizationFormDialog
        open={editing !== null}
        onOpenChange={(open) => {
          if (!open) {
            setEditing(null);
          }
        }}
        organization={editing ?? undefined}
      />
      <DeleteOrganizationDialog
        organization={deleting}
        onOpenChange={(open) => {
          if (!open) {
            setDeleting(null);
          }
        }}
      />
    </>
  );
}
