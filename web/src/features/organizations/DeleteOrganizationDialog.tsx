import { useMutation, useQueryClient } from '@tanstack/react-query';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { organizationsApi, qk, type Organization } from '@/lib/api';
import { notifyError, notifySuccess } from '@/lib/notify';

/** Typed-name confirmation, then `DELETE /organizations/{id}` (the server asks for step-up). */
export function DeleteOrganizationDialog({
  organization,
  onOpenChange,
  onDeleted,
}: {
  organization: Organization | null;
  onOpenChange: (open: boolean) => void;
  onDeleted?: () => void;
}) {
  const queryClient = useQueryClient();
  const remove = useMutation({
    mutationFn: (id: string) => organizationsApi.remove(id),
    onSuccess: async () => {
      notifySuccess('Organization deleted');
      onOpenChange(false);
      onDeleted?.();
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.organizations }),
        queryClient.invalidateQueries({ queryKey: qk.devices }),
        queryClient.invalidateQueries({ queryKey: qk.sitesAll }),
        queryClient.invalidateQueries({ queryKey: qk.groupsAll }),
        queryClient.invalidateQueries({ queryKey: qk.tokensAll }),
      ]);
    },
    onError: notifyError,
  });
  const devices = organization?.deviceCount ?? 0;
  return (
    <ConfirmDialog
      open={organization !== null}
      onOpenChange={onOpenChange}
      title={`Delete ${organization?.name ?? 'organization'}?`}
      description={
        <>
          <p>
            This removes the organization with its sites, groups and enrollment tokens.{' '}
            {devices === 0
              ? 'It has no devices.'
              : `Its ${devices} ${devices === 1 ? 'device is' : 'devices are'} removed and their certificates revoked, so the agents can no longer connect.`}
          </p>
          <p>Audit log entries are kept. This cannot be undone.</p>
        </>
      }
      confirmLabel="Delete organization"
      destructive
      typeToConfirm={organization?.name}
      pending={remove.isPending}
      onConfirm={() => {
        if (organization) {
          remove.mutate(organization.id);
        }
      }}
    />
  );
}
