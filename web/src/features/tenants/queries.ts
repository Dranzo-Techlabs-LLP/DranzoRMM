import { useQuery } from '@tanstack/react-query';
import { groupsApi, organizationsApi, qk, sitesApi, type Id } from '@/lib/api';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';

/** Sites of one organization, or of every visible organization when `organizationId` is omitted. */
export function useSites(organizationId?: Id, enabled = true) {
  const access = useAccess();
  return useQuery({
    queryKey: qk.sites(organizationId),
    queryFn: () => sitesApi.list(organizationId),
    enabled: enabled && access.has(P.tenantsRead),
    staleTime: 30_000,
  });
}

export function useGroups(organizationId?: Id, enabled = true) {
  const access = useAccess();
  return useQuery({
    queryKey: qk.groups(organizationId),
    queryFn: () => groupsApi.list({ organizationId }),
    enabled: enabled && access.has(P.tenantsRead),
    staleTime: 30_000,
  });
}

export function useOrganizationsQuery(enabled = true) {
  return useQuery({ queryKey: qk.organizations, queryFn: organizationsApi.list, enabled, staleTime: 30_000 });
}
