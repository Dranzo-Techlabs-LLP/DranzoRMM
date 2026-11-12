import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';
import { useOrganizationsQuery } from '@/features/tenants/queries';
import type { Id, Organization } from '@/lib/api';
import { P } from '@/lib/auth/permissions';
import { useAccess } from '@/lib/auth/session';
import { readPref, writePref } from '@/lib/prefs';

interface OrgFilterValue {
  /** Selected organization, or `null` for all organizations the user can see. */
  orgId: Id | null;
  organization: Organization | null;
  setOrgId: (id: Id | null) => void;
  organizations: Organization[];
  /** False when the user cannot list organizations (no `tenants.read`). */
  available: boolean;
  isLoading: boolean;
}

const OrgFilterContext = createContext<OrgFilterValue | null>(null);

/** The top-bar organization switcher: one filter shared by Overview, Devices, Enrollment and Audit log. */
export function OrgFilterProvider({ children }: { children: ReactNode }) {
  const access = useAccess();
  const available = access.has(P.tenantsRead);
  const query = useOrganizationsQuery(available);
  const [selected, setSelected] = useState<Id | null>(() => readPref('org'));

  const setOrgId = useCallback((id: Id | null) => {
    setSelected(id);
    writePref('org', id);
  }, []);

  const value = useMemo<OrgFilterValue>(() => {
    const organizations = query.data ?? [];
    // A saved selection may point at an organization that was deleted or is no longer visible.
    const organization = organizations.find((o) => o.id === selected) ?? null;
    const orgId = !available ? null : query.data ? (organization?.id ?? null) : selected;
    return { orgId, organization, setOrgId, organizations, available, isLoading: available && query.isPending };
  }, [available, query.data, query.isPending, selected, setOrgId]);

  return <OrgFilterContext.Provider value={value}>{children}</OrgFilterContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useOrgFilter(): OrgFilterValue {
  const ctx = useContext(OrgFilterContext);
  if (!ctx) {
    throw new Error('useOrgFilter() needs <OrgFilterProvider>');
  }
  return ctx;
}
