import {
  Bell,
  ClipboardCheck,
  Building2,
  FileBarChart,
  KeyRound,
  KeySquare,
  LayoutDashboard,
  ListChecks,
  MonitorSmartphone,
  Network,
  PackageOpen,
  Rocket,
  ScrollText,
  ShieldCheck,
  SquareTerminal,
  TerminalSquare,
  UserCheck,
  Users,
  Wifi,
  Wrench,
  type LucideIcon,
} from 'lucide-react';
import type { ComponentType } from 'react';
import { OpenAlertsBadge } from '@/features/alerts/OpenAlertsBadge';
import { P, type Access, type Requirement } from '@/lib/auth/permissions';

/**
 * The page registry: the single place that defines navigation and routes.
 *
 * To add a page (for example Scripts in Phase 2): build `features/scripts/ScriptsPage.tsx` with a default export and
 * give the matching entry below a `load` function. The sidebar entry, the route, the permission gate and the page
 * title all come from this entry. Entries without `load` are planned pages: they keep their place in the structure
 * but are not rendered or routable yet.
 */

type PageModule = Promise<{ default: ComponentType }>;

export interface PageDef extends Requirement {
  id: string;
  /** Path below the app root; `''` is the index page. */
  path: string;
  label: string;
  icon: LucideIcon;
  load?: () => PageModule;
  /** Small count next to the nav label (for example open alerts). Rendered only for users who can open the page. */
  badge?: ComponentType<{ collapsed: boolean }>;
  /** Routes that belong to this page (detail views). They share its permission and keep its nav item active. */
  children?: { path: string; load: () => PageModule }[];
}

export interface NavArea {
  id: string;
  label: string;
  pages: PageDef[];
}

export const NAV_AREAS: NavArea[] = [
  {
    id: 'fleet',
    label: 'Fleet',
    pages: [
      {
        id: 'overview',
        path: '',
        label: 'Overview',
        icon: LayoutDashboard,
        permission: P.devicesRead,
        load: () => import('@/features/overview/OverviewPage'),
      },
      {
        id: 'devices',
        path: 'devices',
        label: 'Devices',
        icon: MonitorSmartphone,
        permission: P.devicesRead,
        load: () => import('@/features/devices/DevicesPage'),
        children: [{ path: 'devices/:deviceId', load: () => import('@/features/devices/DeviceDetailPage') }],
      },
      {
        id: 'organizations',
        path: 'organizations',
        label: 'Organizations',
        icon: Building2,
        permission: P.tenantsRead,
        load: () => import('@/features/organizations/OrganizationsPage'),
        children: [
          {
            path: 'organizations/:organizationId',
            load: () => import('@/features/organizations/OrganizationDetailPage'),
          },
        ],
      },
      {
        id: 'enrollment',
        path: 'enrollment',
        label: 'Enrollment',
        icon: KeyRound,
        permission: P.enrollmentManage,
        load: () => import('@/features/enrollment/EnrollmentPage'),
      },
    ],
  },
  {
    id: 'automation',
    label: 'Automation',
    pages: [
      {
        id: 'scripts',
        path: 'scripts',
        label: 'Scripts',
        icon: SquareTerminal,
        permission: P.scriptsRead,
        load: () => import('@/features/scripts/ScriptsPage'),
        children: [
          { path: 'scripts/new', load: () => import('@/features/scripts/ScriptEditorPage') },
          { path: 'scripts/:scriptId', load: () => import('@/features/scripts/ScriptDetailPage') },
          { path: 'scripts/:scriptId/edit', load: () => import('@/features/scripts/ScriptEditorPage') },
        ],
      },
      {
        id: 'jobs',
        path: 'jobs',
        label: 'Jobs',
        icon: ListChecks,
        permission: P.jobsRead,
        load: () => import('@/features/jobs/JobsPage'),
        children: [
          { path: 'jobs/:jobId', load: () => import('@/features/jobs/JobDetailPage') },
          { path: 'jobs/:jobId/runs/:runId', load: () => import('@/features/jobs/RunDetailPage') },
        ],
      },
      {
        id: 'policies',
        path: 'policies',
        label: 'Policies',
        icon: ClipboardCheck,
        permission: P.policiesRead,
        load: () => import('@/features/policies/PoliciesPage'),
      },
    ],
  },
  {
    id: 'software',
    label: 'Software',
    pages: [
      {
        id: 'software',
        path: 'software',
        label: 'Software',
        icon: PackageOpen,
        permission: P.softwareRead,
        load: () => import('@/features/software/SoftwarePage'),
      },
      {
        id: 'patches',
        path: 'patches',
        label: 'Patches',
        icon: Wrench,
        permission: P.patchesRead,
        load: () => import('@/features/patches/PatchesPage'),
      },
    ],
  },
  {
    id: 'protection',
    label: 'Protection',
    pages: [
      {
        id: 'security',
        path: 'security',
        label: 'Security',
        icon: ShieldCheck,
        permission: P.securityRead,
        load: () => import('@/features/security/SecurityPage'),
      },
      {
        id: 'alerts',
        path: 'alerts',
        label: 'Alerts',
        icon: Bell,
        permission: P.alertsRead,
        load: () => import('@/features/alerts/AlertsPage'),
        badge: OpenAlertsBadge,
      },
    ],
  },
  {
    id: 'network',
    label: 'Network',
    pages: [
      {
        id: 'network-devices',
        path: 'network/devices',
        label: 'Network devices',
        icon: Network,
        permission: P.networkRead,
        load: () => import('@/features/network/NetworkDevicesPage'),
      },
      {
        id: 'network-controllers',
        path: 'network/controllers',
        label: 'Wi-Fi & controllers',
        icon: Wifi,
        permission: P.networkRead,
        load: () => import('@/features/network/NetworkControllersPage'),
      },
    ],
  },
  {
    id: 'support',
    label: 'Support',
    pages: [
      {
        id: 'remote',
        path: 'remote',
        label: 'Remote sessions',
        icon: TerminalSquare,
        permission: P.sessionsRead,
        load: () => import('@/features/remote/SessionsPage'),
      },
    ],
  },
  {
    id: 'records',
    label: 'Records',
    pages: [
      {
        id: 'reports',
        path: 'reports',
        label: 'Reports',
        icon: FileBarChart,
        permission: P.reportsRead,
        load: () => import('@/features/reports/ReportsPage'),
      },
      {
        id: 'audit',
        path: 'audit',
        label: 'Audit log',
        icon: ScrollText,
        permission: P.auditRead,
        load: () => import('@/features/audit/AuditPage'),
      },
    ],
  },
  {
    id: 'admin',
    label: 'Admin',
    pages: [
      {
        id: 'users',
        path: 'admin/users',
        label: 'Users & roles',
        icon: Users,
        permission: P.usersRead,
        partnerWide: true,
        load: () => import('@/features/admin/UsersPage'),
      },
      {
        id: 'releases',
        path: 'admin/releases',
        label: 'Agent releases',
        icon: Rocket,
        permission: P.releasesManage,
        partnerWide: true,
        load: () => import('@/features/admin/releases/ReleasesPage'),
      },
      {
        id: 'api-keys',
        path: 'admin/api-keys',
        label: 'API keys',
        icon: KeySquare,
        permission: P.apiKeysManage,
        partnerWide: true,
        load: () => import('@/features/admin/apikeys/ApiKeysPage'),
      },
      {
        id: 'access-review',
        path: 'admin/access-review',
        label: 'Access review',
        icon: UserCheck,
        permission: P.usersRead,
        partnerWide: true,
        load: () => import('@/features/admin/access/AccessReviewPage'),
      },
    ],
  },
];

export function isImplemented(page: PageDef): page is PageDef & { load: () => PageModule } {
  return page.load !== undefined;
}

/** Implemented pages across all areas. */
export function implementedPages(): (PageDef & { load: () => PageModule })[] {
  return NAV_AREAS.flatMap((a) => a.pages).filter(isImplemented);
}

/** Sidebar content for a user: implemented pages they may open, grouped by area, empty areas dropped. */
export function visibleNav(access: Access, areas: NavArea[] = NAV_AREAS): NavArea[] {
  return areas
    .map((area) => ({ ...area, pages: area.pages.filter((p) => isImplemented(p) && access.can(p)) }))
    .filter((area) => area.pages.length > 0);
}

/** First page the user can open; used when the index page is not available to them. */
export function firstAccessiblePath(access: Access): string | null {
  const page = visibleNav(access)[0]?.pages[0];
  return page ? `/${page.path}` : null;
}
