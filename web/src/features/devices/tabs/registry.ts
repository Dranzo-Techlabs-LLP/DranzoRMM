import type { ComponentType } from 'react';
import type { DeviceDetail } from '@/lib/api';
import { P, type Requirement } from '@/lib/auth/permissions';
import { ComplianceTab } from './ComplianceTab';
import { DangerTab } from './DangerTab';
import { ManageTab } from './ManageTab';
import { OverviewTab } from './OverviewTab';
import { PatchesTab } from './PatchesTab';
import { RemoteTab } from './RemoteTab';
import { ScriptsTab } from './ScriptsTab';
import { SecurityTab } from './SecurityTab';
import { SoftwareTab } from './SoftwareTab';

export interface DeviceTabProps {
  device: DeviceDetail;
}

export interface DeviceTab extends Requirement {
  /** Used in the URL: `/devices/{id}?tab={id}`. */
  id: string;
  label: string;
  component: ComponentType<DeviceTabProps>;
}

/**
 * Tabs of the device detail page, in display order. A tab is shown when the user holds its permission.
 *
 * Later phases add their tab here and nowhere else, for example:
 *   { id: 'scripts',  label: 'Scripts',  permission: P.scriptsRead,  component: ScriptsTab },   // Phase 2
 *   { id: 'software', label: 'Software', permission: P.softwareRead, component: SoftwareTab },  // Phase 3
 *   { id: 'patches',  label: 'Patches',  permission: P.patchesRead,  component: PatchesTab },   // Phase 4
 *   { id: 'security', label: 'Security', permission: P.securityRead, component: SecurityTab },  // Phase 5
 *   { id: 'remote',   label: 'Remote',   permission: P.sessionsRead, component: RemoteTab },    // Phase 6
 */
export const DEVICE_TABS: DeviceTab[] = [
  { id: 'overview', label: 'Overview', permission: P.devicesRead, component: OverviewTab },
  { id: 'scripts', label: 'Scripts', permission: P.scriptsRead, component: ScriptsTab },
  { id: 'software', label: 'Software', permission: P.softwareRead, component: SoftwareTab },
  { id: 'patches', label: 'Patches', permission: P.patchesRead, component: PatchesTab },
  { id: 'security', label: 'Security', permission: P.securityRead, component: SecurityTab },
  { id: 'compliance', label: 'Compliance', permission: P.policiesRead, component: ComplianceTab },
  { id: 'remote', label: 'Remote', permission: P.sessionsRead, component: RemoteTab },
  { id: 'manage', label: 'Tags and group', permission: P.devicesManage, component: ManageTab },
  { id: 'danger', label: 'Danger zone', permission: P.devicesRevoke, component: DangerTab },
];
