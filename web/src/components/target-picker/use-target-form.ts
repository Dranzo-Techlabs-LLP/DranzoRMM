import { useState } from 'react';
import { useOrgFilter } from '@/app/org-filter';
import { useGroups, useSites } from '@/features/tenants/queries';
import { jobKeys, savedFiltersApi } from '@/lib/api/jobs';
import { useQuery } from '@tanstack/react-query';
import {
  describeTarget,
  deviceTarget,
  emptyTarget,
  targetProblem,
  toTargetRequest,
  type PickedDevice,
  type TargetDraft,
} from './target';
import { useTargetPreview } from './use-target-preview';

/**
 * State shared by every "do this on a target" dialog: the draft, the server request, the live preview and a
 * description for confirmations. With `fixedDevice` the target is that one device and no picker is shown.
 */
export function useTargetForm({
  fixedDevice,
  organizationId,
  preview: wantPreview = true,
}: {
  fixedDevice?: PickedDevice;
  /** Start in (or be locked to) this organization. */
  organizationId?: string | null;
  /** Ask the server for a device count (`POST /jobs/preview-target` needs `scripts.run`). */
  preview?: boolean;
}) {
  const { organizations, orgId } = useOrgFilter();
  const [target, setTarget] = useState<TargetDraft>(() =>
    fixedDevice ? deviceTarget(fixedDevice) : emptyTarget({ organizationId: organizationId ?? orgId ?? '' }),
  );
  const sites = useSites(undefined, !fixedDevice);
  const groups = useGroups(undefined, !fixedDevice);
  const savedFilters = useQuery({
    queryKey: jobKeys.savedFilters,
    queryFn: savedFiltersApi.list,
    staleTime: 30_000,
    enabled: target.mode === 'savedFilter',
  });
  const request = toTargetRequest(target);
  const preview = useTargetPreview(wantPreview ? request : null);
  const single = target.mode === 'devices' && target.devices.length === 1;
  return {
    target,
    setTarget,
    request,
    problem: targetProblem(target),
    preview,
    /** Device count for the current target, once the server has answered for exactly this target. */
    count: single ? 1 : preview.current && preview.preview ? preview.preview.deviceCount : null,
    /** One explicitly chosen device: no extra confirmation needed for non-destructive actions. */
    single,
    where: describeTarget(target, {
      organizations,
      sites: sites.data,
      groups: groups.data,
      savedFilters: savedFilters.data,
    }),
  };
}

export type TargetForm = ReturnType<typeof useTargetForm>;
