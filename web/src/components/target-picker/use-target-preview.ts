import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { jobKeys, jobsApi, type TargetPreview, type TargetRequest } from '@/lib/api/jobs';
import { useDebounced } from '@/lib/hooks';
import { osLabel } from '@/lib/os';

/** Live `POST /jobs/preview-target` for a target; `null` (incomplete target) asks nothing. */
export function useTargetPreview(request: TargetRequest | null) {
  // Typing in the filter fields must not send a request per keystroke.
  const key = useDebounced(request ? JSON.stringify(request) : '', 350);
  const debounced = key ? (JSON.parse(key) as TargetRequest) : null;
  const query = useQuery({
    queryKey: jobKeys.preview(debounced ?? {}),
    queryFn: ({ signal }) => jobsApi.previewTarget(debounced ?? {}, signal),
    enabled: debounced !== null,
    placeholderData: keepPreviousData,
    retry: false,
    staleTime: 10_000,
  });
  const settled = request !== null && key === JSON.stringify(request);
  return {
    preview: request !== null && debounced !== null && query.data ? query.data : null,
    /** The shown preview belongs to the current target (not to an earlier one while typing). */
    current: settled && !query.isPlaceholderData && query.isSuccess,
    isLoading: request !== null && (!settled || query.isFetching),
    error: request !== null && settled && query.isError ? query.error : null,
  };
}

export type TargetPreviewState = ReturnType<typeof useTargetPreview>;

export function osSplit(preview: TargetPreview): string {
  return Object.entries(preview.byOs)
    .sort((a, b) => b[1] - a[1])
    .map(([os, n]) => `${n} ${osLabel(os)}`)
    .join(', ');
}

export function deviceCountLabel(n: number): string {
  return `${n.toLocaleString('en')} ${n === 1 ? 'device' : 'devices'}`;
}
