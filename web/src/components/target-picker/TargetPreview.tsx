import { KeyRound } from 'lucide-react';
import { InlineAlert } from '@/components/status';
import { errorMessage, isApiError } from '@/lib/api';
import { osLabel } from '@/lib/os';
import { cn } from '@/lib/utils';
import { deviceCountLabel, osSplit, type TargetPreviewState } from './use-target-preview';

/**
 * What the target covers right now: device count, per-OS split, how many are online, and whether the server will
 * ask for the authenticator code. `supportedOs` adds a warning for devices the action cannot run on.
 */
export function TargetPreviewPanel({
  state,
  problem,
  supportedOs,
  scheduled = false,
  stepUpNotice = true,
  className,
}: {
  state: TargetPreviewState;
  /** Why the target is incomplete (from `targetProblem`). */
  problem: string | null;
  supportedOs?: readonly string[];
  /** The run is scheduled: the server asks for the code for every target except explicit devices. */
  scheduled?: boolean;
  /** Show the authenticator-code notice (off where nothing is run, for example when saving a filter). */
  stepUpNotice?: boolean;
  className?: string;
}) {
  const { preview, error, isLoading, current } = state;
  const unsupported =
    preview && supportedOs
      ? Object.entries(preview.byOs)
          .filter(([os]) => !supportedOs.includes(os))
          .reduce((n, [, count]) => n + count, 0)
      : 0;

  return (
    <div className={cn('bg-muted/50 rounded-md border px-3 py-2.5', className)} aria-busy={isLoading}>
      <div role="status" aria-live="polite">
        {problem ? (
          <p className="text-muted-foreground">{problem}</p>
        ) : error ? (
          isApiError(error) && error.status === 403 ? (
            <p className="text-muted-foreground">
              A device count preview is not available with your role. The server checks the target when you confirm.
            </p>
          ) : isApiError(error) && error.status === 404 ? (
            <p className="text-danger">
              This target no longer exists or is outside what you can reach. Choose another one.
            </p>
          ) : (
            <p className="text-danger">Could not check the target. {errorMessage(error)}</p>
          )
        ) : preview ? (
          <p className={cn(!current && 'opacity-60')}>
            <span className="font-semibold">{deviceCountLabel(preview.deviceCount)}</span>
            {preview.deviceCount > 0 ? (
              <>
                {' '}
                ({osSplit(preview)}), {preview.online.toLocaleString('en')} online now
                {preview.online < preview.deviceCount ? '. Offline devices run it when they next connect.' : '.'}
              </>
            ) : (
              '. Nothing would run.'
            )}
          </p>
        ) : (
          <p className="text-muted-foreground">Checking the target…</p>
        )}
      </div>
      {preview && !problem && !error && unsupported > 0 && supportedOs ? (
        <p className="text-warn mt-1.5 text-xs font-medium">
          {deviceCountLabel(unsupported)} in this target {unsupported === 1 ? 'runs' : 'run'} an operating system this
          does not support ({supportedOs.map(osLabel).join(', ')} only). Those devices will report “not supported”.
        </p>
      ) : null}
      {stepUpNotice && preview && !problem && !error && (preview.stepUpRequired || scheduled) ? (
        <InlineAlert tone="info" live={false} className="mt-2">
          <span className="inline-flex items-start gap-1.5">
            <KeyRound aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
            <span>
              <span className="font-semibold">This run needs your authenticator code.</span>{' '}
              {preview.stepUpRequired
                ? 'It covers many devices or a whole organization, so you will be asked to confirm it is you.'
                : 'Scheduled runs on a group, site, organization or filter are confirmed with your code.'}
            </span>
          </span>
        </InlineAlert>
      ) : null}
    </div>
  );
}
