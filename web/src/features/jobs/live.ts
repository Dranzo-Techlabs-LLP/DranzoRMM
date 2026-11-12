import { useEffect, useEffectEvent, useState } from 'react';
import type { Id } from '@/lib/api';
import type { OutputChunk } from '@/lib/api/jobs';
import { useLive } from '@/lib/live/LiveProvider';

/** `run` event of the live hub (`LiveNotifier.RunChangedAsync`). */
export interface RunEvent {
  id: Id;
  jobId: Id;
  deviceId: Id;
  status: string;
  exitCode: number | null;
  message: string | null;
  truncated: boolean;
  finishedAt: string | null;
}

/** `runOutput` event: one output chunk of a run the connection subscribed to. */
export interface RunOutputEvent extends OutputChunk {
  runId: Id;
}

/** `jobChanged` event on `job:{jobId}`: something about the job's runs changed; refetch `GET /jobs/{id}`. */
export interface JobChangedEvent {
  jobId: Id;
}

export type RunFeedState = 'connecting' | 'live' | 'reconnecting' | 'polling';

/**
 * Follows a run (`runId`) or all runs of a job (`jobId`) over the app's live connection while `enabled`.
 * - Run: `onRun` / `onOutput` receive the run's own `run` and `runOutput` events.
 * - Job: the hub sends only `jobChanged {jobId}` (no run details, which could belong to other organizations);
 *   `onJobChanged` should refetch the tenant-filtered job.
 * - `onResync` is called after every (re)subscription: events may have been missed while not subscribed, so the
 *   caller refetches the stored state and merges it.
 * Returns `'polling'` when live updates are not available (no hub access, hub down, subscription refused); callers
 * then refetch on an interval.
 */
export function useRunFeed({
  runId,
  jobId,
  enabled,
  onRun,
  onOutput,
  onResync,
  onJobChanged,
}: {
  runId?: Id;
  jobId?: Id;
  enabled: boolean;
  onRun?: (event: RunEvent) => void;
  onOutput?: (event: RunOutputEvent) => void;
  onResync?: () => void;
  onJobChanged?: () => void;
}): RunFeedState {
  const { client, state: hubState } = useLive();
  // null = not answered yet; the hub answers false when the run or job is outside the caller's scope.
  const [subscribed, setSubscribed] = useState<boolean | null>(null);
  const handleRun = useEffectEvent((event: RunEvent) => onRun?.(event));
  const handleOutput = useEffectEvent((event: RunOutputEvent) => onOutput?.(event));
  const handleResync = useEffectEvent(() => onResync?.());
  const handleJobChanged = useEffectEvent(() => onJobChanged?.());
  const hubLive = hubState === 'live';

  useEffect(() => {
    // Group membership belongs to the connection id, so this runs again after every reconnect (`hubLive` flips).
    if (!enabled || !client || !hubLive || (!runId && !jobId)) {
      return;
    }
    let cancelled = false;
    const offRun = client.on('run', (payload) => {
      const event = payload as RunEvent;
      if (runId && event.id === runId) {
        handleRun(event);
      }
    });
    // `jobChanged` is not in the shared `LiveEvents` map yet, so it is subscribed through an untyped view of `on`.
    const onAny = client.on as unknown as (event: string, handler: (payload: unknown) => void) => () => void;
    const offJob = onAny('jobChanged', (payload) => {
      const event = payload as Partial<JobChangedEvent> | null;
      if (jobId && !runId && event?.jobId === jobId) {
        handleJobChanged();
      }
    });
    const offOutput = client.on('runOutput', (payload) => {
      const event = payload as RunOutputEvent;
      if (runId && event.runId === runId) {
        handleOutput(event);
      }
    });
    const subscribing = runId
      ? client.invoke<boolean | null>('SubscribeRun', runId)
      : client.invoke<boolean | null>('SubscribeJob', jobId);
    subscribing.then(
      (ok) => {
        if (cancelled) {
          return;
        }
        setSubscribed(ok !== false);
        if (ok !== false) {
          handleResync();
        }
      },
      () => {
        if (!cancelled) {
          setSubscribed(false);
        }
      },
    );
    return () => {
      cancelled = true;
      offRun();
      offJob();
      offOutput();
      if (runId && client.state() === 'live') {
        client.invoke('UnsubscribeRun', runId).catch(() => undefined);
      }
      setSubscribed(null);
    };
  }, [enabled, client, hubLive, runId, jobId]);

  if (!enabled || !client || hubState === 'offline') {
    return 'polling';
  }
  if (hubState !== 'live') {
    return hubState;
  }
  return subscribed === null ? 'connecting' : subscribed ? 'live' : 'polling';
}
