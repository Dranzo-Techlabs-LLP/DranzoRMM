import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ExternalLink, FolderOpen, MonitorUp, Power, RotateCcw, SquareTerminal, type LucideIcon } from 'lucide-react';
import { lazy, Suspense, useRef, useState, type ReactNode } from 'react';
import { Link, useSearchParams } from 'react-router';
import { useOrgFilter } from '@/app/org-filter';
import { LoadingRows, Panel } from '@/components/page';
import { RelativeTime } from '@/components/relative-time';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { FileBrowser } from '@/features/remote/FileBrowser';
import { consentNotice, INDICATOR_NOTICE, KIND_LABEL } from '@/features/remote/consent';
import { pathStyleFor } from '@/features/remote/paths';
import { useRemoteSessions } from '@/features/remote/RemoteSessions';
import { isOpen, isOver, type SessionState } from '@/features/remote/session-machine';
import { SessionStatus } from '@/features/remote/SessionStatus';
import { errorMessage, isApiError } from '@/lib/api';
import {
  normalizeSessionState,
  OPEN_SESSION_STATES,
  remoteApi,
  remoteKeys,
  type SessionKind,
  type TerminalRunAs,
} from '@/lib/api/remote';
import { P } from '@/lib/auth/permissions';
import { useAccess, useMe } from '@/lib/auth/session';
import { useLive } from '@/lib/live/LiveProvider';
import { notifyError, notifySuccess } from '@/lib/notify';
import type { DeviceTabProps } from './registry';

const TerminalView = lazy(() => import('@/features/remote/TerminalView'));

const KINDS: { kind: SessionKind; permission: string; icon: LucideIcon }[] = [
  { kind: 'terminal', permission: P.remoteTerminal, icon: SquareTerminal },
  { kind: 'files', permission: P.remoteFiles, icon: FolderOpen },
  { kind: 'desktop', permission: P.remoteDesktop, icon: MonitorUp },
];

type Device = DeviceTabProps['device'];

/** Why a session cannot be started right now, or `null` when it can. */
function blocker(device: Device, kind: SessionKind): string | null {
  if (device.status === 'revoked') {
    return 'This device is revoked. It cannot connect, so no session can start.';
  }
  if (!device.isOnline) {
    return 'This device is offline. A session can start only while the device is connected.';
  }
  const capabilities = device.capabilities ?? [];
  if (capabilities.length > 0 && !capabilities.includes(`session.${kind}`)) {
    return `The agent on this device does not support ${KIND_LABEL[kind]?.toLowerCase() ?? kind} sessions. Update the agent.`;
  }
  return null;
}

/** Start / status / end controls shared by the three kinds of session. `children` is the working area. */
function SessionFrame({
  device,
  kind,
  intro,
  startLabel,
  startControls,
  startOptions,
  endButtonRef,
  children,
}: {
  device: Device;
  kind: SessionKind;
  intro: ReactNode;
  startLabel: string;
  startControls?: ReactNode;
  startOptions?: { runAs?: TerminalRunAs };
  endButtonRef?: React.Ref<HTMLButtonElement>;
  children: (session: SessionState) => ReactNode;
}) {
  const { sessions, start, end, reset } = useRemoteSessions();
  const { organizations } = useOrgFilter();
  const session = sessions[kind];
  const consent = organizations.find((o) => o.id === device.organizationId)?.consentMode ?? null;
  const blocked = blocker(device, kind);
  const idle = session.phase === 'idle';
  const over = isOver(session.phase);

  return (
    <div className="grid gap-3">
      {idle ? (
        <>
          <div className="text-muted-foreground max-w-[75ch] space-y-1">{intro}</div>
          <InlineAlert tone="info" live={false} title="What the person at this computer will see">
            <p>{consentNotice(consent)}</p>
            <p>{INDICATOR_NOTICE}</p>
          </InlineAlert>
          {blocked ? (
            <InlineAlert tone="warn" live={false}>
              {blocked}
            </InlineAlert>
          ) : null}
          <div className="flex flex-wrap items-end gap-3">
            {startControls}
            <Button
              disabled={blocked !== null}
              onClick={() => {
                start(kind, startOptions);
              }}
            >
              {startLabel}
            </Button>
            <p className="text-muted-foreground text-xs">You will be asked for your authenticator code.</p>
          </div>
        </>
      ) : null}

      <SessionStatus session={session} />

      {!idle ? (
        <div className="flex flex-wrap items-center gap-2">
          {isOpen(session.phase) ? (
            <Button
              ref={endButtonRef}
              variant="destructive"
              size="sm"
              disabled={session.ending}
              onClick={() => {
                end(kind);
              }}
            >
              <Power aria-hidden="true" />
              {session.ending ? 'Ending…' : session.phase === 'active' ? 'End session' : 'Cancel request'}
            </Button>
          ) : null}
          {over ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                reset(kind);
              }}
            >
              <RotateCcw aria-hidden="true" />
              Close and start over
            </Button>
          ) : null}
          {isOpen(session.phase) ? (
            <p className="text-muted-foreground text-xs">
              Leaving this device&apos;s page ends the session. Reloading the page does not reconnect to it.
            </p>
          ) : null}
        </div>
      ) : null}

      {children(session)}
    </div>
  );
}

function TerminalPanel({ device }: { device: Device }) {
  const { terminal, joined, inputFailed } = useRemoteSessions();
  const { state: liveState } = useLive();
  const [runAs, setRunAs] = useState<TerminalRunAs>('system');
  const endButton = useRef<HTMLButtonElement>(null);
  const systemAccount = device.os === 'windows' ? 'SYSTEM' : 'root';

  return (
    <SessionFrame
      device={device}
      kind="terminal"
      startLabel="Start terminal session"
      startOptions={{ runAs }}
      endButtonRef={endButton}
      intro={
        <p>
          Opens a command line on <span className="ident">{device.hostname}</span>. What you type is sent to the device
          and a hash of the whole input is kept in the audit log.
        </p>
      }
      startControls={
        <div className="grid gap-1">
          <Label htmlFor="terminal-run-as" className="text-xs">
            Run as
          </Label>
          <NativeSelect
            id="terminal-run-as"
            size="sm"
            value={runAs}
            onChange={(e) => {
              setRunAs(e.target.value === 'user' ? 'user' : 'system');
            }}
          >
            <NativeSelectOption value="system">System account ({systemAccount})</NativeSelectOption>
            <NativeSelectOption value="user">
              The logged-in user{device.consoleUser ? ` (${device.consoleUser})` : ''}
            </NativeSelectOption>
          </NativeSelect>
        </div>
      }
    >
      {(session) =>
        terminal && session.phase !== 'idle' ? (
          <div className="grid gap-2">
            {session.phase === 'active' ? (
              <p className="bg-warn-surface text-foreground rounded-md px-3 py-1.5 text-sm font-medium">
                {terminal.runAs === 'user'
                  ? `Connected as the logged-in user${device.consoleUser ? ` (${device.consoleUser})` : ''}.`
                  : `Connected as ${systemAccount}, the agent's system account. Commands run with full control of this computer.`}
              </p>
            ) : null}
            {session.phase === 'active' && (liveState !== 'live' || !joined('terminal')) ? (
              <InlineAlert tone="warn" title="Live connection interrupted">
                Output cannot be shown and keystrokes are not sent until the dashboard reconnects. If this lasts, end
                the session and start a new one.
              </InlineAlert>
            ) : null}
            {session.phase === 'active' && inputFailed && liveState === 'live' ? (
              <InlineAlert tone="warn" title="Your last input did not reach the device">
                Try again. If it keeps happening, end the session and start a new one.
              </InlineAlert>
            ) : null}
            <Suspense fallback={<LoadingRows label="terminal" rows={6} />}>
              <TerminalView
                channel={terminal}
                active={session.phase === 'active'}
                onLeave={() => endButton.current?.focus()}
              />
            </Suspense>
            <p className="text-muted-foreground text-xs">
              {isOver(session.phase)
                ? 'The session is over. The text above is what was on screen; nothing more can be typed.'
                : 'Selecting text does not copy it. Copy with Ctrl+Shift+C (⌘C on a Mac), paste with Ctrl+Shift+V (⌘V). Tab goes to the remote shell; press Ctrl+Shift+E to move focus out of the terminal.'}
            </p>
          </div>
        ) : null
      }
    </SessionFrame>
  );
}

function FilesPanel({ device }: { device: Device }) {
  return (
    <SessionFrame
      device={device}
      kind="files"
      startLabel="Start file session"
      intro={
        <p>
          Browse folders on <span className="ident">{device.hostname}</span>, download a file from it or upload one to
          it. The agent reads and writes files with its system account.
        </p>
      }
    >
      {(session) =>
        session.sessionId && (session.phase === 'active' || session.phase === 'ended') ? (
          <FileBrowser
            key={session.sessionId}
            sessionId={session.sessionId}
            style={pathStyleFor(device.os)}
            active={session.phase === 'active'}
          />
        ) : null
      }
    </SessionFrame>
  );
}

function DesktopLink({ sessionId, device }: { sessionId: string; device: Device }) {
  const access = useAccess();
  const queryClient = useQueryClient();
  // The link signs the technician in to MeshCentral: it is fetched once, kept in memory and never cached or logged.
  const link = useQuery({
    queryKey: ['sessions', sessionId, 'desktop-url'],
    queryFn: () => remoteApi.desktopUrl(sessionId),
    retry: false,
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
  });
  const install = useMutation({
    mutationFn: () => remoteApi.installMeshAgent(device.id),
    onSuccess: async () => {
      notifySuccess('Installing the remote desktop agent. This can take a few minutes.');
      await queryClient.invalidateQueries({ queryKey: ['devices', 'detail', device.id] });
    },
    onError: notifyError,
  });

  if (link.isPending) {
    return (
      <p role="status" className="text-muted-foreground">
        Preparing the remote desktop link…
      </p>
    );
  }
  if (link.isError) {
    const conflict = isApiError(link.error) && link.error.status === 409;
    return (
      <div className="grid gap-3">
        <InlineAlert tone="warn" title="Remote desktop is not available yet">
          {errorMessage(link.error)}
        </InlineAlert>
        <div className="flex flex-wrap items-center gap-2">
          {conflict && access.has(P.remoteDesktop) && !device.meshInstalled ? (
            <Button
              variant="outline"
              size="sm"
              disabled={install.isPending}
              onClick={() => {
                install.mutate();
              }}
            >
              {install.isPending ? 'Requesting…' : 'Install remote desktop agent'}
            </Button>
          ) : null}
          <Button variant="outline" size="sm" onClick={() => void link.refetch()}>
            Try again
          </Button>
        </div>
      </div>
    );
  }
  return (
    <div className="grid gap-2">
      <div>
        <Button asChild>
          <a href={link.data.url} target="_blank" rel="noopener noreferrer">
            <ExternalLink aria-hidden="true" />
            Open remote desktop in a new tab
          </a>
        </Button>
      </div>
      <p className="text-muted-foreground max-w-[75ch] text-xs">
        The link opens MeshCentral, signs you in for a short time and goes straight to this computer. Do not share it.
        End the session here when you are done; that also removes the on-screen indicator.
      </p>
    </div>
  );
}

function DesktopPanel({ device }: { device: Device }) {
  return (
    <SessionFrame
      device={device}
      kind="desktop"
      startLabel="Start desktop session"
      intro={
        <>
          <p>
            See and control the screen of <span className="ident">{device.hostname}</span>. The screen is carried by
            MeshCentral, a separate remote desktop server; DranzoRMM handles permission, the on-screen indicator and the
            audit record.
          </p>
          <p>
            Remote desktop agent on this device:{' '}
            <span className="text-foreground font-medium">{device.meshInstalled ? 'installed' : 'not installed'}</span>.
          </p>
        </>
      }
    >
      {(session) =>
        session.phase === 'active' && session.sessionId ? (
          <DesktopLink sessionId={session.sessionId} device={device} />
        ) : null
      }
    </SessionFrame>
  );
}

/** Sessions on this device that are open on the server but not driven by this page (for example after a reload). */
function LeftoverSessions({ device }: { device: Device }) {
  const me = useMe();
  const queryClient = useQueryClient();
  const { sessions } = useRemoteSessions();
  const filter = { deviceId: device.id, pageSize: 25 };
  const recent = useQuery({
    queryKey: remoteKeys.list(filter),
    queryFn: ({ signal }) => remoteApi.list(filter, signal),
    refetchInterval: 15_000,
  });
  const end = useMutation({
    mutationFn: (id: string) => remoteApi.end(id),
    onSuccess: async () => {
      notifySuccess('Session ended');
      await queryClient.invalidateQueries({ queryKey: remoteKeys.all });
    },
    onError: notifyError,
  });
  const tracked = new Set(Object.values(sessions).map((s) => s.sessionId));
  const leftovers = (recent.data?.items ?? []).filter((s) => {
    const state = normalizeSessionState(s.state);
    return state !== null && OPEN_SESSION_STATES.includes(state) && !tracked.has(s.id);
  });
  if (leftovers.length === 0) {
    return null;
  }
  return (
    <InlineAlert tone="warn" live={false} title="A session is still open on this device">
      <ul className="mt-1 space-y-1.5">
        {leftovers.map((s) => (
          <li key={s.id} className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>
              {KIND_LABEL[s.kind] ?? s.kind} session started by {s.userId === me.user.id ? 'you' : s.userName},{' '}
              <RelativeTime value={s.requestedAt} />.{' '}
              {s.userId === me.user.id
                ? 'This page cannot reconnect to it (a reload or a new tab does not resume a session).'
                : 'The on-screen indicator is showing on the computer.'}
            </span>
            <Button
              variant="outline"
              size="xs"
              disabled={end.isPending}
              onClick={() => {
                end.mutate(s.id);
              }}
            >
              End it
            </Button>
          </li>
        ))}
      </ul>
    </InlineAlert>
  );
}

/** Remote support for one device: terminal, file browser and remote desktop, each as an explicit session. */
export function RemoteTab({ device }: DeviceTabProps) {
  const access = useAccess();
  const [params, setParams] = useSearchParams();
  const kinds = KINDS.filter((k) => access.has(k.permission));
  const requested = params.get('view');
  const view = kinds.find((k) => k.kind === requested)?.kind ?? kinds[0]?.kind;

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-4">
      {access.has(P.sessionsRead) ? <LeftoverSessions device={device} /> : null}
      {kinds.length === 0 || view === undefined ? (
        <Panel>
          <p className="text-muted-foreground">
            Your roles let you see the session history but not start remote sessions on this device.
          </p>
        </Panel>
      ) : (
        <Panel>
          <Tabs
            value={view}
            onValueChange={(next) => {
              const copy = new URLSearchParams(params);
              copy.set('view', next);
              setParams(copy, { replace: true });
            }}
          >
            <TabsList className="mb-4">
              {kinds.map(({ kind, icon: Icon }) => (
                <TabsTrigger key={kind} value={kind}>
                  <Icon aria-hidden="true" />
                  {KIND_LABEL[kind]}
                </TabsTrigger>
              ))}
            </TabsList>
            {kinds.map(({ kind }) => (
              <TabsContent key={kind} value={kind}>
                {kind === 'terminal' ? (
                  <TerminalPanel device={device} />
                ) : kind === 'files' ? (
                  <FilesPanel device={device} />
                ) : (
                  <DesktopPanel device={device} />
                )}
              </TabsContent>
            ))}
          </Tabs>
        </Panel>
      )}
      {access.has(P.sessionsRead) ? (
        <p className="text-muted-foreground text-xs">
          Every session is listed with who started it, how the person at the computer answered and why it ended in the{' '}
          <Link to={`/remote?deviceId=${device.id}`} className="text-link underline">
            session history for this device
          </Link>
          .
        </p>
      ) : null}
    </div>
  );
}
