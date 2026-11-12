import { useQueryClient } from '@tanstack/react-query';
import {
  Building2,
  Check,
  ChevronsUpDown,
  LogOut,
  Monitor,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Sun,
  UserRound,
} from 'lucide-react';
import { Link, useNavigate } from 'react-router';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { authApi } from '@/lib/api';
import { clearSession, useMe } from '@/lib/auth/session';
import { useLive } from '@/lib/live/LiveProvider';
import { cn } from '@/lib/utils';
import { useOrgFilter } from '../org-filter';
import { useTheme, type ThemePreference } from '../theme';

const ALL = '__all__';

function OrgSwitcher() {
  const { orgId, organization, organizations, setOrgId, available, isLoading } = useOrgFilter();
  const me = useMe();
  if (!available) {
    return null;
  }
  // Someone who sees exactly one organization (for example a client with the Organization Viewer role) has nothing
  // to switch between: show whose dashboard this is instead.
  const only = !me.partnerWide && organizations.length === 1 ? organizations[0] : undefined;
  if (only) {
    return (
      <p className="flex min-w-0 items-center gap-2 px-1 text-sm font-medium">
        <Building2 aria-hidden="true" className="text-muted-foreground size-4 shrink-0" />
        <span className="truncate">{only.name}</span>
      </p>
    );
  }
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="max-w-64 justify-between gap-2"
          disabled={isLoading}
          aria-label={`Organization filter: ${organization?.name ?? 'All organizations'}`}
        >
          <Building2 aria-hidden="true" className="text-muted-foreground" />
          <span className="truncate">{organization?.name ?? 'All organizations'}</span>
          <ChevronsUpDown aria-hidden="true" className="text-muted-foreground size-3.5" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="max-h-[min(24rem,70dvh)] w-64 overflow-y-auto">
        <DropdownMenuLabel className="text-muted-foreground text-xs font-normal">Show data for</DropdownMenuLabel>
        <DropdownMenuRadioGroup
          value={orgId ?? ALL}
          onValueChange={(v) => {
            setOrgId(v === ALL ? null : v);
          }}
        >
          <DropdownMenuRadioItem value={ALL}>All organizations</DropdownMenuRadioItem>
          {organizations.length > 0 ? <DropdownMenuSeparator /> : null}
          {organizations.map((o) => (
            <DropdownMenuRadioItem key={o.id} value={o.id}>
              <span className="truncate">{o.name}</span>
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function LiveIndicator() {
  const { state, available } = useLive();
  if (!available) {
    return null;
  }
  const live = state === 'live';
  const label = live ? 'Live' : state === 'offline' ? 'Updates paused' : 'Connecting';
  const title = live
    ? 'Device status updates arrive as they happen.'
    : state === 'offline'
      ? 'Live updates are not connected. Lists still refresh every minute.'
      : 'Connecting to live updates…';
  return (
    <span
      role="status"
      title={title}
      className={cn(
        'hidden items-center gap-1.5 px-1 text-xs font-medium sm:inline-flex',
        live ? 'text-ok' : 'text-muted-foreground',
      )}
    >
      <svg viewBox="0 0 10 10" aria-hidden="true" className={cn('size-2', live ? 'text-ok-mark' : 'text-idle-mark')}>
        {live ? (
          <circle cx="5" cy="5" r="4.5" fill="currentColor" />
        ) : (
          <circle cx="5" cy="5" r="3.5" fill="none" stroke="currentColor" strokeWidth="2" />
        )}
      </svg>
      {label}
    </span>
  );
}

const THEMES: { value: ThemePreference; label: string; icon: typeof Sun }[] = [
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'system', label: 'Match system', icon: Monitor },
];

function ThemeToggle() {
  const { preference, resolved, setPreference } = useTheme();
  const Current = resolved === 'dark' ? Moon : Sun;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label={`Theme: ${preference}. Change theme`}>
          <Current aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44">
        {THEMES.map(({ value, label, icon: Icon }) => (
          <DropdownMenuItem
            key={value}
            onSelect={() => {
              setPreference(value);
            }}
          >
            <Icon aria-hidden="true" />
            {label}
            {preference === value ? <Check aria-label="selected" className="ml-auto" /> : null}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  const first = parts[0]?.[0] ?? '?';
  const last = parts.length > 1 ? (parts[parts.length - 1]?.[0] ?? '') : '';
  return (first + last).toUpperCase();
}

function UserMenu() {
  const me = useMe();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const signOut = async () => {
    try {
      await authApi.logout();
    } catch {
      // Even if the call fails (network, already expired) the local state is cleared and the user lands on sign-in.
    }
    clearSession(queryClient, { explicit: true });
    void navigate('/login', { replace: true });
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="gap-2 px-1.5"
          aria-label={`Account menu for ${me.user.displayName}`}
        >
          <span
            aria-hidden="true"
            className="bg-primary text-primary-foreground grid size-6 place-items-center rounded-full text-[11px] font-semibold"
          >
            {initials(me.user.displayName)}
          </span>
          <span className="hidden max-w-40 truncate lg:inline">{me.user.displayName}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-60">
        <DropdownMenuLabel>
          <span className="block truncate">{me.user.displayName}</span>
          <span className="text-muted-foreground block truncate text-xs font-normal">{me.user.email}</span>
          <span className="text-muted-foreground block truncate text-xs font-normal">{me.partner.name}</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem asChild>
          <Link to="/account">
            <UserRound aria-hidden="true" />
            Account
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem
          onSelect={() => {
            void signOut();
          }}
        >
          <LogOut aria-hidden="true" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function TopBar({ collapsed, onToggleSidebar }: { collapsed: boolean; onToggleSidebar: () => void }) {
  return (
    <header className="bg-background/95 sticky top-0 z-30 flex h-12 shrink-0 items-center gap-2 border-b px-3 backdrop-blur">
      <Button
        variant="ghost"
        size="icon-sm"
        onClick={onToggleSidebar}
        aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
        aria-expanded={!collapsed}
      >
        {collapsed ? <PanelLeftOpen aria-hidden="true" /> : <PanelLeftClose aria-hidden="true" />}
      </Button>
      <OrgSwitcher />
      <div className="ml-auto flex items-center gap-1.5">
        <LiveIndicator />
        <ThemeToggle />
        <UserMenu />
      </div>
    </header>
  );
}
