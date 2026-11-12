import { Suspense, useEffect, useState } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router';
import { LoadingRows } from '@/components/page';
import { StepUpProvider } from '@/features/auth/StepUpProvider';
import { useMe } from '@/lib/auth/session';
import { LiveProvider } from '@/lib/live/LiveProvider';
import { readPref, writePref } from '@/lib/prefs';
import { OrgFilterProvider } from '../org-filter';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';

const NARROW = '(max-width: 1023px)';

function isNarrow(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia(NARROW).matches;
}

/** Collapsed by the user's choice if they made one; otherwise collapsed on tablet-width screens. */
function useSidebarCollapsed(): [boolean, () => void] {
  const [choice, setChoice] = useState<boolean | null>(() => {
    const saved = readPref('sidebar');
    return saved === 'collapsed' ? true : saved === 'expanded' ? false : null;
  });
  const [narrow, setNarrow] = useState(isNarrow);

  useEffect(() => {
    if (typeof window.matchMedia !== 'function') {
      return;
    }
    const media = window.matchMedia(NARROW);
    const onChange = (e: MediaQueryListEvent) => {
      setNarrow(e.matches);
    };
    media.addEventListener('change', onChange);
    return () => {
      media.removeEventListener('change', onChange);
    };
  }, []);

  // On tablet-width screens the icon rail is the default; expanding there is temporary and not saved.
  const desktopCollapsed = choice ?? false;
  const [narrowExpanded, setNarrowExpanded] = useState(false);
  const effective = narrow ? !narrowExpanded : desktopCollapsed;

  const toggle = () => {
    if (narrow) {
      setNarrowExpanded((v) => !v);
    } else {
      const next = !desktopCollapsed;
      setChoice(next);
      writePref('sidebar', next ? 'collapsed' : 'expanded');
    }
  };
  return [effective, toggle];
}

export function AppShell() {
  const me = useMe();
  const location = useLocation();
  const [collapsed, toggle] = useSidebarCollapsed();

  // A temporary password must be replaced before anything else.
  if (me.user.mustChangePassword && location.pathname !== '/account') {
    return <Navigate to="/account" replace />;
  }

  return (
    <StepUpProvider>
      <OrgFilterProvider>
        <LiveProvider>
          <a
            href="#main"
            className="bg-primary text-primary-foreground sr-only z-50 rounded-md px-3 py-2 focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
          >
            Skip to content
          </a>
          <div className="flex min-h-dvh">
            <Sidebar collapsed={collapsed} />
            <div className="flex min-w-0 flex-1 flex-col">
              <TopBar collapsed={collapsed} onToggleSidebar={toggle} />
              <main
                id="main"
                tabIndex={-1}
                className="mx-auto w-full max-w-[1480px] flex-1 px-4 py-5 outline-none lg:px-6"
              >
                <Suspense fallback={<LoadingRows label="page" rows={8} />}>
                  <Outlet />
                </Suspense>
              </main>
            </div>
          </div>
        </LiveProvider>
      </OrgFilterProvider>
    </StepUpProvider>
  );
}
