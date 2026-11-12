import { NavLink } from 'react-router';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { BrandMark } from '@/features/auth/Brand';
import { useAccess } from '@/lib/auth/session';
import { cn } from '@/lib/utils';
import { visibleNav, type PageDef } from '../pages';

function NavItem({ page, collapsed }: { page: PageDef; collapsed: boolean }) {
  const Icon = page.icon;
  const Badge = page.badge;
  const link = (
    <NavLink
      to={`/${page.path}`}
      end={page.path === ''}
      aria-label={collapsed ? page.label : undefined}
      // Active styling keys off aria-current (set by NavLink) rather than a className function: the collapsed rail
      // wraps this link in a Radix Slot (tooltip trigger), which can only merge string class names.
      className={cn(
        'text-sidebar-foreground flex h-8 items-center gap-2.5 rounded-md px-2 font-medium',
        'hover:bg-sidebar-active/70 hover:text-foreground',
        'aria-[current=page]:bg-sidebar-active aria-[current=page]:text-foreground aria-[current=page]:shadow-xs',
        'aria-[current=page]:ring-sidebar-border aria-[current=page]:ring-1',
        collapsed && 'relative justify-center px-0',
      )}
    >
      <Icon aria-hidden="true" className="size-4 shrink-0" strokeWidth={1.75} />
      {collapsed ? null : <span className="truncate">{page.label}</span>}
      {Badge ? <Badge collapsed={collapsed} /> : null}
    </NavLink>
  );
  if (!collapsed) {
    return link;
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>{link}</TooltipTrigger>
      <TooltipContent side="right" sideOffset={6}>
        {page.label}
      </TooltipContent>
    </Tooltip>
  );
}

export function Sidebar({ collapsed }: { collapsed: boolean }) {
  const access = useAccess();
  const areas = visibleNav(access);
  return (
    <aside
      className={cn(
        'bg-sidebar border-sidebar-border sticky top-0 flex h-dvh shrink-0 flex-col border-r',
        'transition-[width] duration-150',
        collapsed ? 'w-13' : 'w-56',
      )}
    >
      <div className={cn('flex h-12 shrink-0 items-center gap-2 px-3', collapsed && 'justify-center px-0')}>
        <BrandMark className="size-6" />
        {collapsed ? null : <span className="text-[15px] font-semibold tracking-tight">DranzoRMM</span>}
      </div>
      <nav aria-label="Main" className="flex-1 overflow-y-auto px-2 pb-4">
        {areas.map((area, i) => (
          <div key={area.id} role="group" aria-label={area.label} className={i === 0 ? 'mt-1' : 'mt-4'}>
            {collapsed ? (
              i > 0 ? (
                <div aria-hidden="true" className="border-sidebar-border mx-2 mb-2 border-t" />
              ) : null
            ) : (
              <p aria-hidden="true" className="text-muted-foreground mb-1 px-2 text-xs">
                {area.label}
              </p>
            )}
            <ul className="space-y-0.5">
              {area.pages.map((page) => (
                <li key={page.id}>
                  <NavItem page={page} collapsed={collapsed} />
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
    </aside>
  );
}
