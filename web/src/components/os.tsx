import { Apple, Grid2x2, HelpCircle, Terminal, type LucideIcon } from 'lucide-react';
import { osLabel } from '@/lib/os';
import { cn } from '@/lib/utils';

const ICONS: Record<string, LucideIcon> = { windows: Grid2x2, macos: Apple, linux: Terminal };

/** OS family glyph. Decorative by default because callers print the OS name next to it. */
export function OsIcon({ os, className, labelled = false }: { os: string; className?: string; labelled?: boolean }) {
  const Icon = ICONS[os] ?? HelpCircle;
  return labelled ? (
    <Icon role="img" aria-label={osLabel(os)} className={cn('size-4 shrink-0', className)} />
  ) : (
    <Icon aria-hidden="true" className={cn('size-4 shrink-0', className)} />
  );
}
