import { cn } from '@/lib/utils';

/** Product mark: three rack units, the top one lit. */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true" className={cn('size-7 shrink-0', className)}>
      <rect width="32" height="32" rx="7" className="fill-primary" />
      <rect x="7" y="8" width="18" height="4" rx="1.5" className="fill-primary-foreground" />
      <rect x="7" y="14" width="18" height="4" rx="1.5" className="fill-primary-foreground" opacity=".7" />
      <rect x="7" y="20" width="18" height="4" rx="1.5" className="fill-primary-foreground" opacity=".4" />
      <circle cx="22" cy="10" r="1.2" className="fill-ok-mark" />
    </svg>
  );
}

export function Brand({ className }: { className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-2 text-base font-semibold tracking-tight', className)}>
      <BrandMark />
      DranzoRMM
    </span>
  );
}
