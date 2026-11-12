import { ChevronRight, RefreshCw, type LucideIcon } from 'lucide-react';
import { Fragment, type ReactNode } from 'react';
import { Link } from 'react-router';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { errorMessage, isApiError } from '@/lib/api';
import { cn } from '@/lib/utils';

export interface Crumb {
  label: string;
  to?: string;
}

export function PageHeader({
  title,
  description,
  actions,
  crumbs,
  meta,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  crumbs?: Crumb[];
  meta?: ReactNode;
}) {
  return (
    <header className="mb-5">
      {crumbs && crumbs.length > 0 ? (
        <nav aria-label="Breadcrumb" className="mb-1.5">
          <ol className="text-muted-foreground flex flex-wrap items-center gap-1 text-xs">
            {crumbs.map((c, i) => (
              <Fragment key={`${c.label}-${i}`}>
                {i > 0 ? <ChevronRight aria-hidden="true" className="size-3" /> : null}
                <li>
                  {c.to ? (
                    <Link to={c.to} className="hover:text-foreground hover:underline">
                      {c.label}
                    </Link>
                  ) : (
                    <span aria-current="page">{c.label}</span>
                  )}
                </li>
              </Fragment>
            ))}
          </ol>
        </nav>
      ) : null}
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <h1 className="text-xl leading-7 font-semibold tracking-tight">{title}</h1>
          {description ? <p className="text-muted-foreground mt-0.5 max-w-[72ch]">{description}</p> : null}
          {meta ? <div className="mt-2">{meta}</div> : null}
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
    </header>
  );
}

/** A bordered surface for tables and grouped content. */
export function Panel({
  title,
  description,
  actions,
  children,
  className,
  flush = false,
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  /** Content runs edge to edge (tables). */
  flush?: boolean;
}) {
  return (
    <section className={cn('bg-card rounded-lg border', className)}>
      {title || actions ? (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-2.5">
          <div className="min-w-0">
            {title ? <h2 className="text-sm font-semibold">{title}</h2> : null}
            {description ? <p className="text-muted-foreground text-xs">{description}</p> : null}
          </div>
          {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      <div className={flush ? undefined : 'p-4'}>{children}</div>
    </section>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  children,
  action,
}: {
  icon?: LucideIcon;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center px-6 py-10 text-center">
      {Icon ? <Icon aria-hidden="true" className="text-muted-foreground mb-3 size-6" strokeWidth={1.5} /> : null}
      <p className="font-medium">{title}</p>
      {children ? <div className="text-muted-foreground mt-1 max-w-[52ch]">{children}</div> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function ErrorState({ error, onRetry, what }: { error: unknown; onRetry?: () => void; what: string }) {
  const forbidden = isApiError(error) && error.status === 403;
  return (
    <div role="alert" className="flex flex-col items-center px-6 py-10 text-center">
      <p className="font-medium">{forbidden ? `You do not have access to ${what}.` : `Could not load ${what}.`}</p>
      <p className="text-muted-foreground mt-1 max-w-[52ch]">{errorMessage(error)}</p>
      {onRetry && !forbidden ? (
        <Button variant="outline" size="sm" className="mt-4" onClick={onRetry}>
          <RefreshCw aria-hidden="true" />
          Try again
        </Button>
      ) : null}
    </div>
  );
}

export function LoadingRows({ rows = 6, label }: { rows?: number; label: string }) {
  return (
    <div role="status" aria-label={`Loading ${label}`} className="space-y-2 p-4">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-7 w-full" />
      ))}
    </div>
  );
}

interface QueryLike<T> {
  data: T | undefined;
  error: unknown;
  isPending: boolean;
  isError: boolean;
  refetch: () => unknown;
}

/** Loading, error and empty handling for one query; renders `children` only with usable data. */
export function QueryView<T>({
  query,
  what,
  isEmpty,
  empty,
  children,
  rows,
}: {
  query: QueryLike<T>;
  /** Plural noun for messages: "devices", "organizations". */
  what: string;
  isEmpty?: (data: T) => boolean;
  empty?: ReactNode;
  children: (data: T) => ReactNode;
  rows?: number;
}) {
  if (query.isPending) {
    return <LoadingRows label={what} rows={rows} />;
  }
  if (query.isError || query.data === undefined) {
    return <ErrorState error={query.error} what={what} onRetry={() => void query.refetch()} />;
  }
  if (isEmpty?.(query.data) && empty) {
    return <>{empty}</>;
  }
  return <>{children(query.data)}</>;
}
