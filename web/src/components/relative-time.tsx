import { useEffect, useState } from 'react';
import { formatDateTime, formatRelative } from '@/lib/format';

/** "5 minutes ago" that keeps itself current, with the exact time as a tooltip and machine-readable value. */
export function RelativeTime({ value, fallback = 'never' }: { value: string | null | undefined; fallback?: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => {
      setNow(Date.now());
    }, 30_000);
    return () => {
      clearInterval(t);
    };
  }, []);
  if (!value) {
    return <span className="text-muted-foreground">{fallback}</span>;
  }
  return (
    <time dateTime={value} title={formatDateTime(value, true)}>
      {formatRelative(value, now)}
    </time>
  );
}
