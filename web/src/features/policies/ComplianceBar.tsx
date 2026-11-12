import { cn } from '@/lib/utils';

/**
 * Compliant / not compliant / not supported as one bar. Not compliant is hatched as well as coloured, and the
 * numbers are always printed next to the bar, so nothing depends on colour alone. The bar itself is decorative.
 */
export function ComplianceBar({
  compliant,
  nonCompliant,
  unsupported,
  className,
}: {
  compliant: number;
  nonCompliant: number;
  unsupported: number;
  className?: string;
}) {
  const total = compliant + nonCompliant + unsupported;
  const pct = (n: number) => (total === 0 ? 0 : (n / total) * 100);
  return (
    <div
      aria-hidden="true"
      className={cn('bg-idle-surface flex h-2.5 w-full overflow-hidden rounded-[3px]', className)}
    >
      <div className="bg-ok-mark h-full" style={{ width: `${pct(compliant)}%` }} />
      <div
        className="bg-danger-mark h-full"
        style={{
          width: `${pct(nonCompliant)}%`,
          backgroundImage:
            'repeating-linear-gradient(135deg, transparent 0 3px, color-mix(in oklab, var(--background) 55%, transparent) 3px 5px)',
        }}
      />
    </div>
  );
}
