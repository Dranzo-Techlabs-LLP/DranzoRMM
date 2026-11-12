import { useOpenAlertCount } from './use-open-alerts';

/** Open-alert count beside "Alerts" in the navigation. A number, not a colour, carries the meaning. */
export function OpenAlertsBadge({ collapsed }: { collapsed: boolean }) {
  const count = useOpenAlertCount();
  if (!count) {
    return null;
  }
  const text = count > 99 ? '99+' : String(count);
  return (
    <span
      className={
        collapsed
          ? 'bg-danger-mark absolute top-0.5 right-0.5 min-w-4 rounded-full px-1 text-center text-[10px] leading-4 font-semibold text-white'
          : 'bg-danger-surface text-danger ml-auto rounded-sm px-1.5 text-xs leading-5 font-semibold tabular-nums'
      }
    >
      {text}
      <span className="sr-only"> open {count === 1 ? 'alert' : 'alerts'}</span>
    </span>
  );
}
