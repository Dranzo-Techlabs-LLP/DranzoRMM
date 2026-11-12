import { useMemo, useRef } from 'react';
import { cn } from '@/lib/utils';

/**
 * A plain `<textarea>` with a line-number gutter. No syntax highlighting and no key remapping: Tab keeps moving
 * focus, so the editor is not a keyboard trap. The gutter is decorative and hidden from assistive technology.
 */
export function CodeEditor({
  value,
  onChange,
  readOnly = false,
  className,
  rows = 22,
  ...control
}: {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  className?: string;
  rows?: number;
  id?: string;
  'aria-describedby'?: string;
  'aria-invalid'?: true;
  'aria-label'?: string;
}) {
  const gutter = useRef<HTMLPreElement>(null);
  const numbers = useMemo(() => {
    let count = 1;
    for (let i = 0; i < value.length; i++) {
      if (value.charCodeAt(i) === 10) {
        count += 1;
      }
    }
    return Array.from({ length: count }, (_, i) => i + 1).join('\n');
  }, [value]);

  return (
    <div
      className={cn(
        'border-input bg-card focus-within:border-ring focus-within:ring-ring/50 dark:bg-input/30 flex overflow-hidden rounded-md border shadow-xs focus-within:ring-[3px]',
        control['aria-invalid'] && 'border-destructive',
        className,
      )}
    >
      <pre
        ref={gutter}
        aria-hidden="true"
        className="bg-muted/60 text-muted-foreground shrink-0 overflow-hidden border-r px-2 py-2 text-right font-mono text-[0.8125rem] leading-5 select-none"
      >
        {numbers}
      </pre>
      <textarea
        {...control}
        value={value}
        readOnly={readOnly}
        rows={rows}
        wrap="off"
        spellCheck={false}
        autoCapitalize="none"
        autoCorrect="off"
        autoComplete="off"
        className="min-w-0 flex-1 resize-y bg-transparent px-3 py-2 font-mono text-[0.8125rem] leading-5 whitespace-pre outline-none"
        onChange={(e) => onChange?.(e.target.value)}
        onScroll={(e) => {
          if (gutter.current) {
            gutter.current.scrollTop = e.currentTarget.scrollTop;
          }
        }}
      />
    </div>
  );
}
