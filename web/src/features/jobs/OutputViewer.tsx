import { ArrowDownToLine, Download, Pause, TriangleAlert } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';
import { CopyButton } from '@/components/copy-button';
import { Button } from '@/components/ui/button';
import type { OutputChunk } from '@/lib/api/jobs';
import { formatBytes } from '@/lib/format';
import { cn } from '@/lib/utils';
import { outputText, toSegments } from './output';

/** Distance from the bottom (px) within which the view still counts as "following". */
const FOLLOW_SLACK = 24;

/**
 * Terminal-like view of a run's output. Everything is rendered as text nodes inside a `<pre>`: escape sequences are
 * removed, nothing is interpreted as markup. stderr is marked with a bar and a label, not only with colour.
 *
 * Follows new output while the view is at the bottom; scrolling up pauses it. Only the short status line is a live
 * region, so screen readers hear "Receiving output" / "Finished" rather than every line.
 */
export function OutputViewer({
  chunks,
  active,
  truncated,
  maxOutputBytes,
  fileName,
  statusText,
  className,
}: {
  chunks: readonly OutputChunk[];
  /** The run can still produce output. */
  active: boolean;
  truncated: boolean;
  maxOutputBytes?: number;
  fileName: string;
  /** Short status for the live region, for example "Receiving output live". */
  statusText: string;
  className?: string;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  const [follow, setFollow] = useState(true);
  const segments = useMemo(() => toSegments(chunks), [chunks]);
  const text = useMemo(() => outputText(chunks, truncated), [chunks, truncated]);
  const hasStderr = segments.some((s) => s.stream === 'stderr');
  const lineCount = useMemo(() => {
    const body = segments.map((seg) => seg.text).join('');
    return body === '' ? 0 : body.replace(/\n$/, '').split('\n').length;
  }, [segments]);

  useEffect(() => {
    const el = scroller.current;
    if (follow && el) {
      el.scrollTop = el.scrollHeight;
    }
  }, [segments, follow, truncated]);

  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.append(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <section aria-label="Output" className={cn('bg-card overflow-hidden rounded-lg border', className)}>
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b px-4 py-2">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">Output</h2>
          <p className="text-muted-foreground text-xs" role="status" aria-live="polite">
            {statusText}
            {lineCount > 0 ? ` · ${lineCount.toLocaleString('en')} ${lineCount === 1 ? 'line' : 'lines'}` : ''}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {hasStderr ? (
            <p className="text-muted-foreground mr-1 flex items-center gap-1.5 text-xs">
              <span aria-hidden="true" className="bg-danger-mark inline-block h-3 w-1 rounded-sm" />
              Lines marked like this are error output (stderr)
            </p>
          ) : null}
          {active || !follow ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              aria-pressed={follow}
              onClick={() => {
                setFollow(!follow);
              }}
            >
              {follow ? <Pause aria-hidden="true" /> : <ArrowDownToLine aria-hidden="true" />}
              {follow ? 'Pause scrolling' : 'Follow output'}
            </Button>
          ) : null}
          <CopyButton value={text} label="Copy" />
          <Button type="button" variant="outline" size="sm" disabled={text === ''} onClick={download}>
            <Download aria-hidden="true" />
            Download .txt
          </Button>
        </div>
      </div>
      {truncated ? (
        <p
          role="alert"
          className="bg-warn-surface text-warn flex items-start gap-2 border-b px-4 py-2 text-sm font-medium"
        >
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
          <span>
            Output truncated. The run produced more than its limit
            {maxOutputBytes ? ` of ${formatBytes(maxOutputBytes)}` : ''}; what you see is the beginning. Raise the
            output limit when you run it again to capture more.
          </span>
        </p>
      ) : null}
      <div
        ref={scroller}
        // Scrollable regions must be reachable by keyboard.
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        tabIndex={0}
        role="region"
        aria-label="Output text"
        className="bg-background text-foreground h-[min(60dvh,34rem)] overflow-auto focus-visible:outline-offset-[-2px]"
        onScroll={(e) => {
          const el = e.currentTarget;
          const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight <= FOLLOW_SLACK;
          if (atBottom !== follow && (active || atBottom)) {
            setFollow(atBottom);
          }
        }}
      >
        {segments.length === 0 ? (
          <p className="text-muted-foreground px-4 py-3 text-sm">
            {active ? 'No output yet.' : 'The run produced no output.'}
          </p>
        ) : (
          <pre className="min-w-full py-2 font-mono text-[0.8125rem] leading-5 whitespace-pre-wrap">
            {segments.map((s) => (
              <span
                key={s.seq}
                data-stream={s.stream}
                className={cn(
                  'block border-l-4 px-3 break-words',
                  s.stream === 'stderr' ? 'border-danger-mark text-danger' : 'border-transparent',
                )}
              >
                {s.stream === 'stderr' ? <span className="sr-only">Error output: </span> : null}
                {s.text}
              </span>
            ))}
          </pre>
        )}
      </div>
    </section>
  );
}
