import type { OutputChunk } from '@/lib/api/jobs';

/**
 * Output of one run: chunks stored by the server (from `GET /runs/{id}`) merged with chunks that arrive live
 * (`runOutput` hub events). Chunks are keyed by `seq`; a chunk that is already known is ignored, so it does not
 * matter in which order the two sources deliver or how often a chunk is repeated (reconnects, refetches).
 */
export interface OutputState {
  /** Ascending by `seq`. */
  chunks: OutputChunk[];
  seen: ReadonlySet<number>;
}

export const EMPTY_OUTPUT: OutputState = { chunks: [], seen: new Set<number>() };

/** Adds chunks that are not yet known. Returns the same object when nothing changed (cheap for React state). */
export function mergeOutput(state: OutputState, incoming: readonly OutputChunk[]): OutputState {
  let seen: Set<number> | null = null;
  const added: OutputChunk[] = [];
  for (const chunk of incoming) {
    if (!Number.isInteger(chunk.seq) || typeof chunk.data !== 'string') {
      continue;
    }
    if (state.seen.has(chunk.seq) || seen?.has(chunk.seq)) {
      continue;
    }
    seen ??= new Set(state.seen);
    seen.add(chunk.seq);
    added.push({ seq: chunk.seq, stream: chunk.stream === 'stderr' ? 'stderr' : 'stdout', data: chunk.data });
  }
  if (added.length === 0 || seen === null) {
    return state;
  }
  const last = state.chunks[state.chunks.length - 1];
  added.sort((a, b) => a.seq - b.seq);
  // The common case is live chunks arriving in order: append without re-sorting everything.
  const inOrder = last === undefined || (added[0]?.seq ?? 0) > last.seq;
  const chunks = inOrder ? [...state.chunks, ...added] : [...state.chunks, ...added].sort((a, b) => a.seq - b.seq);
  return { chunks, seen };
}

/**
 * Removes terminal control sequences so output is shown as plain text and nothing in it is interpreted:
 * CSI (colours, cursor movement), OSC (window titles, hyperlinks), other escape sequences, and stray C0/C1 control
 * characters. Tabs and line breaks stay; a lone carriage return (progress bars) becomes a line break.
 */
export function stripAnsi(text: string): string {
  return (
    text
      // OSC ... terminated by BEL or ST
      // eslint-disable-next-line no-control-regex
      .replace(/(?:\u001b\]|\u009d)[\s\S]*?(?:\u0007|\u001b\\|\u009c)/g, '')
      // CSI: ESC [ parameters intermediates final
      // eslint-disable-next-line no-control-regex
      .replace(/(?:\u001b\[|\u009b)[0-?]*[ -/]*[@-~]/g, '')
      // DCS, SOS, PM, APC strings
      // eslint-disable-next-line no-control-regex
      .replace(/\u001b[PX^_][\s\S]*?(?:\u001b\\|\u009c)/g, '')
      // Two-character escapes (charset selection, keypad modes, ...)
      // eslint-disable-next-line no-control-regex
      .replace(/\u001b[ -/]*[0-~]/g, '')
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      // Whatever control characters are left, except tab and line feed
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, '')
  );
}

export interface OutputSegment {
  /** Seq of the first chunk in the segment: a stable React key. */
  seq: number;
  stream: 'stdout' | 'stderr';
  text: string;
}

/** Consecutive chunks of the same stream become one segment, with control sequences removed. */
export function toSegments(chunks: readonly OutputChunk[]): OutputSegment[] {
  // Group first, strip afterwards: an escape sequence split across two chunks is then still removed as a whole.
  const groups: { seq: number; stream: 'stdout' | 'stderr'; raw: string }[] = [];
  for (const chunk of chunks) {
    const stream = chunk.stream === 'stderr' ? 'stderr' : 'stdout';
    const last = groups[groups.length - 1];
    if (last?.stream === stream) {
      last.raw += chunk.data;
    } else {
      groups.push({ seq: chunk.seq, stream, raw: chunk.data });
    }
  }
  return groups.map((g) => ({ seq: g.seq, stream: g.stream, text: stripAnsi(g.raw) })).filter((s) => s.text.length > 0);
}

/** The output as one plain-text document (copy and download). */
export function outputText(chunks: readonly OutputChunk[], truncated = false): string {
  const body = toSegments(chunks)
    .map((s) => s.text)
    .join('');
  if (!truncated) {
    return body;
  }
  return `${body}${body.endsWith('\n') || body === '' ? '' : '\n'}[Output truncated: the run produced more than its output limit.]\n`;
}

export function outputBytes(chunks: readonly OutputChunk[]): number {
  const encoder = new TextEncoder();
  return chunks.reduce((n, c) => n + encoder.encode(c.data).length, 0);
}

/** A safe file name for the downloaded output. */
export function outputFileName(hostname: string, jobName: string, runId: string): string {
  const clean = (s: string) =>
    s
      .replace(/[^A-Za-z0-9._-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 40);
  return `${clean(hostname) || 'device'}_${clean(jobName) || 'run'}_${runId.slice(0, 8)}.txt`;
}
