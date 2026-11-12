import { describe, expect, it } from 'vitest';
import type { OutputChunk } from '@/lib/api/jobs';
import { EMPTY_OUTPUT, mergeOutput, outputFileName, outputText, stripAnsi, toSegments } from './output';
import { countRuns, formatRunDuration, runDurationSeconds } from './run-model';

const out = (seq: number, data: string, stream: 'stdout' | 'stderr' = 'stdout'): OutputChunk => ({ seq, stream, data });

describe('run output merge', () => {
  it('merges stored chunks with live events, dropping duplicates by seq', () => {
    const stored = mergeOutput(EMPTY_OUTPUT, [out(0, 'a'), out(1, 'b')]);
    // A live event repeats seq 1 (it was stored before the subscription) and adds seq 2.
    const live = mergeOutput(stored, [out(1, 'b'), out(2, 'c')]);
    expect(live.chunks.map((c) => c.seq)).toEqual([0, 1, 2]);
    expect(outputText(live.chunks)).toBe('abc');
  });

  it('orders chunks by seq whatever order they arrive in', () => {
    let state = mergeOutput(EMPTY_OUTPUT, [out(3, 'd')]);
    state = mergeOutput(state, [out(1, 'b'), out(0, 'a')]);
    state = mergeOutput(state, [out(2, 'c')]);
    expect(outputText(state.chunks)).toBe('abcd');
  });

  it('returns the same state object when nothing is new', () => {
    const state = mergeOutput(EMPTY_OUTPUT, [out(0, 'a')]);
    expect(mergeOutput(state, [out(0, 'a')])).toBe(state);
    expect(mergeOutput(state, [])).toBe(state);
  });

  it('ignores malformed chunks and normalises unknown streams to stdout', () => {
    const state = mergeOutput(EMPTY_OUTPUT, [
      { seq: 1.5, stream: 'stdout', data: 'x' },
      { seq: 2, stream: 'weird', data: 'y' },
      { seq: 3, stream: 'stdout', data: null as unknown as string },
    ]);
    expect(state.chunks).toEqual([{ seq: 2, stream: 'stdout', data: 'y' }]);
  });

  it('keeps stdout and stderr apart as segments', () => {
    const segments = toSegments([out(0, 'one\n'), out(1, 'two\n'), out(2, 'oops\n', 'stderr'), out(3, 'three\n')]);
    expect(segments).toEqual([
      { seq: 0, stream: 'stdout', text: 'one\ntwo\n' },
      { seq: 2, stream: 'stderr', text: 'oops\n' },
      { seq: 3, stream: 'stdout', text: 'three\n' },
    ]);
  });

  it('adds a truncation note to the copied and downloaded text', () => {
    expect(outputText([out(0, 'partial')], true)).toBe(
      'partial\n[Output truncated: the run produced more than its output limit.]\n',
    );
    expect(outputText([out(0, 'done\n')], false)).toBe('done\n');
  });
});

describe('escape sequences in output', () => {
  it('removes colours, cursor movement, titles and hyperlinks instead of interpreting them', () => {
    expect(stripAnsi('\u001b[31mred\u001b[0m plain')).toBe('red plain');
    expect(stripAnsi('\u001b]0;evil title\u0007after')).toBe('after');
    expect(stripAnsi('\u001b]8;;https://x.test\u001b\\link\u001b]8;;\u001b\\')).toBe('link');
    expect(stripAnsi('a\u001b[2J\u001b[Hb')).toBe('ab');
    expect(stripAnsi('bell\u0007 nul\u0000 tab\tok')).toBe('bell nul tab\tok');
    expect(stripAnsi('progress 10%\rprogress 100%\r\n')).toBe('progress 10%\nprogress 100%\n');
  });

  it('keeps markup as literal text', () => {
    expect(stripAnsi('<script>alert(1)</script>')).toBe('<script>alert(1)</script>');
  });

  it('removes a sequence split across two chunks', () => {
    expect(toSegments([out(0, 'x\u001b['), out(1, '32my')])).toEqual([{ seq: 0, stream: 'stdout', text: 'xy' }]);
  });

  it('builds a safe download file name', () => {
    expect(outputFileName('srv/01', '../Clean temp', 'abcdef1234')).toBe('srv-01_..-Clean-temp_abcdef12.txt');
  });
});

describe('run helpers', () => {
  it('counts runs like the server', () => {
    expect(
      countRuns([
        { status: 'succeeded' },
        { status: 'failed' },
        { status: 'timedout' },
        { status: 'rejected' },
        { status: 'running' },
        { status: 'pending' },
        { status: 'cancelled' },
      ]),
    ).toEqual({ total: 7, succeeded: 1, failed: 3, active: 2, other: 1 });
  });

  it('computes durations', () => {
    const now = Date.parse('2026-11-12T10:00:30Z');
    expect(runDurationSeconds({ startedAt: '2026-11-12T10:00:00Z', finishedAt: null, status: 'running' }, now)).toBe(
      30,
    );
    expect(
      runDurationSeconds({ startedAt: '2026-11-12T10:00:00Z', finishedAt: '2026-11-12T10:02:05Z', status: 'failed' }),
    ).toBe(125);
    expect(runDurationSeconds({ startedAt: null, finishedAt: null, status: 'pending' })).toBeNull();
    expect(formatRunDuration(0.42)).toBe('0.4 s');
    expect(formatRunDuration(125)).toBe('2 min 05 s');
    expect(formatRunDuration(7800)).toBe('2 h 10 min');
  });
});
