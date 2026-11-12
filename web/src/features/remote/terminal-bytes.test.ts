import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  binaryStringToBytes,
  bytesToBase64,
  clampTerminalSize,
  textToBytes,
  toInputFrames,
} from './terminal-bytes';

describe('terminal byte encoding', () => {
  it('round-trips arbitrary bytes through base64', () => {
    const bytes = new Uint8Array(256).map((_, i) => i);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
  });

  it('encodes keyboard input as UTF-8, not UTF-16', () => {
    expect([...textToBytes('é')]).toEqual([0xc3, 0xa9]);
    expect(bytesToBase64(textToBytes('ls\r'))).toBe('bHMN');
  });

  it('keeps a multi-byte character split across two output frames intact as bytes', () => {
    const euro = textToBytes('€'); // e2 82 ac
    const first = base64ToBytes(bytesToBase64(euro.subarray(0, 2)));
    const second = base64ToBytes(bytesToBase64(euro.subarray(2)));
    expect(new TextDecoder().decode(new Uint8Array([...first, ...second]))).toBe('€');
  });

  it('treats binary (mouse) events as one byte per code unit', () => {
    expect([...binaryStringToBytes('\x1b[M\xff')]).toEqual([0x1b, 0x5b, 0x4d, 0xff]);
  });

  it('returns no bytes for invalid base64', () => {
    expect(base64ToBytes('not base64!!').length).toBe(0);
  });

  it('splits large pastes into frames below the hub limit', () => {
    const big = new Uint8Array(40_000).fill(65);
    const frames = toInputFrames(big);
    expect(frames).toHaveLength(3);
    expect(frames.every((f) => f.length <= 32 * 1024)).toBe(true);
    expect(frames.reduce((n, f) => n + base64ToBytes(f).length, 0)).toBe(40_000);
    expect(toInputFrames(new Uint8Array(0))).toEqual([]);
  });

  it('clamps the size to what the server accepts', () => {
    expect(clampTerminalSize(2, 1)).toEqual({ cols: 10, rows: 5 });
    expect(clampTerminalSize(1000.7, 80.2)).toEqual({ cols: 500, rows: 80 });
    expect(clampTerminalSize(Number.NaN, Number.POSITIVE_INFINITY)).toEqual({ cols: 120, rows: 30 });
  });
});
