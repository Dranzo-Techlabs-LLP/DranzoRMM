/**
 * Byte handling for the terminal. The hub carries terminal data as base64 in both directions; the terminal emulator
 * is fed raw bytes (never decoded strings), so multi-byte characters split across frames still render correctly.
 */

/** The hub rejects `TerminalInput` frames above 32 KiB of base64; 16 KiB of bytes is about 21.9 KiB of base64. */
export const MAX_INPUT_CHUNK_BYTES = 16 * 1024;

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  // Chunked so a large paste does not exceed the argument limit of String.fromCharCode.
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

/** Decodes base64 to bytes. Returns an empty array for input that is not valid base64. */
export function base64ToBytes(data: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(data);
  } catch {
    return new Uint8Array(0);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

const encoder = new TextEncoder();

/** Keyboard and paste input from the terminal emulator (a JavaScript string) as UTF-8 bytes. */
export function textToBytes(text: string): Uint8Array {
  return encoder.encode(text);
}

/**
 * The emulator's "binary" events (mouse reports) deliver one byte per UTF-16 code unit. They must not go through
 * UTF-8 encoding, which would turn bytes above 0x7F into two bytes.
 */
export function binaryStringToBytes(binary: string): Uint8Array {
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i) & 0xff;
  }
  return bytes;
}

/** Splits input into frames the hub accepts, each already base64-encoded. Empty input yields no frames. */
export function toInputFrames(bytes: Uint8Array, chunkBytes: number = MAX_INPUT_CHUNK_BYTES): string[] {
  const frames: string[] = [];
  for (let i = 0; i < bytes.length; i += chunkBytes) {
    frames.push(bytesToBase64(bytes.subarray(i, i + chunkBytes)));
  }
  return frames;
}

/** Terminal sizes the server accepts (`TerminalResize` clamps to the same range). */
export function clampTerminalSize(cols: number, rows: number): { cols: number; rows: number } {
  const clamp = (v: number, min: number, max: number, fallback: number) =>
    Number.isFinite(v) ? Math.min(max, Math.max(min, Math.floor(v))) : fallback;
  return { cols: clamp(cols, 10, 500, 120), rows: clamp(rows, 5, 300, 30) };
}
