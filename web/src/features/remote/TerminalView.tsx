import { FitAddon } from '@xterm/addon-fit';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { useEffect, useRef } from 'react';
import type { TerminalChannel } from './RemoteSessions';
import { binaryStringToBytes, textToBytes } from './terminal-bytes';

interface Emulator {
  term: Terminal;
  fit: FitAddon;
  /** The element the emulator draws into. It is moved between containers when the view remounts. */
  host: HTMLDivElement;
}

/** One emulator per session channel, kept while the view is unmounted so the screen contents survive tab switches. */
const emulators = new WeakMap<TerminalChannel, Emulator>();

function createEmulator(channel: TerminalChannel, container: HTMLElement, onLeave: () => void): Emulator {
  const host = document.createElement('div');
  host.className = 'h-full w-full';
  container.appendChild(host);
  const term = new Terminal({
    cursorBlink: true,
    convertEol: false,
    scrollback: 5000,
    fontFamily: "'Atkinson Hyperlegible Mono Variable', ui-monospace, 'SF Mono', Menlo, monospace",
    fontSize: 13,
    // Announces output to screen readers and exposes the buffer as text.
    screenReaderMode: true,
    // A terminal is conventionally dark in both themes; the colours meet contrast on this background.
    theme: { background: '#0f151b', foreground: '#e4e9ee', cursor: '#e4e9ee', selectionBackground: '#3a4a5c' },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(host);

  // Selecting text never copies by itself. Ctrl+Shift+C copies the selection (Ctrl+C stays the interrupt key);
  // Ctrl+Shift+E leaves the terminal, because Tab belongs to the remote shell.
  term.attachCustomKeyEventHandler((e) => {
    if (e.type !== 'keydown' || !e.ctrlKey || !e.shiftKey) {
      return true;
    }
    if (e.code === 'KeyC') {
      const selection = term.getSelection();
      if (selection) {
        void navigator.clipboard.writeText(selection).catch(() => undefined);
      }
      e.preventDefault();
      return false;
    }
    if (e.code === 'KeyE') {
      e.preventDefault();
      onLeave();
      return false;
    }
    return true;
  });
  term.onData((text) => {
    channel.input(textToBytes(text));
  });
  term.onBinary((binary) => {
    channel.input(binaryStringToBytes(binary));
  });
  term.onResize(({ cols, rows }) => {
    channel.resize(cols, rows);
  });

  for (const chunk of channel.pending) {
    term.write(chunk);
  }
  channel.pending = [];
  channel.sink = (bytes) => {
    term.write(bytes);
  };
  channel.dispose = () => {
    channel.sink = null;
    channel.dispose = null;
    emulators.delete(channel);
    term.dispose();
    host.remove();
  };
  return { term, fit, host };
}

/**
 * xterm.js bound to a session channel. Bytes go in and out untouched; this component only mounts the emulator,
 * keeps it sized to its container and tells it whether typing is allowed.
 */
export default function TerminalView({
  channel,
  active,
  onLeave,
}: {
  channel: TerminalChannel;
  /** Input is accepted only while the session is active. */
  active: boolean;
  /** Called for Ctrl+Shift+E: move keyboard focus out of the terminal. */
  onLeave: () => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const leaveRef = useRef(onLeave);
  useEffect(() => {
    leaveRef.current = onLeave;
  });

  useEffect(() => {
    const container = containerRef.current;
    if (!container) {
      return;
    }
    let emulator = emulators.get(channel);
    if (emulator) {
      container.appendChild(emulator.host);
    } else {
      emulator = createEmulator(channel, container, () => {
        leaveRef.current();
      });
      emulators.set(channel, emulator);
    }
    const { fit, host } = emulator;
    let frame = 0;
    const refit = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        if (container.clientWidth > 0 && container.clientHeight > 0) {
          try {
            fit.fit();
          } catch {
            // The emulator was disposed between the resize and this frame.
          }
        }
      });
    };
    const observer = new ResizeObserver(refit);
    observer.observe(container);
    refit();
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
      // Keep the emulator (and its contents) for the next mount; only take it off the page.
      host.remove();
    };
  }, [channel]);

  useEffect(() => {
    const emulator = emulators.get(channel);
    if (!emulator) {
      return;
    }
    emulator.term.options.disableStdin = !active;
    emulator.term.options.cursorBlink = active;
    if (active) {
      emulator.term.focus();
    }
  }, [channel, active]);

  return (
    <div
      ref={containerRef}
      role="group"
      aria-label="Remote terminal"
      className="h-[min(60dvh,34rem)] min-h-64 w-full overflow-hidden rounded-md bg-[#0f151b] p-2"
    />
  );
}
