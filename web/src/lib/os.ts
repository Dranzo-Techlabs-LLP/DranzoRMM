const LABELS: Record<string, string> = { windows: 'Windows', macos: 'macOS', linux: 'Linux' };

/** Display name of an OS family as reported by the agent (`windows`, `macos`, `linux`). */
export function osLabel(os: string): string {
  return LABELS[os] ?? (os || 'Unknown');
}
