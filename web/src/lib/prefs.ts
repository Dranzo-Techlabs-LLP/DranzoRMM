/**
 * Non-secret UI preferences (theme, sidebar state, selected organization) kept in localStorage.
 * Nothing sensitive may ever be stored here: the session lives in an HttpOnly cookie and the CSRF token in memory.
 */
const PREFIX = 'dranzo.';

export type PrefKey = 'theme' | 'sidebar' | 'org';

export function readPref(key: PrefKey): string | null {
  try {
    return window.localStorage.getItem(PREFIX + key);
  } catch {
    return null;
  }
}

export function writePref(key: PrefKey, value: string | null): void {
  try {
    if (value === null) {
      window.localStorage.removeItem(PREFIX + key);
    } else {
      window.localStorage.setItem(PREFIX + key, value);
    }
  } catch {
    // Storage blocked or full: the preference just does not persist.
  }
}
