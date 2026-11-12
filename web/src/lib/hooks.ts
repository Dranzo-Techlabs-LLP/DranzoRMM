import { useEffect, useMemo, useRef, useState } from 'react';

/** Returns `value` after it has been stable for `delayMs` (search boxes). */
export function useDebounced<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => {
      setDebounced(value);
    }, delayMs);
    return () => {
      clearTimeout(t);
    };
  }, [value, delayMs]);
  return debounced;
}

/** Sets the browser tab title while a page is mounted. */
export function useDocumentTitle(title: string): void {
  useEffect(() => {
    const previous = document.title;
    document.title = title ? `${title} | DranzoRMM` : 'DranzoRMM';
    return () => {
      document.title = previous;
    };
  }, [title]);
}

/**
 * Focus return for dialogs opened from a row menu. The menu item that opened the dialog is gone by the time the
 * dialog closes, so focus would fall back to the page. Call `from(id)` with the id of the menu's button when the item
 * is chosen, and pass `onCloseAutoFocus` to the dialog content: focus then lands on that button again.
 */
export function useReturnFocus(): { from: (elementId: string) => void; onCloseAutoFocus: (event: Event) => void } {
  const target = useRef<string | null>(null);
  return useMemo(
    () => ({
      from: (elementId: string) => {
        target.current = elementId;
      },
      onCloseAutoFocus: (event: Event) => {
        const element = target.current ? document.getElementById(target.current) : null;
        target.current = null;
        if (element) {
          event.preventDefault();
          element.focus();
        }
      },
    }),
    [],
  );
}
