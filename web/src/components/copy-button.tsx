import { Check, Copy } from 'lucide-react';
import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';

/** Copies text to the clipboard and confirms in place (and to screen readers). */
export function CopyButton({
  value,
  label = 'Copy',
  size = 'sm',
  variant = 'outline',
}: {
  value: string;
  label?: string;
  size?: 'sm' | 'xs' | 'default';
  variant?: 'outline' | 'ghost' | 'secondary';
}) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');

  useEffect(() => {
    if (state === 'idle') {
      return;
    }
    const t = setTimeout(() => {
      setState('idle');
    }, 2000);
    return () => {
      clearTimeout(t);
    };
  }, [state]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState('copied');
    } catch {
      setState('failed');
    }
  };

  return (
    <Button type="button" variant={variant} size={size} onClick={() => void copy()}>
      {state === 'copied' ? <Check aria-hidden="true" /> : <Copy aria-hidden="true" />}
      <span aria-live="polite">
        {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed, select the text instead' : label}
      </span>
    </Button>
  );
}
