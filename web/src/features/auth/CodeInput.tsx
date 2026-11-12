import type { ComponentProps } from 'react';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import { normalizeTotp } from './login-machine';

/** 6-digit authenticator code field. One input (not six boxes) so paste, autofill and screen readers just work. */
export function CodeInput({
  value,
  onValueChange,
  className,
  ...props
}: Omit<ComponentProps<typeof Input>, 'value' | 'onChange'> & {
  value: string;
  onValueChange: (value: string) => void;
}) {
  return (
    <Input
      {...props}
      value={value}
      onChange={(e) => {
        onValueChange(normalizeTotp(e.target.value));
      }}
      inputMode="numeric"
      autoComplete="one-time-code"
      pattern="[0-9]{6}"
      maxLength={12}
      spellCheck={false}
      placeholder="000000"
      className={cn('ident h-10 w-40 text-center text-lg tracking-[0.3em]', className)}
    />
  );
}
