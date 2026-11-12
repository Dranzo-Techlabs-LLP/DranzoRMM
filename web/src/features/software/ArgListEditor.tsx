import { Plus, X } from 'lucide-react';
import { useId } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { MAX_ARG_LENGTH, MAX_ARGS } from './software-model';

/**
 * Edits an argument list (argv) one item per row. Items are passed to the program as separate arguments exactly as
 * typed, so no quoting or escaping is needed, and none is interpreted.
 */
export function ArgListEditor({
  legend,
  hint,
  value,
  onChange,
  itemLabel = 'Argument',
  firstItemLabel,
  placeholder,
  error,
}: {
  legend: string;
  hint?: string;
  value: string[];
  onChange: (next: string[]) => void;
  itemLabel?: string;
  /** Label of the first row when it means something else (the program of a command). */
  firstItemLabel?: string;
  placeholder?: string;
  error?: string | null;
}) {
  const id = useId();
  return (
    <fieldset className="grid gap-2" aria-describedby={hint ? `${id}-hint` : undefined}>
      <legend className="mb-1.5 text-sm font-medium">{legend}</legend>
      {value.length === 0 ? <p className="text-muted-foreground text-sm">None.</p> : null}
      <ol className="grid gap-1.5">
        {value.map((item, index) => {
          const label =
            index === 0 && firstItemLabel ? firstItemLabel : `${itemLabel} ${firstItemLabel ? index : index + 1}`;
          return (
            // Rows have no identity besides their position.
            <li key={index} className="flex items-center gap-2">
              <span aria-hidden="true" className="text-muted-foreground w-5 text-right text-xs">
                {index + 1}
              </span>
              <Input
                aria-label={label}
                className="ident h-8"
                value={item}
                maxLength={MAX_ARG_LENGTH}
                spellCheck={false}
                autoCapitalize="none"
                autoComplete="off"
                placeholder={index === 0 ? placeholder : undefined}
                onChange={(e) => {
                  onChange(value.map((v, i) => (i === index ? e.target.value : v)));
                }}
              />
              <Button
                type="button"
                variant="ghost"
                size="icon-sm"
                aria-label={`Remove ${label.toLowerCase()}`}
                onClick={() => {
                  onChange(value.filter((_, i) => i !== index));
                }}
              >
                <X aria-hidden="true" />
              </Button>
            </li>
          );
        })}
      </ol>
      <div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={value.length >= MAX_ARGS}
          onClick={() => {
            onChange([...value, '']);
          }}
        >
          <Plus aria-hidden="true" />
          Add {value.length === 0 && firstItemLabel ? firstItemLabel.toLowerCase() : itemLabel.toLowerCase()}
        </Button>
      </div>
      {hint ? (
        <p id={`${id}-hint`} className="text-muted-foreground text-xs">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-danger text-xs font-medium">
          {error}
        </p>
      ) : null}
    </fieldset>
  );
}
