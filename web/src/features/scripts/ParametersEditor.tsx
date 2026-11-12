import { Plus, Trash2 } from 'lucide-react';
import { useId } from 'react';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import {
  MAX_PARAMETER_DEFAULT,
  MAX_PARAMETERS,
  newParameterDraft,
  PARAMETER_TYPES,
  type ParameterDraft,
  type ParameterDraftErrors,
} from './script-model';

/** Typed parameters of a script: name, type, required, default. They reach the script as environment variables. */
export function ParametersEditor({
  value,
  onChange,
  errors,
  showErrors,
}: {
  value: ParameterDraft[];
  onChange: (next: ParameterDraft[]) => void;
  errors: Record<string, ParameterDraftErrors>;
  showErrors: boolean;
}) {
  const baseId = useId();
  const patch = (key: string, change: Partial<ParameterDraft>) => {
    onChange(value.map((p) => (p.key === key ? { ...p, ...change } : p)));
  };

  return (
    <div className="grid gap-3">
      {value.length === 0 ? (
        <p className="text-muted-foreground">No parameters. Add one to ask for a value each time the script is run.</p>
      ) : (
        <ul className="grid gap-3">
          {value.map((p, index) => {
            const e = showErrors ? errors[p.key] : undefined;
            const id = `${baseId}-${p.key}`;
            return (
              <li key={p.key} className="rounded-md border p-3">
                <fieldset className="grid gap-x-3 gap-y-2 sm:grid-cols-[minmax(0,1.2fr)_9.5rem_minmax(0,1fr)_auto_auto] sm:items-start">
                  <legend className="sr-only">Parameter {index + 1}</legend>
                  <div className="grid gap-1">
                    <label htmlFor={`${id}-name`} className="text-xs font-medium">
                      Name
                      <span className="sr-only"> of parameter {index + 1}</span>
                    </label>
                    <Input
                      id={`${id}-name`}
                      className="ident h-8"
                      value={p.name}
                      maxLength={64}
                      spellCheck={false}
                      autoCapitalize="none"
                      autoComplete="off"
                      placeholder="RETENTION_DAYS"
                      aria-invalid={e?.name ? true : undefined}
                      aria-describedby={e?.name ? `${id}-name-error` : undefined}
                      onChange={(ev) => {
                        patch(p.key, { name: ev.target.value });
                      }}
                    />
                    {e?.name ? (
                      <p id={`${id}-name-error`} role="alert" className="text-danger text-xs font-medium">
                        {e.name}
                      </p>
                    ) : null}
                  </div>
                  <div className="grid gap-1">
                    <label htmlFor={`${id}-type`} className="text-xs font-medium">
                      Type
                      <span className="sr-only"> of parameter {index + 1}</span>
                    </label>
                    <NativeSelect
                      id={`${id}-type`}
                      size="sm"
                      className="w-full"
                      value={p.type}
                      onChange={(ev) => {
                        const type = PARAMETER_TYPES.find((t) => t.id === ev.target.value)?.id ?? 'string';
                        patch(p.key, { type, default: type === p.type ? p.default : '' });
                      }}
                    >
                      {PARAMETER_TYPES.map((t) => (
                        <NativeSelectOption key={t.id} value={t.id}>
                          {t.label}
                        </NativeSelectOption>
                      ))}
                    </NativeSelect>
                  </div>
                  <div className="grid gap-1">
                    <label htmlFor={`${id}-default`} className="text-xs font-medium">
                      Default (optional)
                      <span className="sr-only"> of parameter {index + 1}</span>
                    </label>
                    {p.type === 'bool' ? (
                      <NativeSelect
                        id={`${id}-default`}
                        size="sm"
                        className="w-full"
                        value={p.default}
                        onChange={(ev) => {
                          patch(p.key, { default: ev.target.value });
                        }}
                      >
                        <NativeSelectOption value="">No default</NativeSelectOption>
                        <NativeSelectOption value="true">Yes (true)</NativeSelectOption>
                        <NativeSelectOption value="false">No (false)</NativeSelectOption>
                      </NativeSelect>
                    ) : (
                      <Input
                        id={`${id}-default`}
                        className="h-8"
                        value={p.default}
                        maxLength={MAX_PARAMETER_DEFAULT}
                        inputMode={p.type === 'int' ? 'numeric' : undefined}
                        autoComplete="off"
                        spellCheck={false}
                        aria-invalid={e?.default ? true : undefined}
                        aria-describedby={e?.default ? `${id}-default-error` : undefined}
                        onChange={(ev) => {
                          patch(p.key, { default: ev.target.value });
                        }}
                      />
                    )}
                    {e?.default ? (
                      <p id={`${id}-default-error`} role="alert" className="text-danger text-xs font-medium">
                        {e.default}
                      </p>
                    ) : null}
                  </div>
                  <div className="flex h-8 items-center gap-2 sm:mt-5">
                    <Checkbox
                      id={`${id}-required`}
                      checked={p.required}
                      onCheckedChange={(checked) => {
                        patch(p.key, { required: checked === true });
                      }}
                    />
                    <label htmlFor={`${id}-required`} className="text-sm">
                      Required
                    </label>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="justify-self-start sm:mt-5"
                    onClick={() => {
                      onChange(value.filter((x) => x.key !== p.key));
                    }}
                  >
                    <Trash2 aria-hidden="true" />
                    Remove<span className="sr-only"> parameter {p.name || index + 1}</span>
                  </Button>
                </fieldset>
              </li>
            );
          })}
        </ul>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={value.length >= MAX_PARAMETERS}
          onClick={() => {
            onChange([...value, newParameterDraft()]);
          }}
        >
          <Plus aria-hidden="true" />
          Add parameter
        </Button>
        <p className="text-muted-foreground text-xs">
          Up to {MAX_PARAMETERS}. The script reads each one as an environment variable with the same name.
        </p>
      </div>
    </div>
  );
}
