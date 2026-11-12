import { useMutation, useQueryClient } from '@tanstack/react-query';
import { CircleCheck, Upload, X } from 'lucide-react';
import { useRef, useState, type SyntheticEvent } from 'react';
import { Field } from '@/components/field';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { errorMessage, isApiError } from '@/lib/api';
import { releaseKeys, releasesApi, type ReleaseFileInput, type UploadedReleaseFile } from '@/lib/api/releases';
import { formatBytes } from '@/lib/format';
import { notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import {
  KIND_LABEL,
  MAX_RELEASE_FILE_BYTES,
  MIN_RELEASE_FILE_BYTES,
  RELEASE_SLOTS,
  slotKey,
  VERSION_PATTERN,
  type ReleaseSlot,
} from './release-model';

type SlotState =
  | { status: 'uploading'; fileName: string; progress: number }
  | { status: 'done'; fileName: string; result: UploadedReleaseFile }
  | { status: 'error'; fileName: string; message: string };

/**
 * New release: upload each file (agent binary per OS/arch for self-update, optional installers for enrollment),
 * check the SHA-256 the server computed against your build output, then name the version. The server signs every
 * file. A new release is offered to no device until a ring is chosen.
 */
export function CreateReleaseWizard({ existingVersions, onDone }: { existingVersions: string[]; onDone: () => void }) {
  const queryClient = useQueryClient();
  const [slots, setSlots] = useState<Record<string, SlotState>>({});
  const [version, setVersion] = useState('');
  const [notes, setNotes] = useState('');
  const [touched, setTouched] = useState(false);
  const inputs = useRef<Record<string, HTMLInputElement | null>>({});
  const uploading = Object.values(slots).some((s) => s.status === 'uploading');
  const done = RELEASE_SLOTS.filter((s) => slots[slotKey(s)]?.status === 'done');
  const hasBinary = done.some((s) => s.kind === 'binary');
  const versionValid = VERSION_PATTERN.test(version.trim());
  const duplicate = existingVersions.includes(version.trim());

  const upload = async (slot: ReleaseSlot, file: File) => {
    const key = slotKey(slot);
    if (file.size < MIN_RELEASE_FILE_BYTES || file.size > MAX_RELEASE_FILE_BYTES) {
      setSlots((s) => ({
        ...s,
        [key]: { status: 'error', fileName: file.name, message: 'Files must be 1 MiB to 500 MiB.' },
      }));
      return;
    }
    setSlots((s) => ({ ...s, [key]: { status: 'uploading', fileName: file.name, progress: 0 } }));
    try {
      const result = await releasesApi.upload(file, {
        onProgress: (progress) => {
          setSlots((s) => ({ ...s, [key]: { status: 'uploading', fileName: file.name, progress } }));
        },
      });
      setSlots((s) => ({ ...s, [key]: { status: 'done', fileName: file.name, result } }));
    } catch (error) {
      const message = isApiError(error) && error.code === 'step_up_cancelled' ? 'Cancelled.' : errorMessage(error);
      setSlots((s) => ({ ...s, [key]: { status: 'error', fileName: file.name, message } }));
    }
  };

  const create = useMutation({
    mutationFn: () => {
      const binaries: ReleaseFileInput[] = done.map((slot) => {
        const state = slots[slotKey(slot)];
        const blobId = state?.status === 'done' ? state.result.blobId : '';
        return slot.kind === 'binary'
          ? { os: slot.os, arch: slot.arch, blobId }
          : { os: slot.os, arch: slot.arch, blobId, kind: slot.kind };
      });
      return releasesApi.create({ version: version.trim(), notes: notes.trim(), binaries });
    },
    onSuccess: async () => {
      notifySuccess(`Release ${version.trim()} created. It is not offered to any device yet.`);
      await queryClient.invalidateQueries({ queryKey: releaseKeys.list });
      onDone();
    },
  });

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (versionValid && !duplicate && done.length > 0 && hasBinary && !uploading) {
      create.mutate();
    }
  };
  const error =
    create.error && !(isApiError(create.error) && create.error.code === 'step_up_cancelled')
      ? errorMessage(create.error)
      : null;

  return (
    <form onSubmit={submit} noValidate className="grid grid-cols-[minmax(0,1fr)] gap-4">
      <DialogHeader>
        <DialogTitle>New agent release</DialogTitle>
        <DialogDescription>
          1. Upload the files you built. 2. Compare each SHA-256 with your build output. 3. Name the version. Each
          upload and the release itself ask for your authenticator code when it is no longer fresh.
        </DialogDescription>
      </DialogHeader>
      <div aria-live="assertive" className="empty:hidden">
        {error ? <InlineAlert live={false}>{error}</InlineAlert> : null}
      </div>
      <fieldset className="grid gap-2">
        <legend className="mb-1 text-sm font-medium">Files (1 MiB to 500 MiB each)</legend>
        <ul className="divide-y rounded-md border">
          {RELEASE_SLOTS.map((slot) => {
            const key = slotKey(slot);
            const state = slots[key];
            const label = `${osLabel(slot.os)} ${slot.arch}: ${KIND_LABEL[slot.kind] ?? slot.kind}`;
            return (
              <li key={key} className="grid gap-1 px-3 py-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm">
                    <span className="font-medium">
                      {osLabel(slot.os)} {slot.arch}
                    </span>{' '}
                    <span className="text-muted-foreground">{KIND_LABEL[slot.kind]}</span>
                  </span>
                  <span className="flex items-center gap-1">
                    <input
                      ref={(el) => {
                        inputs.current[key] = el;
                      }}
                      type="file"
                      className="sr-only"
                      tabIndex={-1}
                      aria-hidden="true"
                      onChange={(e) => {
                        const file = e.currentTarget.files?.[0];
                        e.currentTarget.value = '';
                        if (file) {
                          void upload(slot, file);
                        }
                      }}
                    />
                    {state?.status === 'done' ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="xs"
                        onClick={() => {
                          setSlots((s) => Object.fromEntries(Object.entries(s).filter(([k]) => k !== key)));
                        }}
                      >
                        <X aria-hidden="true" />
                        Remove<span className="sr-only"> {label}</span>
                      </Button>
                    ) : null}
                    <Button
                      type="button"
                      variant="outline"
                      size="xs"
                      disabled={state?.status === 'uploading'}
                      onClick={() => inputs.current[key]?.click()}
                    >
                      <Upload aria-hidden="true" />
                      {state ? 'Replace' : 'Upload'}
                      <span className="sr-only"> {label}</span>
                    </Button>
                  </span>
                </div>
                {state?.status === 'uploading' ? (
                  <div role="status" className="grid gap-1">
                    <span className="text-xs">
                      {state.fileName}: {state.progress < 1 ? `${Math.round(state.progress * 100)}%` : 'checking…'}
                    </span>
                    <div
                      role="progressbar"
                      aria-label={`Upload of ${state.fileName}`}
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-valuenow={Math.round(state.progress * 100)}
                      className="bg-idle-surface h-1.5 overflow-hidden rounded-[3px]"
                    >
                      <div
                        className="bg-foreground/60 h-full"
                        style={{ width: `${Math.round(state.progress * 100)}%` }}
                      />
                    </div>
                  </div>
                ) : null}
                {state?.status === 'done' ? (
                  <p className="text-xs">
                    <CircleCheck aria-hidden="true" className="text-ok mr-1 inline size-3.5 align-[-2px]" />
                    <span className="break-all">{state.fileName}</span>, {formatBytes(state.result.sizeBytes)}. SHA-256{' '}
                    <span className="ident break-all select-all">{state.result.sha256}</span>
                  </p>
                ) : null}
                {state?.status === 'error' ? (
                  <p role="alert" className="text-danger text-xs font-medium">
                    {state.fileName}: {state.message}
                  </p>
                ) : null}
              </li>
            );
          })}
        </ul>
        {touched && !hasBinary ? (
          <p role="alert" className="text-danger text-xs font-medium">
            Upload at least one agent binary. Installers alone cannot update devices.
          </p>
        ) : null}
      </fieldset>
      <Field
        label="Version"
        hint="Like 1.4.0 or 1.4.0-rc1. Must be higher than what devices run to be offered. Versions cannot be reused."
        error={
          touched && !versionValid
            ? 'Use the form 1.2.3 or 1.2.3-rc1.'
            : touched && duplicate
              ? 'This version already exists.'
              : null
        }
      >
        {(control) => (
          <Input
            {...control}
            className="ident max-w-48"
            value={version}
            maxLength={40}
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => {
              setVersion(e.target.value);
            }}
          />
        )}
      </Field>
      <Field label="Release notes (optional)">
        {(control) => (
          <Textarea
            {...control}
            rows={3}
            maxLength={4000}
            value={notes}
            onChange={(e) => {
              setNotes(e.target.value);
            }}
          />
        )}
      </Field>
      <DialogFooter>
        <Button type="button" variant="outline" onClick={onDone} disabled={create.isPending || uploading}>
          Cancel
        </Button>
        <Button type="submit" disabled={create.isPending || uploading}>
          {create.isPending ? 'Creating…' : 'Create release'}
        </Button>
      </DialogFooter>
    </form>
  );
}
