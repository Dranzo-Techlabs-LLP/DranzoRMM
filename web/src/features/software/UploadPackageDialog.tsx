import { useMutation, useQueryClient } from '@tanstack/react-query';
import { CircleCheck, FileUp } from 'lucide-react';
import { useId, useRef, useState, type SyntheticEvent } from 'react';
import { useOrgFilter } from '@/app/org-filter';
import { CopyButton } from '@/components/copy-button';
import { Field } from '@/components/field';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { NativeSelect, NativeSelectOption } from '@/components/ui/native-select';
import { AP } from '@/features/jobs/permissions';
import { errorMessage, isApiError } from '@/lib/api';
import { packagesApi, softwareKeys, type PackageType, type UploadedBlob } from '@/lib/api/software';
import { useAccess } from '@/lib/auth/session';
import { formatBytes } from '@/lib/format';
import { notifySuccess } from '@/lib/notify';
import { osLabel } from '@/lib/os';
import { ArgListEditor } from './ArgListEditor';
import {
  argListProblem,
  cleanArgs,
  detectionProblems,
  detectionTypesFor,
  EMPTY_DETECTION,
  installArgsHint,
  PACKAGE_ACCEPT,
  packageTypeFromFileName,
  packageTypeInfo,
  suggestPackageName,
  supportsInstallArgs,
  toDetectionRule,
  uninstallHint,
  uninstallProgramProblem,
  type DetectionDraft,
} from './software-model';

const SHARED = '';

/**
 * Adds a custom package in two steps, as the API does: upload the installer (the server computes its SHA-256), then
 * describe it. The dialog cannot be dismissed by clicking outside, so an upload is not lost by accident.
 */
export function UploadPackageDialog({ onClose }: { onClose: () => void }) {
  const [uploaded, setUploaded] = useState<{ blob: UploadedBlob; fileName: string; type: PackageType } | null>(null);
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) {
          onClose();
        }
      }}
    >
      <DialogContent
        className="max-h-[92dvh] overflow-y-auto sm:max-w-2xl"
        onInteractOutside={(e) => {
          e.preventDefault();
        }}
      >
        <DialogHeader>
          <DialogTitle>{uploaded ? 'Describe the package' : 'Upload a package'}</DialogTitle>
          <DialogDescription>
            {uploaded
              ? 'Step 2 of 2. Tell the agent how to install it silently and how to recognise that it is installed.'
              : 'Step 1 of 2. Choose an installer file: .msi or .exe for Windows, .pkg or .dmg for macOS, .deb or .rpm for Linux.'}
          </DialogDescription>
        </DialogHeader>
        {uploaded ? (
          <MetadataStep uploaded={uploaded} onClose={onClose} />
        ) : (
          <UploadStep onUploaded={setUploaded} onClose={onClose} />
        )}
      </DialogContent>
    </Dialog>
  );
}

function UploadStep({
  onUploaded,
  onClose,
}: {
  onUploaded: (result: { blob: UploadedBlob; fileName: string; type: PackageType }) => void;
  onClose: () => void;
}) {
  const inputId = useId();
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState(0);
  const abort = useRef<AbortController | null>(null);
  const type = file ? packageTypeFromFileName(file.name) : null;
  const fileProblem = !file
    ? null
    : type === null
      ? 'This file type is not supported. Choose a .msi, .exe, .pkg, .dmg, .deb or .rpm file.'
      : file.size === 0
        ? 'This file is empty.'
        : null;

  const upload = useMutation({
    mutationFn: (chosen: File) => {
      abort.current = new AbortController();
      setProgress(0);
      return packagesApi.upload(chosen, { onProgress: setProgress, signal: abort.current.signal });
    },
    onSuccess: (blob, chosen) => {
      const uploadedType = packageTypeFromFileName(chosen.name);
      if (uploadedType) {
        onUploaded({ blob, fileName: chosen.name, type: uploadedType });
      }
    },
  });
  const cancelled = isApiError(upload.error) && upload.error.code === 'upload_cancelled';
  const percent = Math.round(progress * 100);

  return (
    <form
      className="grid gap-4"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        if (file && !fileProblem && !upload.isPending) {
          upload.mutate(file);
        }
      }}
    >
      <div aria-live="assertive" className="empty:hidden">
        {upload.error && !cancelled ? <InlineAlert live={false}>{errorMessage(upload.error)}</InlineAlert> : null}
      </div>
      <div className="grid gap-1.5">
        <label htmlFor={inputId} className="text-sm font-medium">
          Installer file
        </label>
        <input
          id={inputId}
          type="file"
          accept={PACKAGE_ACCEPT}
          disabled={upload.isPending}
          aria-invalid={fileProblem ? true : undefined}
          aria-describedby={`${inputId}-hint`}
          className="border-input bg-card file:bg-secondary file:text-secondary-foreground dark:bg-input/30 block w-full rounded-md border text-sm file:mr-3 file:border-0 file:px-3 file:py-2 file:text-sm file:font-medium disabled:opacity-50"
          onChange={(e) => {
            setFile(e.target.files?.[0] ?? null);
            upload.reset();
          }}
        />
        <p id={`${inputId}-hint`} className="text-muted-foreground text-xs">
          {file && !fileProblem && type
            ? `${formatBytes(file.size)}, ${packageTypeInfo(type)?.label ?? type}, for ${osLabel(packageTypeInfo(type)?.os ?? '')} devices.`
            : 'The file is stored on your server. Agents download it from there and verify its SHA-256 before running it.'}
        </p>
        {fileProblem ? (
          <p role="alert" className="text-danger text-xs font-medium">
            {fileProblem}
          </p>
        ) : null}
      </div>

      {upload.isPending ? (
        <div className="grid gap-1.5">
          <div
            role="progressbar"
            aria-label="Upload progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={percent}
            className="bg-muted h-2 overflow-hidden rounded-full"
          >
            <div className="bg-primary h-full transition-[width]" style={{ width: `${percent}%` }} />
          </div>
          <p className="text-muted-foreground text-xs" role="status">
            {percent < 100
              ? `Uploading… ${percent}% of ${formatBytes(file?.size ?? 0)}`
              : 'Upload complete. The server is computing the SHA-256…'}
          </p>
        </div>
      ) : cancelled ? (
        <p className="text-muted-foreground text-xs" role="status">
          Upload cancelled. Nothing was stored.
        </p>
      ) : null}

      <DialogFooter>
        {upload.isPending ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              abort.current?.abort();
            }}
          >
            Cancel upload
          </Button>
        ) : (
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
        )}
        <Button type="submit" disabled={!file || fileProblem !== null || upload.isPending}>
          <FileUp aria-hidden="true" />
          {upload.isPending ? 'Uploading…' : 'Upload'}
        </Button>
      </DialogFooter>
    </form>
  );
}

function MetadataStep({
  uploaded,
  onClose,
}: {
  uploaded: { blob: UploadedBlob; fileName: string; type: PackageType };
  onClose: () => void;
}) {
  const access = useAccess();
  const queryClient = useQueryClient();
  const { organizations, orgId } = useOrgFilter();
  const ids = useId();
  const info = packageTypeInfo(uploaded.type);
  const os = info?.os ?? '';
  const canShare = access.hasPartnerWide(AP.packagesManage);
  const detectionTypes = detectionTypesFor(os);

  const [name, setName] = useState(() => suggestPackageName(uploaded.fileName));
  const [version, setVersion] = useState('');
  const [organizationId, setOrganizationId] = useState<string>(
    canShare ? (orgId ?? SHARED) : (orgId ?? organizations[0]?.id ?? ''),
  );
  const [installArgs, setInstallArgs] = useState<string[]>([]);
  const [uninstallCommand, setUninstallCommand] = useState<string[]>([]);
  const [detection, setDetection] = useState<DetectionDraft>({
    ...EMPTY_DETECTION,
    type: detectionTypes[0]?.id ?? 'file',
  });
  const [touched, setTouched] = useState(false);

  const nameValid = name.trim().length > 0 && name.trim().length <= 120;
  const versionValid = version.trim().length <= 64;
  const installProblem = argListProblem(installArgs);
  const uninstall = cleanArgs(uninstallCommand).map((a, i) => (i === 0 ? a.trim() : a));
  const uninstallProblem = argListProblem(uninstallCommand) ?? uninstallProgramProblem(uninstallCommand, os);
  const detectionErrors = detectionProblems(detection);
  const scopeValid = organizationId !== '' || canShare;
  const valid =
    nameValid &&
    versionValid &&
    scopeValid &&
    !installProblem &&
    !uninstallProblem &&
    Object.keys(detectionErrors).length === 0;
  const detectionType = detectionTypes.find((t) => t.id === detection.type) ?? detectionTypes[0];

  const create = useMutation({
    mutationFn: () =>
      packagesApi.create({
        name: name.trim(),
        version: version.trim() || undefined,
        type: uploaded.type,
        blobId: uploaded.blob.blobId,
        installArgs: supportsInstallArgs(uploaded.type) ? cleanArgs(installArgs) : [],
        uninstallCommand: uninstall,
        detection: toDetectionRule(detection),
        organizationId: organizationId === SHARED ? null : organizationId,
      }),
    onSuccess: async () => {
      notifySuccess(`Package “${name.trim()}” added`);
      await queryClient.invalidateQueries({ queryKey: softwareKeys.packages });
      onClose();
    },
  });
  const forbiddenShared = isApiError(create.error) && create.error.status === 403 && organizationId === SHARED;

  const submit = (e: SyntheticEvent) => {
    e.preventDefault();
    setTouched(true);
    if (valid && !create.isPending) {
      create.mutate();
    }
  };

  return (
    <form onSubmit={submit} noValidate className="grid gap-5">
      <div className="bg-ok-surface rounded-md px-3 py-2.5">
        <p className="text-ok flex items-center gap-1.5 font-semibold">
          <CircleCheck aria-hidden="true" className="size-4" />
          Uploaded
        </p>
        <dl className="mt-1.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
          <dt className="text-muted-foreground">File</dt>
          <dd className="ident min-w-0 break-all">{uploaded.fileName}</dd>
          <dt className="text-muted-foreground">Size</dt>
          <dd>
            {formatBytes(uploaded.blob.sizeBytes)} ({uploaded.blob.sizeBytes.toLocaleString('en')} bytes)
          </dd>
          <dt className="text-muted-foreground">SHA-256</dt>
          <dd className="flex items-start gap-2">
            <span className="ident min-w-0 break-all">{uploaded.blob.sha256}</span>
            <CopyButton value={uploaded.blob.sha256} label="Copy" size="xs" variant="ghost" />
          </dd>
        </dl>
        <p className="mt-1.5 text-xs">
          Computed by the server from the bytes it received. Compare it with the hash the publisher lists. Agents refuse
          to run the file if their download does not match it.
        </p>
      </div>

      <div aria-live="assertive" className="empty:hidden">
        {create.error ? (
          <InlineAlert live={false} title={forbiddenShared ? 'Shared packages need a partner-wide role' : undefined}>
            {forbiddenShared
              ? 'A shared package can be deployed to every organization. Choose one organization for it, or ask a partner administrator.'
              : errorMessage(create.error)}
          </InlineAlert>
        ) : null}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" error={touched && !nameValid ? 'Enter a name of up to 120 characters.' : null}>
          {(control) => (
            <Input
              {...control}
              value={name}
              maxLength={120}
              autoComplete="off"
              autoFocus
              onChange={(e) => {
                setName(e.target.value);
              }}
            />
          )}
        </Field>
        <Field
          label="Version (optional)"
          hint="For your reference, for example 5.2.1."
          error={touched && !versionValid ? 'At most 64 characters.' : null}
        >
          {(control) => (
            <Input
              {...control}
              className="ident"
              value={version}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => {
                setVersion(e.target.value);
              }}
            />
          )}
        </Field>
        <div className="grid content-start gap-1.5">
          <p className="text-sm font-medium">Type</p>
          <p className="flex min-h-9 items-center">{info?.label ?? uploaded.type}</p>
          <p className="text-muted-foreground text-xs">
            Taken from the file extension. Installs on {osLabel(os)} devices only.
          </p>
        </div>
        <Field
          label="Available to"
          hint={canShare ? undefined : 'Shared packages need a partner-wide role.'}
          error={touched && !scopeValid ? 'Choose an organization.' : null}
        >
          {(control) => (
            <NativeSelect
              {...control}
              className="w-full"
              value={organizationId}
              onChange={(e) => {
                setOrganizationId(e.target.value);
              }}
            >
              {canShare ? (
                <NativeSelectOption value={SHARED}>All organizations (shared)</NativeSelectOption>
              ) : (
                <NativeSelectOption value="">Choose…</NativeSelectOption>
              )}
              {organizations.map((o) => (
                <NativeSelectOption key={o.id} value={o.id}>
                  {o.name} only
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        </Field>
      </div>

      {supportsInstallArgs(uploaded.type) ? (
        <ArgListEditor
          legend="Install arguments"
          hint={installArgsHint(uploaded.type)}
          value={installArgs}
          onChange={setInstallArgs}
          placeholder={uploaded.type === 'exe' ? '/S' : 'PROPERTY=value'}
          error={touched ? installProblem : null}
        />
      ) : (
        <div>
          <p className="text-sm font-medium">Install arguments</p>
          <p className="text-muted-foreground text-sm">
            Not needed: {info?.label ?? 'this type'} installs silently with the system’s own installer.
          </p>
        </div>
      )}

      <ArgListEditor
        legend="Uninstall command (optional)"
        hint={uninstallHint(os)}
        value={uninstallCommand}
        onChange={setUninstallCommand}
        itemLabel="Argument"
        firstItemLabel="Program"
        placeholder={os === 'windows' ? 'msiexec' : os === 'macos' ? '/usr/sbin/pkgutil' : 'apt-get'}
        error={touched ? uninstallProblem : null}
      />

      <fieldset className="grid gap-3">
        <legend className="mb-1.5 text-sm font-medium">Detection rule</legend>
        <div className="flex items-start gap-2.5">
          <Checkbox
            id={`${ids}-detect`}
            className="mt-0.5"
            checked={detection.enabled}
            onCheckedChange={(checked) => {
              setDetection({ ...detection, enabled: checked === true });
            }}
          />
          <label htmlFor={`${ids}-detect`}>
            <span className="font-medium">Check whether it is already installed</span>
            <span className="text-muted-foreground block text-xs">
              With a rule, devices that already have it (at the minimum version or newer) skip the install, and the
              result of every deployment is verified. Without one, the installer’s exit code decides.
            </span>
          </label>
        </div>
        {detection.enabled ? (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Installed when">
              {(control) => (
                <NativeSelect
                  {...control}
                  className="w-full"
                  value={detectionType?.id ?? detection.type}
                  onChange={(e) => {
                    setDetection({ ...detection, type: e.target.value, valueName: '' });
                  }}
                >
                  {detectionTypes.map((t) => (
                    <NativeSelectOption key={t.id} value={t.id}>
                      {t.label}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              )}
            </Field>
            <Field
              label={detectionType?.keyLabel ?? 'Key'}
              hint={detectionType?.keyHint}
              error={touched ? (detectionErrors.key ?? null) : null}
            >
              {(control) => (
                <Input
                  {...control}
                  className="ident"
                  value={detection.key}
                  maxLength={512}
                  spellCheck={false}
                  autoCapitalize="none"
                  autoComplete="off"
                  onChange={(e) => {
                    setDetection({ ...detection, key: e.target.value });
                  }}
                />
              )}
            </Field>
            {detectionType?.valueName ? (
              <Field label={detectionType.valueName} error={touched ? (detectionErrors.valueName ?? null) : null}>
                {(control) => (
                  <Input
                    {...control}
                    className="ident"
                    value={detection.valueName}
                    maxLength={255}
                    spellCheck={false}
                    autoComplete="off"
                    placeholder="DisplayVersion"
                    onChange={(e) => {
                      setDetection({ ...detection, valueName: e.target.value });
                    }}
                  />
                )}
              </Field>
            ) : null}
            <Field
              label="Minimum version (optional)"
              hint="Older versions count as not installed, so they are upgraded."
              error={touched ? (detectionErrors.minVersion ?? null) : null}
            >
              {(control) => (
                <Input
                  {...control}
                  className="ident"
                  value={detection.minVersion}
                  maxLength={64}
                  spellCheck={false}
                  autoComplete="off"
                  onChange={(e) => {
                    setDetection({ ...detection, minVersion: e.target.value });
                  }}
                />
              )}
            </Field>
          </div>
        ) : null}
      </fieldset>

      <DialogFooter>
        <Button type="button" variant="outline" onClick={onClose} disabled={create.isPending}>
          Discard upload
        </Button>
        <Button type="submit" disabled={create.isPending}>
          {create.isPending ? 'Saving…' : 'Add package'}
        </Button>
      </DialogFooter>
    </form>
  );
}
