import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ChevronRight, CornerLeftUp, Download, File as FileIcon, Folder, RefreshCw, Upload } from 'lucide-react';
import { Fragment, useRef, useState, type SyntheticEvent } from 'react';
import { ConfirmDialog } from '@/components/confirm-dialog';
import { EmptyState, LoadingRows } from '@/components/page';
import { InlineAlert } from '@/components/status';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { errorMessage, isApiError, type Id } from '@/lib/api';
import { remoteApi, type DownloadTicket, type FileEntry } from '@/lib/api/remote';
import { formatBytes, formatDateTime } from '@/lib/format';
import { notifySuccess } from '@/lib/notify';
import { cn } from '@/lib/utils';
import { breadcrumbs, defaultPath, joinPath, normalizePath, parentPath, sortEntries, type PathStyle } from './paths';

/** Starts a normal browser download of a same-origin URL. The server answers with `attachment`. */
function triggerDownload(url: string, fileName: string): void {
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function fileError(error: unknown): { title: string; message: string } {
  if (isApiError(error)) {
    if (error.status === 422) {
      return { title: 'The device reported a problem', message: error.message };
    }
    if (error.status === 504) {
      return {
        title: 'The device did not answer in time',
        message: 'It may be busy or the file may be large. Try again.',
      };
    }
    if (error.status === 413) {
      return { title: 'The file is too large', message: error.message };
    }
    if (error.status === 409) {
      return { title: 'The session is no longer active', message: error.message };
    }
  }
  return { title: 'That did not work', message: errorMessage(error) };
}

interface Ready {
  ticket: DownloadTicket;
  url: string;
}

/**
 * File browser inside an active `files` session. Every listing, download and upload is carried out by the agent
 * and recorded in the audit log. Names, sizes and error texts come from the device and are rendered as text.
 */
export function FileBrowser({
  sessionId,
  style,
  active,
}: {
  sessionId: Id;
  style: PathStyle;
  /** False once the session is over: the last listing stays visible but nothing can be requested. */
  active: boolean;
}) {
  const queryClient = useQueryClient();
  const [path, setPath] = useState(() => defaultPath(style));
  const [draft, setDraft] = useState(path);
  const [ready, setReady] = useState<Ready | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [overwrite, setOverwrite] = useState<File | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const key = ['sessions', sessionId, 'files', path] as const;
  const listing = useQuery({
    queryKey: key,
    queryFn: ({ signal }) => remoteApi.listFiles(sessionId, path, signal),
    enabled: active,
    placeholderData: keepPreviousData,
    staleTime: Infinity,
    retry: false,
    refetchOnWindowFocus: false,
  });

  const go = (next: string) => {
    const normalized = normalizePath(next, style);
    setPath(normalized);
    setDraft(normalized);
    if (normalized === path) {
      void listing.refetch();
    }
  };

  const download = useMutation({
    mutationFn: async (entry: FileEntry) => {
      const ticket = await remoteApi.prepareDownload(sessionId, joinPath(path, entry.name, style));
      return { ticket, url: remoteApi.contentUrl(sessionId, ticket) };
    },
    onSuccess: (result) => {
      setReady(result);
      triggerDownload(result.url, result.ticket.fileName);
    },
  });

  const upload = useMutation({
    mutationFn: ({ file, replace }: { file: File; replace: boolean }) =>
      remoteApi.uploadFile(sessionId, joinPath(path, file.name, style), file, replace, { onProgress: setProgress }),
    onSuccess: async (result, { file }) => {
      notifySuccess(`Uploaded ${file.name} (${formatBytes(result.sizeBytes)})`);
      await queryClient.invalidateQueries({ queryKey: key });
    },
    onSettled: () => {
      setProgress(null);
      setOverwrite(null);
    },
  });

  const entries = listing.data ? sortEntries(listing.data.entries) : [];
  // What the device says the folder is (it resolves links and `..`); falls back to what was asked for.
  const shownPath = listing.data && !listing.isPlaceholderData ? listing.data.path || path : path;
  const crumbs = breadcrumbs(shownPath, style);
  const parent = parentPath(shownPath, style);

  const exists = (name: string) =>
    entries.some((e) => (style === 'windows' ? e.name.toLowerCase() === name.toLowerCase() : e.name === name));

  const onPick = (e: SyntheticEvent<HTMLInputElement>) => {
    const file = e.currentTarget.files?.[0];
    e.currentTarget.value = '';
    if (!file) {
      return;
    }
    upload.reset();
    if (exists(file.name)) {
      setOverwrite(file);
    } else {
      upload.mutate({ file, replace: false });
    }
  };

  const listError = listing.isError ? fileError(listing.error) : null;
  const actionError = download.isError ? fileError(download.error) : upload.isError ? fileError(upload.error) : null;
  const busy = upload.isPending || download.isPending;

  return (
    <div className="grid gap-3">
      <form
        className="flex flex-wrap items-end gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          go(draft);
        }}
      >
        <div className="grid min-w-64 flex-1 gap-1">
          <Label htmlFor="file-path" className="text-xs">
            Folder on the device
          </Label>
          <Input
            id="file-path"
            className="ident h-8"
            value={draft}
            maxLength={4096}
            spellCheck={false}
            autoCapitalize="none"
            autoComplete="off"
            disabled={!active}
            onChange={(e) => {
              setDraft(e.target.value);
            }}
          />
        </div>
        <Button type="submit" size="sm" variant="outline" disabled={!active}>
          Go
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={!active || parent === null}
          onClick={() => {
            if (parent !== null) {
              go(parent);
            }
          }}
        >
          <CornerLeftUp aria-hidden="true" />
          Up
        </Button>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={!active || listing.isFetching}
          onClick={() => void listing.refetch()}
        >
          <RefreshCw aria-hidden="true" />
          Refresh
        </Button>
        <input ref={fileInput} type="file" className="sr-only" tabIndex={-1} aria-hidden="true" onChange={onPick} />
        <Button
          type="button"
          size="sm"
          disabled={!active || busy || listing.isError || !listing.data}
          onClick={() => fileInput.current?.click()}
        >
          <Upload aria-hidden="true" />
          Upload a file here
        </Button>
      </form>

      <nav aria-label="Folder path">
        <ol className="flex flex-wrap items-center gap-0.5 text-sm">
          {crumbs.map((c, i) => (
            <Fragment key={c.path}>
              {i > 0 ? <ChevronRight aria-hidden="true" className="text-muted-foreground size-3.5" /> : null}
              <li>
                {i === crumbs.length - 1 ? (
                  <span aria-current="location" className="ident px-1 font-medium">
                    {c.label}
                  </span>
                ) : (
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    className="ident px-1"
                    disabled={!active}
                    onClick={() => {
                      go(c.path);
                    }}
                  >
                    {c.label}
                  </Button>
                )}
              </li>
            </Fragment>
          ))}
        </ol>
      </nav>

      <p className="text-muted-foreground text-xs">
        Uploads and downloads are limited in size by the server (100 MB unless your administrator changed it). Every
        folder you open and every file you transfer is recorded in the audit log.
      </p>

      {progress !== null ? (
        <div role="status" className="grid gap-1">
          <p className="text-sm">
            {progress < 1
              ? `Uploading… ${Math.round(progress * 100)}%`
              : 'Sent. Waiting for the device to save the file…'}
          </p>
          <div
            role="progressbar"
            aria-label="Upload progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={Math.round(progress * 100)}
            className="bg-idle-surface h-2 overflow-hidden rounded-[3px]"
          >
            <div className="bg-foreground/60 h-full" style={{ width: `${Math.round(progress * 100)}%` }} />
          </div>
        </div>
      ) : null}
      {download.isPending ? (
        <p role="status" className="text-sm">
          Asking the device for the file…
        </p>
      ) : null}
      {actionError ? <InlineAlert title={actionError.title}>{actionError.message}</InlineAlert> : null}
      {ready ? (
        <InlineAlert tone="ok" title="Download ready">
          <a href={ready.url} download={ready.ticket.fileName} rel="noopener noreferrer" className="underline">
            Save {ready.ticket.fileName}
          </a>{' '}
          if your browser did not start the download.
          {ready.ticket.sha256 ? (
            <span className="mt-1 block text-xs">
              SHA-256 <span className="ident break-all">{ready.ticket.sha256}</span>
            </span>
          ) : null}
        </InlineAlert>
      ) : null}

      <div className="rounded-md border">
        {listError ? (
          <div className="p-3">
            <InlineAlert title={listError.title}>{listError.message}</InlineAlert>
          </div>
        ) : listing.isPending ? (
          active ? (
            <LoadingRows label="folder" rows={6} />
          ) : (
            <EmptyState title="No folder was opened in this session" />
          )
        ) : entries.length === 0 ? (
          <EmptyState icon={Folder} title="This folder is empty" />
        ) : (
          <div
            className={cn('max-h-[min(60dvh,36rem)] overflow-auto', listing.isPlaceholderData && 'opacity-60')}
            aria-busy={listing.isFetching}
          >
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead scope="col">Name</TableHead>
                  <TableHead scope="col" className="text-right">
                    Size
                  </TableHead>
                  <TableHead scope="col">Modified</TableHead>
                  <TableHead scope="col">Mode</TableHead>
                  <TableHead scope="col">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry) => (
                  <TableRow key={`${entry.isDir ? 'd' : 'f'}:${entry.name}`}>
                    <TableHead scope="row" className="text-foreground h-auto py-1.5 text-sm font-normal">
                      {entry.isDir ? (
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="ident -ml-2 h-7 max-w-full justify-start gap-2"
                          disabled={!active}
                          onClick={() => {
                            go(joinPath(shownPath, entry.name, style));
                          }}
                        >
                          <Folder aria-hidden="true" className="text-muted-foreground" />
                          <span className="sr-only">Folder </span>
                          <span className="truncate">{entry.name}</span>
                        </Button>
                      ) : (
                        <span className="ident inline-flex max-w-full items-center gap-2">
                          <FileIcon aria-hidden="true" className="text-muted-foreground size-4 shrink-0" />
                          <span className="sr-only">File </span>
                          <span className="break-all">{entry.name}</span>
                        </span>
                      )}
                    </TableHead>
                    <TableCell className="text-right whitespace-nowrap">
                      {entry.isDir ? (
                        <span className="text-muted-foreground">Folder</span>
                      ) : (
                        formatBytes(entry.sizeBytes)
                      )}
                    </TableCell>
                    <TableCell className="whitespace-nowrap">{formatDateTime(entry.modifiedAt)}</TableCell>
                    <TableCell className="ident text-xs">{entry.mode}</TableCell>
                    <TableCell className="py-1 text-right">
                      {entry.isDir ? null : (
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          disabled={!active || busy}
                          onClick={() => {
                            setReady(null);
                            upload.reset();
                            download.mutate(entry);
                          }}
                        >
                          <Download aria-hidden="true" />
                          Download<span className="sr-only"> {entry.name}</span>
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
      {listing.data?.truncated ? (
        <p className="text-muted-foreground text-xs">
          This folder has more entries than the device lists at once. Open a subfolder or type a path to reach the rest.
        </p>
      ) : null}

      <ConfirmDialog
        open={overwrite !== null}
        onOpenChange={(open) => {
          if (!open) {
            setOverwrite(null);
          }
        }}
        title={`Replace ${overwrite?.name ?? 'this file'}?`}
        description={
          <p>
            A file with this name already exists in <span className="ident break-all">{shownPath}</span>. Uploading
            replaces it on the device. The old content cannot be recovered from here.
          </p>
        }
        confirmLabel="Replace file"
        destructive
        pending={upload.isPending}
        onConfirm={() => {
          if (overwrite) {
            upload.mutate({ file: overwrite, replace: true });
          }
        }}
      />
    </div>
  );
}
