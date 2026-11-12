import { api, buildUrl, CSRF_HEADER, type Query } from './client';
import { ApiError } from './errors';

export interface RawUploadOptions {
  query?: Query;
  /** Called with a fraction from 0 to 1 while the body is being sent. */
  onProgress?: (fraction: number) => void;
  signal?: AbortSignal;
  /** Injectable for tests. */
  createRequest?: () => XMLHttpRequest;
}

const FALLBACK: Record<number, string> = {
  401: 'Your session has ended. Sign in again and retry the upload.',
  403: 'You do not have permission to upload this.',
  413: 'The file is larger than the server allows.',
};

function toError(xhr: XMLHttpRequest): ApiError {
  let code = xhr.status >= 500 ? 'server_error' : 'error';
  let message =
    FALLBACK[xhr.status] ??
    (xhr.status >= 500 ? 'The server had a problem. Try again shortly.' : `Upload failed (${xhr.status}).`);
  try {
    const body: unknown = JSON.parse(xhr.responseText);
    if (typeof body === 'object' && body !== null) {
      const b = body as Record<string, unknown>;
      if (typeof b.error === 'string') {
        code = b.error;
      }
      if (typeof b.message === 'string') {
        message = b.message;
      }
    }
  } catch {
    // Empty or non-JSON body (a proxy's 413, for example).
  }
  return new ApiError(xhr.status, code, message);
}

function send<T>(path: string, file: Blob, options: RawUploadOptions): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = options.createRequest ? options.createRequest() : new XMLHttpRequest();
    xhr.open('PUT', buildUrl(path, options.query));
    xhr.setRequestHeader('Accept', 'application/json');
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    const csrf = api.getCsrfToken();
    if (csrf) {
      xhr.setRequestHeader(CSRF_HEADER, csrf);
    }
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && e.total > 0) {
        options.onProgress?.(e.loaded / e.total);
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve((xhr.responseText ? JSON.parse(xhr.responseText) : undefined) as T);
        } catch {
          reject(new ApiError(xhr.status, 'bad_response', 'The server sent an unreadable answer to the upload.'));
        }
      } else {
        reject(toError(xhr));
      }
    };
    xhr.onerror = () => {
      reject(new ApiError(0, 'network', 'The upload was interrupted. Check your connection and try again.'));
    };
    xhr.onabort = () => {
      reject(new DOMException('Upload cancelled', 'AbortError'));
    };
    options.signal?.addEventListener('abort', () => {
      xhr.abort();
    });
    xhr.send(file);
  });
}

/**
 * `PUT` with the file as the raw request body. `fetch` cannot report upload progress, so this uses XMLHttpRequest
 * with the same cookie session and CSRF header as the API client, and the same step-up behaviour: on
 * `401 step_up_required` the "Confirm it is you" dialog opens and the upload is retried once.
 */
export async function uploadRaw<T>(path: string, file: Blob, options: RawUploadOptions = {}): Promise<T> {
  try {
    return await send<T>(path, file, options);
  } catch (error) {
    if (!(error instanceof ApiError)) {
      throw error;
    }
    if (error.status === 401 && error.code === 'step_up_required') {
      const confirmed = await api.confirmStepUp();
      if (!confirmed) {
        throw new ApiError(401, 'step_up_cancelled', 'Cancelled. The action was not carried out.');
      }
      options.onProgress?.(0);
      return send<T>(path, file, options);
    }
    api.noteError(error);
    throw error;
  }
}
