import { ApiError, toApiError } from './errors';

export const API_BASE = '/api/v1';
export const CSRF_HEADER = 'X-CSRF-Token';

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export type QueryValue = string | number | boolean | null | undefined;
export type Query = Record<string, QueryValue>;

export interface RequestOptions {
  query?: Query;
  body?: unknown;
  signal?: AbortSignal;
  /**
   * The call is part of signing in (or probing the session). A `401` is an expected answer and must not trigger the
   * global "session ended" handling.
   */
  anonymous?: boolean;
  /** Do not open the step-up dialog for this call (used by the step-up call itself). */
  noStepUp?: boolean;
}

export interface ApiClientHandlers {
  /** Called once per failed request when the server says the session is gone (`401 unauthenticated`). */
  onUnauthenticated?: () => void;
  /**
   * Asks the user to re-enter their authenticator code and performs `POST /auth/step-up`.
   * Resolves `true` when step-up succeeded, `false` when the user cancelled.
   */
  requestStepUp?: () => Promise<boolean>;
  /** Called when the server refuses a call because the user still has a temporary password. */
  onPasswordChangeRequired?: () => void;
}

/** Builds `/api/v1/...?a=b`, dropping empty values. Values go in the query string, so never pass secrets. */
export function buildUrl(path: string, query?: Query): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, String(value));
    }
  }
  const qs = params.toString();
  return `${API_BASE}${path}${qs ? `?${qs}` : ''}`;
}

/**
 * Typed fetch wrapper for the dashboard API.
 *
 * - Cookie session: `credentials: 'same-origin'`; the session token is HttpOnly and never visible here.
 * - CSRF: every unsafe method carries `X-CSRF-Token` (held in memory only, from `/auth/me` or the MFA response).
 * - Step-up: `401 step_up_required` opens the step-up dialog and the original request is retried exactly once.
 * - `401 unauthenticated`: notifies the app so it can clear state and go to the sign-in page.
 */
export class ApiClient {
  private csrfToken: string | null = null;
  private handlers: ApiClientHandlers = {};
  private stepUpInFlight: Promise<boolean> | null = null;
  private readonly fetchImpl: typeof fetch;

  constructor(fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? ((input, init) => globalThis.fetch(input, init));
  }

  setCsrfToken(token: string | null): void {
    this.csrfToken = token;
  }

  getCsrfToken(): string | null {
    return this.csrfToken;
  }

  /** Registers app-level handlers. Returns a function that removes exactly the handlers it added. */
  configure(handlers: ApiClientHandlers): () => void {
    this.handlers = { ...this.handlers, ...handlers };
    return () => {
      for (const key of Object.keys(handlers) as (keyof ApiClientHandlers)[]) {
        if (this.handlers[key] === handlers[key]) {
          this.handlers[key] = undefined;
        }
      }
    };
  }

  get<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>('GET', path, options);
  }

  post<T = void>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>('POST', path, { ...options, body });
  }

  patch<T = void>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.request<T>('PATCH', path, { ...options, body });
  }

  delete<T = void>(path: string, options?: RequestOptions): Promise<T> {
    return this.request<T>('DELETE', path, options);
  }

  async request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
    return this.attempt<T>(method.toUpperCase(), path, options, { steppedUp: false, csrfRefreshed: false });
  }

  private async attempt<T>(
    method: string,
    path: string,
    options: RequestOptions,
    retried: { steppedUp: boolean; csrfRefreshed: boolean },
  ): Promise<T> {
    const res = await this.send(method, path, options);
    if (res.ok) {
      return (await this.parse(res)) as T;
    }
    const error = await toApiError(res);

    if (error.status === 401 && error.code === 'step_up_required' && !options.noStepUp && !retried.steppedUp) {
      const confirmed = await this.confirmStepUp();
      if (!confirmed) {
        throw new ApiError(401, 'step_up_cancelled', 'Cancelled. The action was not carried out.');
      }
      return this.attempt<T>(method, path, options, { ...retried, steppedUp: true });
    }

    // The in-memory CSRF token can be stale (for example another tab signed in again). Refresh it once.
    if (error.status === 403 && error.code === 'csrf' && !retried.csrfRefreshed && !options.anonymous) {
      const me = await this.attempt<{ csrfToken?: string }>(
        'GET',
        '/auth/me',
        { signal: options.signal },
        { steppedUp: true, csrfRefreshed: true },
      );
      this.csrfToken = me.csrfToken ?? null;
      return this.attempt<T>(method, path, options, { ...retried, csrfRefreshed: true });
    }

    if (error.status === 401 && error.code === 'unauthenticated' && !options.anonymous) {
      this.csrfToken = null;
      this.handlers.onUnauthenticated?.();
    }
    this.noteError(error);
    throw error;
  }

  /**
   * App-wide reactions to an error from a request made outside {@link request} (raw uploads use XMLHttpRequest).
   * `403 password_change_required` means the user must replace a temporary password before anything else works.
   */
  noteError(error: ApiError): void {
    if (error.status === 403 && error.code === 'password_change_required') {
      this.handlers.onPasswordChangeRequired?.();
    }
  }

  /**
   * Opens the "Confirm it is you" dialog (shared by concurrent requests). Resolves `true` after a successful
   * `POST /auth/step-up`. Public so raw uploads can retry after `401 step_up_required` the same way `request` does.
   */
  confirmStepUp(): Promise<boolean> {
    const request = this.handlers.requestStepUp;
    if (!request) {
      return Promise.resolve(false);
    }
    this.stepUpInFlight ??= request().finally(() => {
      this.stepUpInFlight = null;
    });
    return this.stepUpInFlight;
  }

  private async send(method: string, path: string, options: RequestOptions): Promise<Response> {
    const headers = new Headers({ Accept: 'application/json' });
    let body: string | undefined;
    if (options.body !== undefined) {
      headers.set('Content-Type', 'application/json');
      body = JSON.stringify(options.body);
    }
    if (UNSAFE_METHODS.has(method) && this.csrfToken) {
      headers.set(CSRF_HEADER, this.csrfToken);
    }
    try {
      return await this.fetchImpl(buildUrl(path, options.query), {
        method,
        headers,
        body,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        signal: options.signal,
      });
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === 'AbortError') {
        throw cause;
      }
      throw new ApiError(0, 'network', 'Cannot reach the server. Check your connection and try again.');
    }
  }

  private async parse(res: Response): Promise<unknown> {
    if (res.status === 204 || res.status === 205) {
      return undefined;
    }
    const type = res.headers.get('Content-Type') ?? '';
    if (!type.includes('json')) {
      return undefined;
    }
    const text = await res.text();
    return text ? (JSON.parse(text) as unknown) : undefined;
  }
}

/** The single client used by the app. Tests construct their own instances. */
export const api = new ApiClient();
