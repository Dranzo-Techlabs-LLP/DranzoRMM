/** Error shape of every non-2xx API response: `{ error, message }` (see server `Api.Error` / `AccessMiddleware`). */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

/** Text safe to show to the user for any thrown value. */
export function errorMessage(error: unknown): string {
  if (isApiError(error)) {
    return error.message;
  }
  return 'Something went wrong. Try again.';
}

const FALLBACK_MESSAGES: Record<number, [code: string, message: string]> = {
  400: ['bad_request', 'The server rejected the request.'],
  401: ['unauthenticated', 'Sign in required.'],
  403: ['forbidden', 'You do not have permission to do this.'],
  404: ['not_found', 'Not found. It may have been removed, or you may not have access.'],
  409: ['conflict', 'This conflicts with the current state. Refresh and try again.'],
  423: ['locked', 'Account temporarily locked. Try again later.'],
  429: ['rate_limited', 'Too many requests. Wait a minute and try again.'],
};

/** Builds an {@link ApiError} from a failed response, tolerating empty or non-JSON bodies. */
export async function toApiError(res: Response): Promise<ApiError> {
  let code: string | undefined;
  let message: string | undefined;
  try {
    const body: unknown = await res.json();
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
    // Empty or non-JSON body (for example a 429 from the rate limiter or a 502 from a proxy).
  }
  const fallback = FALLBACK_MESSAGES[res.status] ?? [
    res.status >= 500 ? 'server_error' : 'error',
    res.status >= 500 ? 'The server had a problem. Try again shortly.' : `Request failed (${res.status}).`,
  ];
  return new ApiError(res.status, code ?? fallback[0], message ?? fallback[1]);
}
