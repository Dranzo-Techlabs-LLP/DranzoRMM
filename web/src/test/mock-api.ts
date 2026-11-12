import { vi } from 'vitest';

export interface RecordedCall {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Headers;
  body: unknown;
  credentials: RequestCredentials | undefined;
}

export interface MockResponse {
  status?: number;
  body?: unknown;
}

type Handler = (call: RecordedCall) => MockResponse | Promise<MockResponse>;

export function json(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
  });
}

/**
 * Replaces `fetch` with a router keyed by `"METHOD /path"` (path relative to `/api/v1`).
 * A route can be one response, or a list consumed in order (the last one repeats).
 */
export function mockApi(routes: Record<string, MockResponse | Handler | (MockResponse | Handler)[]>) {
  const calls: RecordedCall[] = [];
  const counters = new Map<string, number>();

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(
      typeof input === 'string' ? input : input instanceof URL ? input.href : input.url,
      'http://localhost',
    );
    const method = (init?.method ?? 'GET').toUpperCase();
    const path = url.pathname.replace(/^\/api\/v1/, '');
    const call: RecordedCall = {
      method,
      path,
      query: url.searchParams,
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined,
      credentials: init?.credentials,
    };
    calls.push(call);
    const key = `${method} ${path}`;
    const route = routes[key];
    if (route === undefined) {
      return json(404, { error: 'not_found', message: `No mock for ${key}` });
    }
    let entry: MockResponse | Handler;
    if (Array.isArray(route)) {
      const n = counters.get(key) ?? 0;
      counters.set(key, n + 1);
      entry = route[Math.min(n, route.length - 1)] as MockResponse | Handler;
    } else {
      entry = route;
    }
    const result = typeof entry === 'function' ? await entry(call) : entry;
    return json(result.status ?? 200, result.body);
  });

  vi.stubGlobal('fetch', fetchMock);
  return {
    calls,
    fetchMock,
    callsTo: (key: string) => calls.filter((c) => `${c.method} ${c.path}` === key),
  };
}

export const ME = {
  user: { id: 'u-1', email: 'admin@example.test', displayName: 'Ada Admin', mustChangePassword: false },
  partner: { id: 'p-1', name: 'Northwind IT' },
  permissions: [
    'audit.read',
    'devices.manage',
    'devices.read',
    'devices.revoke',
    'enrollment.manage',
    'roles.manage',
    'tenants.manage',
    'tenants.read',
    'users.manage',
    'users.read',
  ],
  partnerWide: true,
  roles: [{ name: 'Partner Admin', scopeType: 'Partner' as const, scopeId: null }],
  csrfToken: 'csrf-from-me',
  stepUpFresh: false,
  sessionIdleMinutes: 30,
};

export const UNAUTHENTICATED: MockResponse = {
  status: 401,
  body: { error: 'unauthenticated', message: 'Sign in required.' },
};

export const STEP_UP_REQUIRED: MockResponse = {
  status: 401,
  body: { error: 'step_up_required', message: 'Re-enter your authenticator code to continue.' },
};
