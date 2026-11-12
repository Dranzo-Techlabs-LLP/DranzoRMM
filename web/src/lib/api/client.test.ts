import { describe, expect, it, vi } from 'vitest';
import { ApiClient, buildUrl } from './client';
import { ApiError } from './errors';

type FetchArgs = [input: RequestInfo | URL, init?: RequestInit];

function json(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
  });
}

function clientWith(...responses: (Response | (() => Response))[]) {
  const queue = [...responses];
  const fetchMock = vi.fn((..._args: FetchArgs) => {
    const next = queue.shift();
    if (!next) {
      throw new Error('Unexpected extra fetch call');
    }
    return Promise.resolve(typeof next === 'function' ? next() : next);
  });
  const client = new ApiClient(fetchMock as unknown as typeof fetch);
  const request = (i: number) => {
    const [url, init] = fetchMock.mock.calls[i]!;
    return { url: String(url), init: init!, headers: new Headers(init!.headers) };
  };
  return { client, fetchMock, request };
}

const STEP_UP = { error: 'step_up_required', message: 'Re-enter your authenticator code to continue.' };

describe('ApiClient: request basics', () => {
  it('sends same-origin credentials, JSON bodies, and never caches', async () => {
    const { client, request } = clientWith(json(200, { id: '1' }));
    client.setCsrfToken('tok');
    await client.post('/organizations', { name: 'Acme' });
    const r = request(0);
    expect(r.url).toBe('/api/v1/organizations');
    expect(r.init.credentials).toBe('same-origin');
    expect(r.init.cache).toBe('no-store');
    expect(r.headers.get('Content-Type')).toBe('application/json');
    expect(r.init.body).toBe('{"name":"Acme"}');
  });

  it('builds query strings without empty values', () => {
    expect(buildUrl('/devices', { search: 'web', os: '', online: false, page: 2, tag: undefined, siteId: null })).toBe(
      '/api/v1/devices?search=web&online=false&page=2',
    );
    expect(buildUrl('/devices')).toBe('/api/v1/devices');
  });

  it('returns undefined for 204 responses', async () => {
    const { client } = clientWith(json(204));
    await expect(client.delete('/sites/1')).resolves.toBeUndefined();
  });

  it('turns {error, message} bodies into ApiError', async () => {
    const { client } = clientWith(json(409, { error: 'conflict', message: 'Move or remove the devices first.' }));
    const error = await client.delete('/sites/1').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 409, code: 'conflict', message: 'Move or remove the devices first.' });
  });

  it('gives a readable error for empty error bodies (rate limiter)', async () => {
    const { client } = clientWith(json(429));
    await expect(client.get('/devices')).rejects.toMatchObject({ status: 429, code: 'rate_limited' });
  });

  it('reports network failures as ApiError', async () => {
    const client = new ApiClient((() => Promise.reject(new TypeError('Failed to fetch'))) as unknown as typeof fetch);
    await expect(client.get('/devices')).rejects.toMatchObject({ status: 0, code: 'network' });
  });
});

describe('ApiClient: CSRF', () => {
  it.each(['POST', 'PATCH', 'PUT', 'DELETE'])('sends X-CSRF-Token on %s', async (method) => {
    const { client, request } = clientWith(json(204));
    client.setCsrfToken('csrf-123');
    await client.request(method, '/things/1', { body: {} });
    expect(request(0).headers.get('X-CSRF-Token')).toBe('csrf-123');
  });

  it.each(['GET', 'HEAD'])('does not send X-CSRF-Token on %s', async (method) => {
    const { client, request } = clientWith(json(200, {}));
    client.setCsrfToken('csrf-123');
    await client.request(method, '/things');
    expect(request(0).headers.has('X-CSRF-Token')).toBe(false);
  });

  it('refreshes a stale token from /auth/me once and retries', async () => {
    const { client, fetchMock, request } = clientWith(
      json(403, { error: 'csrf', message: 'Missing or invalid CSRF token.' }),
      json(200, { csrfToken: 'fresh' }),
      json(204),
    );
    client.setCsrfToken('stale');
    await client.post('/sites', { name: 'HQ' });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(request(1).url).toBe('/api/v1/auth/me');
    expect(request(2).headers.get('X-CSRF-Token')).toBe('fresh');
  });

  it('does not loop when the token is still rejected', async () => {
    const csrf = () => json(403, { error: 'csrf', message: 'Missing or invalid CSRF token.' });
    const { client, fetchMock } = clientWith(csrf, json(200, { csrfToken: 'fresh' }), csrf);
    await expect(client.post('/sites', {})).rejects.toMatchObject({ status: 403, code: 'csrf' });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});

describe('ApiClient: step-up', () => {
  it('asks for step-up on 401 step_up_required and retries the original request once', async () => {
    const { client, fetchMock, request } = clientWith(json(401, STEP_UP), json(204));
    client.setCsrfToken('tok');
    const requestStepUp = vi.fn(() => Promise.resolve(true));
    client.configure({ requestStepUp });

    await expect(client.delete('/organizations/42')).resolves.toBeUndefined();

    expect(requestStepUp).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(request(1).url).toBe('/api/v1/organizations/42');
    expect(request(1).init.method).toBe('DELETE');
    expect(request(1).headers.get('X-CSRF-Token')).toBe('tok');
  });

  it('retries only once: a second step_up_required is returned as an error', async () => {
    const { client, fetchMock } = clientWith(json(401, STEP_UP), json(401, STEP_UP));
    const requestStepUp = vi.fn(() => Promise.resolve(true));
    client.configure({ requestStepUp });

    await expect(client.delete('/organizations/42')).rejects.toMatchObject({ status: 401, code: 'step_up_required' });
    expect(requestStepUp).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not retry when the user cancels', async () => {
    const { client, fetchMock } = clientWith(json(401, STEP_UP));
    const onUnauthenticated = vi.fn();
    client.configure({ requestStepUp: () => Promise.resolve(false), onUnauthenticated });

    await expect(client.delete('/organizations/42')).rejects.toMatchObject({ code: 'step_up_cancelled' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(onUnauthenticated).not.toHaveBeenCalled();
  });

  it('shares one prompt between concurrent requests', async () => {
    const { client, fetchMock } = clientWith(json(401, STEP_UP), json(401, STEP_UP), json(204), json(204));
    let confirm: (ok: boolean) => void = () => undefined;
    const requestStepUp = vi.fn(() => new Promise<boolean>((resolve) => (confirm = resolve)));
    client.configure({ requestStepUp });

    const both = Promise.all([client.delete('/users/1'), client.delete('/users/2')]);
    await vi.waitFor(() => expect(requestStepUp).toHaveBeenCalled());
    confirm(true);
    await both;

    expect(requestStepUp).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('never prompts for the step-up call itself', async () => {
    const { client } = clientWith(json(401, STEP_UP));
    const requestStepUp = vi.fn(() => Promise.resolve(true));
    client.configure({ requestStepUp });
    await expect(client.post('/auth/step-up', { code: '123456' }, { noStepUp: true })).rejects.toMatchObject({
      code: 'step_up_required',
    });
    expect(requestStepUp).not.toHaveBeenCalled();
  });

  it('treats step_up_required as an error when no dialog is registered', async () => {
    const { client } = clientWith(json(401, STEP_UP));
    await expect(client.delete('/users/1')).rejects.toMatchObject({ code: 'step_up_cancelled' });
  });
});

describe('ApiClient: session loss', () => {
  const UNAUTH = { error: 'unauthenticated', message: 'Sign in required.' };

  it('notifies the app on 401 unauthenticated and forgets the CSRF token', async () => {
    const { client } = clientWith(json(401, UNAUTH));
    const onUnauthenticated = vi.fn();
    client.configure({ onUnauthenticated });
    client.setCsrfToken('tok');

    await expect(client.get('/devices')).rejects.toMatchObject({ status: 401, code: 'unauthenticated' });
    expect(onUnauthenticated).toHaveBeenCalledTimes(1);
    expect(client.getCsrfToken()).toBeNull();
  });

  it('does not treat sign-in failures as a lost session', async () => {
    const { client } = clientWith(
      json(401, { error: 'invalid_credentials', message: 'Invalid email or password.' }),
      json(401, UNAUTH),
    );
    const onUnauthenticated = vi.fn();
    client.configure({ onUnauthenticated });

    await expect(client.post('/auth/login', {}, { anonymous: true })).rejects.toMatchObject({
      code: 'invalid_credentials',
    });
    await expect(client.get('/auth/me', { anonymous: true })).rejects.toMatchObject({ code: 'unauthenticated' });
    expect(onUnauthenticated).not.toHaveBeenCalled();
  });

  it('configure() returns a function that removes only its own handlers', () => {
    const client = new ApiClient((() => Promise.resolve(json(401, UNAUTH))) as unknown as typeof fetch);
    const first = vi.fn();
    const second = vi.fn();
    const removeFirst = client.configure({ onUnauthenticated: first });
    client.configure({ onUnauthenticated: second });
    removeFirst(); // must not remove the newer handler
    return client.get('/devices').catch(() => {
      expect(first).not.toHaveBeenCalled();
      expect(second).toHaveBeenCalledTimes(1);
    });
  });
});
