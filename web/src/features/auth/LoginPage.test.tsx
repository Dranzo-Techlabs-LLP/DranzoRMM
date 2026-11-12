import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { api } from '@/lib/api';
import { ME, mockApi, UNAUTHENTICATED } from '@/test/mock-api';
import { renderApp } from '@/test/render';
import LoginPage from './LoginPage';

const routes = [
  { path: '/login', element: <LoginPage /> },
  { path: '/', element: <p>Overview page</p> },
  { path: '/devices', element: <p>Devices page</p> },
];

const RECOVERY_CODES = [
  'aaaa-1111',
  'bbbb-2222',
  'cccc-3333',
  'dddd-4444',
  'eeee-5555',
  'ffff-6666',
  'gggg-7777',
  'hhhh-8888',
  'iiii-9999',
  'jjjj-0000',
];

async function enterCredentials(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText('Email'), 'admin@example.test');
  await user.type(screen.getByLabelText('Password'), 'Dev-Only-Passw0rd-42');
  await user.click(screen.getByRole('button', { name: 'Continue' }));
}

describe('LoginPage: verify path (authenticator already set up)', () => {
  it('password → 6-digit code → dashboard, keeping the CSRF token in memory', async () => {
    const user = userEvent.setup();
    const server = mockApi({
      'GET /auth/me': [UNAUTHENTICATED, { body: ME }],
      'POST /auth/login': { body: { status: 'mfa_required', challengeToken: 'challenge-1' } },
      'POST /auth/mfa/verify': { body: { status: 'ok', csrfToken: 'csrf-from-verify' } },
    });
    renderApp(routes, '/login?returnTo=%2Fdevices');

    await enterCredentials(user);
    expect(server.callsTo('POST /auth/login')[0]?.body).toEqual({
      email: 'admin@example.test',
      password: 'Dev-Only-Passw0rd-42',
    });

    const code = await screen.findByLabelText('Authenticator code');
    await user.type(code, '123 456');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    // Lands on the page the user originally asked for.
    expect(await screen.findByText('Devices page')).toBeInTheDocument();
    expect(server.callsTo('POST /auth/mfa/verify')[0]?.body).toEqual({ challengeToken: 'challenge-1', code: '123456' });
    expect(api.getCsrfToken()).toBe('csrf-from-me');
    expect(window.localStorage.length).toBe(0);
  });

  it('shows a clear error for a wrong code and stays on the code step', async () => {
    const user = userEvent.setup();
    mockApi({
      'GET /auth/me': UNAUTHENTICATED,
      'POST /auth/login': { body: { status: 'mfa_required', challengeToken: 'challenge-1' } },
      'POST /auth/mfa/verify': { status: 401, body: { error: 'invalid_code', message: 'Invalid code.' } },
    });
    renderApp(routes, '/login');

    await enterCredentials(user);
    await user.type(await screen.findByLabelText('Authenticator code'), '000000');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByText(/That code was not accepted/)).toBeInTheDocument();
    expect(screen.getByLabelText('Authenticator code')).toBeInTheDocument();
  });

  it('accepts a recovery code instead of the authenticator', async () => {
    const user = userEvent.setup();
    const server = mockApi({
      'GET /auth/me': [UNAUTHENTICATED, { body: ME }],
      'POST /auth/login': { body: { status: 'mfa_required', challengeToken: 'challenge-1' } },
      'POST /auth/mfa/verify': { body: { status: 'ok', csrfToken: 'csrf' } },
    });
    renderApp(routes, '/login');

    await enterCredentials(user);
    await user.click(await screen.findByRole('button', { name: 'Use a recovery code' }));
    await user.type(screen.getByLabelText('Recovery code'), 'aaaa-1111');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByText('Overview page')).toBeInTheDocument();
    expect(server.callsTo('POST /auth/mfa/verify')[0]?.body).toEqual({
      challengeToken: 'challenge-1',
      recoveryCode: 'aaaa-1111',
    });
  });

  it('shows wrong-password and lockout messages from the server', async () => {
    const user = userEvent.setup();
    mockApi({
      'GET /auth/me': UNAUTHENTICATED,
      'POST /auth/login': [
        { status: 401, body: { error: 'invalid_credentials', message: 'Invalid email or password.' } },
        { status: 423, body: { error: 'locked', message: 'Account temporarily locked. Try again later.' } },
      ],
    });
    renderApp(routes, '/login');

    await enterCredentials(user);
    expect(await screen.findByText('Invalid email or password.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Continue' }));
    expect(await screen.findByText('Account temporarily locked. Try again later.')).toBeInTheDocument();
  });
});

describe('LoginPage: enrollment path (first sign-in)', () => {
  it('password → QR and key → code → recovery codes shown once → acknowledged → dashboard', async () => {
    const user = userEvent.setup();
    const server = mockApi({
      'GET /auth/me': [UNAUTHENTICATED, { body: ME }],
      'POST /auth/login': { body: { status: 'mfa_enrollment_required', challengeToken: 'challenge-2' } },
      'POST /auth/mfa/enroll/start': {
        body: {
          secret: 'JBSWY3DPEHPK3PXP',
          otpauthUri: 'otpauth://totp/DranzoRMM:admin%40example.test?secret=JBSWY3DPEHPK3PXP&issuer=DranzoRMM',
        },
      },
      'POST /auth/mfa/enroll/verify': {
        body: { status: 'ok', csrfToken: 'csrf-enroll', recoveryCodes: RECOVERY_CODES },
      },
    });
    renderApp(routes, '/login');

    await enterCredentials(user);

    // QR code plus the secret as text for people who cannot scan.
    expect(await screen.findByRole('img', { name: 'QR code for your authenticator app' })).toBeInTheDocument();
    expect(screen.getByText('JBSW Y3DP EHPK 3PXP')).toBeInTheDocument();
    expect(server.callsTo('POST /auth/mfa/enroll/start')).toHaveLength(1);
    expect(server.callsTo('POST /auth/mfa/enroll/start')[0]?.body).toEqual({ challengeToken: 'challenge-2' });

    // There is no way to skip: the only actions are verifying a code or starting again.
    expect(screen.queryByRole('button', { name: /skip|later|not now/i })).not.toBeInTheDocument();

    await user.type(screen.getByLabelText('Code from the app'), '654321');
    await user.click(screen.getByRole('button', { name: 'Turn on two-step sign-in' }));

    const list = await screen.findByRole('list', { name: 'Recovery codes' });
    expect(within(list).getAllByRole('listitem')).toHaveLength(10);
    expect(within(list).getByText('aaaa-1111')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Copy codes/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Download as text file/ })).toBeInTheDocument();
    expect(server.callsTo('POST /auth/mfa/enroll/verify')[0]?.body).toEqual({
      challengeToken: 'challenge-2',
      code: '654321',
    });

    // The dashboard stays out of reach until the user confirms the codes are saved.
    const proceed = screen.getByRole('button', { name: 'Continue to the dashboard' });
    expect(proceed).toBeDisabled();
    expect(screen.queryByText('Overview page')).not.toBeInTheDocument();

    await user.click(screen.getByRole('checkbox', { name: 'I saved these codes somewhere safe' }));
    expect(proceed).toBeEnabled();
    await user.click(proceed);

    expect(await screen.findByText('Overview page')).toBeInTheDocument();
    // The codes are gone from the page and were never written to storage.
    expect(screen.queryByText('aaaa-1111')).not.toBeInTheDocument();
    expect(window.localStorage.length).toBe(0);
  });

  it('returns to the password step when the sign-in attempt has expired', async () => {
    const user = userEvent.setup();
    mockApi({
      'GET /auth/me': UNAUTHENTICATED,
      'POST /auth/login': { body: { status: 'mfa_enrollment_required', challengeToken: 'old' } },
      'POST /auth/mfa/enroll/start': { status: 401, body: { error: 'invalid_challenge', message: 'Sign in again.' } },
    });
    renderApp(routes, '/login');

    await enterCredentials(user);
    expect(await screen.findByText(/Your sign-in attempt timed out/)).toBeInTheDocument();
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
  });
});

describe('LoginPage: already signed in', () => {
  it('goes straight to the return URL, ignoring unsafe targets', async () => {
    mockApi({ 'GET /auth/me': { body: ME } });
    renderApp(routes, '/login?returnTo=https%3A%2F%2Fevil.example%2F');
    await waitFor(() => {
      expect(screen.getByText('Overview page')).toBeInTheDocument();
    });
  });
});
