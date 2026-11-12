import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { api, organizationsApi } from '@/lib/api';
import { mockApi, STEP_UP_REQUIRED } from '@/test/mock-api';
import { renderElement } from '@/test/render';
import { StepUpProvider } from './StepUpProvider';

function setup(routes: Parameters<typeof mockApi>[0]) {
  const server = mockApi(routes);
  renderElement(
    <StepUpProvider>
      <p>App</p>
    </StepUpProvider>,
  );
  api.setCsrfToken('csrf-1');
  return server;
}

describe('step-up dialog', () => {
  it('opens on step_up_required, verifies the code, then retries the original request once', async () => {
    const user = userEvent.setup();
    const server = setup({
      'DELETE /organizations/org-1': [STEP_UP_REQUIRED, { status: 204 }],
      'POST /auth/step-up': { body: { status: 'ok' } },
    });

    const pending = organizationsApi.remove('org-1');

    const dialog = await screen.findByRole('dialog', { name: 'Confirm it is you' });
    expect(dialog).toBeInTheDocument();
    const confirm = screen.getByRole('button', { name: 'Confirm and continue' });
    expect(confirm).toBeDisabled();

    await user.type(screen.getByLabelText('Authenticator code'), '123456');
    await user.click(confirm);

    await expect(pending).resolves.toBeUndefined();
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    expect(server.calls.map((c) => `${c.method} ${c.path}`)).toEqual([
      'DELETE /organizations/org-1',
      'POST /auth/step-up',
      'DELETE /organizations/org-1',
    ]);
    const stepUp = server.callsTo('POST /auth/step-up')[0];
    expect(stepUp?.body).toEqual({ code: '123456' });
    expect(stepUp?.headers.get('X-CSRF-Token')).toBe('csrf-1');
  });

  it('keeps the dialog open with an error when the code is wrong', async () => {
    const user = userEvent.setup();
    const server = setup({
      'DELETE /organizations/org-1': [STEP_UP_REQUIRED, { status: 204 }],
      'POST /auth/step-up': [
        { status: 401, body: { error: 'invalid_code', message: 'Invalid code.' } },
        { body: { status: 'ok' } },
      ],
    });

    const pending = organizationsApi.remove('org-1');
    await user.type(await screen.findByLabelText('Authenticator code'), '000000');
    await user.click(screen.getByRole('button', { name: 'Confirm and continue' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/That code was not accepted/);
    expect(server.callsTo('DELETE /organizations/org-1')).toHaveLength(1);

    await user.type(screen.getByLabelText('Authenticator code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm and continue' }));
    await expect(pending).resolves.toBeUndefined();
    expect(server.callsTo('DELETE /organizations/org-1')).toHaveLength(2);
  });

  it('cancelling rejects the original request without retrying it', async () => {
    const user = userEvent.setup();
    const server = setup({ 'DELETE /organizations/org-1': STEP_UP_REQUIRED });

    const pending = organizationsApi.remove('org-1').catch((e: unknown) => e);
    await screen.findByRole('dialog', { name: 'Confirm it is you' });
    await user.click(screen.getByRole('button', { name: 'Cancel' }));

    await expect(pending).resolves.toMatchObject({ code: 'step_up_cancelled' });
    expect(server.callsTo('DELETE /organizations/org-1')).toHaveLength(1);
    expect(server.callsTo('POST /auth/step-up')).toHaveLength(0);
  });
});
