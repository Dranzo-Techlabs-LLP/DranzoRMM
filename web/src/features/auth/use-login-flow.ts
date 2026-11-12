import { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import { api, authApi, errorMessage, isApiError } from '@/lib/api';
import { initialLoginState, loginReducer, type LoginState } from './login-machine';

export interface LoginFlow {
  state: LoginState;
  pending: boolean;
  error: string | null;
  submitCredentials: (email: string, password: string) => Promise<void>;
  submitCode: (code: string) => Promise<void>;
  submitRecoveryCode: (recoveryCode: string) => Promise<void>;
  submitEnrollmentCode: (code: string) => Promise<void>;
  switchToRecoveryCode: () => void;
  switchToAuthenticator: () => void;
  confirmRecoveryCodesSaved: () => void;
  restart: () => void;
}

const INVALID_CODE = 'That code was not accepted. Codes change every 30 seconds, so wait for a new one and try again.';

/** Drives {@link loginReducer} with the auth endpoints. */
export function useLoginFlow(): LoginFlow {
  const [state, dispatch] = useReducer(loginReducer, initialLoginState);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const enrollStarted = useRef<string | null>(null);

  const run = useCallback(async (action: () => Promise<void>, describe?: (e: unknown) => string) => {
    setPending(true);
    setError(null);
    try {
      await action();
    } catch (e) {
      setError(describe ? describe(e) : errorMessage(e));
    } finally {
      setPending(false);
    }
  }, []);

  // Entering the enrollment step asks the server for a fresh secret (once per challenge).
  const enrollToken = state.step === 'enroll' && state.secret === null ? state.challengeToken : null;
  useEffect(() => {
    if (!enrollToken || enrollStarted.current === enrollToken) {
      return;
    }
    enrollStarted.current = enrollToken;
    void run(async () => {
      try {
        const r = await authApi.enrollStart(enrollToken);
        dispatch({ type: 'enrollment_started', secret: r.secret, otpauthUri: r.otpauthUri });
      } catch (e) {
        if (isApiError(e) && e.code === 'invalid_challenge') {
          dispatch({ type: 'challenge_expired' });
          return;
        }
        throw e;
      }
    });
  }, [enrollToken, run]);

  const describeCodeError = (e: unknown) =>
    isApiError(e) && e.code === 'invalid_code' ? INVALID_CODE : errorMessage(e);

  return {
    state,
    pending,
    error,
    submitCredentials: (email, password) =>
      run(async () => {
        const r = await authApi.login(email.trim(), password);
        dispatch({ type: 'password_accepted', status: r.status, challengeToken: r.challengeToken });
      }),
    submitCode: (code) =>
      run(async () => {
        if (state.step !== 'mfa') {
          return;
        }
        const r = await authApi.mfaVerify(state.challengeToken, { code });
        api.setCsrfToken(r.csrfToken);
        dispatch({ type: 'mfa_verified' });
      }, describeCodeError),
    submitRecoveryCode: (recoveryCode) =>
      run(
        async () => {
          if (state.step !== 'mfa') {
            return;
          }
          const r = await authApi.mfaVerify(state.challengeToken, { recoveryCode: recoveryCode.trim() });
          api.setCsrfToken(r.csrfToken);
          dispatch({ type: 'mfa_verified' });
        },
        (e) =>
          isApiError(e) && e.code === 'invalid_code'
            ? 'That recovery code was not accepted. Each code works once.'
            : errorMessage(e),
      ),
    submitEnrollmentCode: (code) =>
      run(async () => {
        if (state.step !== 'enroll') {
          return;
        }
        const r = await authApi.enrollVerify(state.challengeToken, code);
        api.setCsrfToken(r.csrfToken);
        dispatch({ type: 'enrollment_verified', recoveryCodes: r.recoveryCodes });
      }, describeCodeError),
    switchToRecoveryCode: () => {
      setError(null);
      dispatch({ type: 'use_recovery_code' });
    },
    switchToAuthenticator: () => {
      setError(null);
      dispatch({ type: 'use_authenticator' });
    },
    confirmRecoveryCodesSaved: () => {
      dispatch({ type: 'recovery_codes_saved' });
    },
    restart: () => {
      setError(null);
      enrollStarted.current = null;
      dispatch({ type: 'restart' });
    },
  };
}
