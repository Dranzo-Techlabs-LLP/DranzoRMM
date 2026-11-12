/**
 * Sign-in flow as a pure state machine. MFA is mandatory: there is no transition that reaches `done` without
 * either verifying a code or completing enrollment and acknowledging the recovery codes.
 *
 *   credentials ──password ok──▶ mfa ──code / recovery code ok──▶ done
 *        │
 *        └──password ok, no authenticator yet──▶ enroll ──code ok──▶ recovery-codes ──"I saved them"──▶ done
 */
export type LoginState =
  | { step: 'credentials'; notice?: string }
  | { step: 'mfa'; challengeToken: string; method: 'code' | 'recovery' }
  | { step: 'enroll'; challengeToken: string; secret: string | null; otpauthUri: string | null }
  | { step: 'recovery-codes'; codes: string[] }
  | { step: 'done' };

export type LoginEvent =
  | { type: 'password_accepted'; status: 'mfa_required' | 'mfa_enrollment_required'; challengeToken: string }
  | { type: 'enrollment_started'; secret: string; otpauthUri: string }
  | { type: 'use_recovery_code' }
  | { type: 'use_authenticator' }
  | { type: 'mfa_verified' }
  | { type: 'enrollment_verified'; recoveryCodes: string[] }
  | { type: 'recovery_codes_saved' }
  | { type: 'challenge_expired' }
  | { type: 'restart' };

export const initialLoginState: LoginState = { step: 'credentials' };

export const CHALLENGE_EXPIRED_NOTICE = 'Your sign-in attempt timed out. Enter your email and password again.';

export function loginReducer(state: LoginState, event: LoginEvent): LoginState {
  switch (event.type) {
    case 'password_accepted':
      if (state.step !== 'credentials') {
        return state;
      }
      return event.status === 'mfa_required'
        ? { step: 'mfa', challengeToken: event.challengeToken, method: 'code' }
        : { step: 'enroll', challengeToken: event.challengeToken, secret: null, otpauthUri: null };
    case 'enrollment_started':
      return state.step === 'enroll' ? { ...state, secret: event.secret, otpauthUri: event.otpauthUri } : state;
    case 'use_recovery_code':
      return state.step === 'mfa' ? { ...state, method: 'recovery' } : state;
    case 'use_authenticator':
      return state.step === 'mfa' ? { ...state, method: 'code' } : state;
    case 'mfa_verified':
      return state.step === 'mfa' ? { step: 'done' } : state;
    case 'enrollment_verified':
      // Enrollment must have shown the secret before a code can be accepted.
      return state.step === 'enroll' && state.secret !== null
        ? { step: 'recovery-codes', codes: event.recoveryCodes }
        : state;
    case 'recovery_codes_saved':
      return state.step === 'recovery-codes' ? { step: 'done' } : state;
    case 'challenge_expired':
      return state.step === 'mfa' || state.step === 'enroll'
        ? { step: 'credentials', notice: CHALLENGE_EXPIRED_NOTICE }
        : state;
    case 'restart':
      // Recovery codes are shown once; leaving that step without acknowledging would lose them.
      return state.step === 'recovery-codes' || state.step === 'done' ? state : { step: 'credentials' };
  }
}

/** Authenticator codes are 6 digits; users often paste them with spaces. */
export function normalizeTotp(input: string): string {
  return input.replace(/\D/g, '').slice(0, 6);
}

export function isCompleteTotp(code: string): boolean {
  return /^\d{6}$/.test(code);
}
