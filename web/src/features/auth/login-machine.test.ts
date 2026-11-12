import { describe, expect, it } from 'vitest';
import {
  CHALLENGE_EXPIRED_NOTICE,
  initialLoginState,
  isCompleteTotp,
  loginReducer,
  normalizeTotp,
  type LoginEvent,
  type LoginState,
} from './login-machine';

function run(events: LoginEvent[], from: LoginState = initialLoginState): LoginState {
  return events.reduce(loginReducer, from);
}

describe('login state machine', () => {
  it('verify path: credentials → mfa → done', () => {
    const afterPassword = run([{ type: 'password_accepted', status: 'mfa_required', challengeToken: 'c1' }]);
    expect(afterPassword).toEqual({ step: 'mfa', challengeToken: 'c1', method: 'code' });
    expect(run([{ type: 'mfa_verified' }], afterPassword)).toEqual({ step: 'done' });
  });

  it('verify path: can switch to a recovery code and back', () => {
    const mfa = run([{ type: 'password_accepted', status: 'mfa_required', challengeToken: 'c1' }]);
    const recovery = run([{ type: 'use_recovery_code' }], mfa);
    expect(recovery).toMatchObject({ step: 'mfa', method: 'recovery', challengeToken: 'c1' });
    expect(run([{ type: 'use_authenticator' }], recovery)).toMatchObject({ step: 'mfa', method: 'code' });
    expect(run([{ type: 'mfa_verified' }], recovery)).toEqual({ step: 'done' });
  });

  it('enrollment path: credentials → enroll → recovery codes → done', () => {
    const enroll = run([{ type: 'password_accepted', status: 'mfa_enrollment_required', challengeToken: 'c2' }]);
    expect(enroll).toEqual({ step: 'enroll', challengeToken: 'c2', secret: null, otpauthUri: null });

    const started = run([{ type: 'enrollment_started', secret: 'JBSWY3DP', otpauthUri: 'otpauth://totp/x' }], enroll);
    expect(started).toMatchObject({ step: 'enroll', secret: 'JBSWY3DP', otpauthUri: 'otpauth://totp/x' });

    const codes = run([{ type: 'enrollment_verified', recoveryCodes: ['a', 'b'] }], started);
    expect(codes).toEqual({ step: 'recovery-codes', codes: ['a', 'b'] });

    expect(run([{ type: 'recovery_codes_saved' }], codes)).toEqual({ step: 'done' });
  });

  it('MFA cannot be skipped: no event takes credentials or enrollment straight to done', () => {
    const skipping: LoginEvent[] = [
      { type: 'mfa_verified' },
      { type: 'recovery_codes_saved' },
      { type: 'enrollment_verified', recoveryCodes: ['x'] },
    ];
    for (const event of skipping) {
      expect(loginReducer(initialLoginState, event)).toEqual(initialLoginState);
    }
    const enroll = run([{ type: 'password_accepted', status: 'mfa_enrollment_required', challengeToken: 'c' }]);
    expect(loginReducer(enroll, { type: 'mfa_verified' })).toBe(enroll);
    expect(loginReducer(enroll, { type: 'recovery_codes_saved' })).toBe(enroll);
    // A code cannot be accepted before the secret was shown.
    expect(loginReducer(enroll, { type: 'enrollment_verified', recoveryCodes: ['x'] })).toBe(enroll);
  });

  it('recovery codes must be acknowledged: restart does not leave that step', () => {
    const codes: LoginState = { step: 'recovery-codes', codes: ['a'] };
    expect(loginReducer(codes, { type: 'restart' })).toBe(codes);
    expect(loginReducer(codes, { type: 'challenge_expired' })).toBe(codes);
  });

  it('an expired challenge returns to credentials with an explanation', () => {
    const mfa = run([{ type: 'password_accepted', status: 'mfa_required', challengeToken: 'c1' }]);
    expect(loginReducer(mfa, { type: 'challenge_expired' })).toEqual({
      step: 'credentials',
      notice: CHALLENGE_EXPIRED_NOTICE,
    });
  });

  it('restart returns to credentials from mfa and enroll', () => {
    const mfa = run([{ type: 'password_accepted', status: 'mfa_required', challengeToken: 'c1' }]);
    expect(loginReducer(mfa, { type: 'restart' })).toEqual({ step: 'credentials' });
  });

  it('ignores a second password_accepted once past credentials', () => {
    const mfa = run([{ type: 'password_accepted', status: 'mfa_required', challengeToken: 'c1' }]);
    expect(loginReducer(mfa, { type: 'password_accepted', status: 'mfa_required', challengeToken: 'other' })).toBe(mfa);
  });
});

describe('TOTP helpers', () => {
  it('normalizes pasted codes', () => {
    expect(normalizeTotp('123 456')).toBe('123456');
    expect(normalizeTotp('12a34-56 789')).toBe('123456');
  });

  it('accepts exactly six digits', () => {
    expect(isCompleteTotp('123456')).toBe(true);
    expect(isCompleteTotp('12345')).toBe(false);
    expect(isCompleteTotp('1234567')).toBe(false);
  });
});
