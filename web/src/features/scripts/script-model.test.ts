import { describe, expect, it } from 'vitest';
import type { ScriptParameter } from '@/lib/api/scripts';
import { CRON_PRESETS, describeCron } from './cron';
import {
  allowedOs,
  buildParameterPayload,
  clampOsTargets,
  initialParameterValues,
  isWholeNumber,
  newParameterDraft,
  toScriptParameters,
  validateParameterDrafts,
  validateParameterValues,
} from './script-model';

const params: ScriptParameter[] = [
  { name: 'TARGET', type: 'string', required: true, default: null },
  { name: 'DAYS', type: 'int', required: true, default: '30' },
  { name: 'DRY_RUN', type: 'bool', required: false, default: null },
  { name: 'NOTE', type: 'string', required: false, default: null },
];

describe('script language and OS targets', () => {
  it('mirrors the server mapping', () => {
    expect(allowedOs('powershell')).toEqual(['windows']);
    expect(allowedOs('bash')).toEqual(['macos', 'linux']);
    expect(allowedOs('python')).toEqual(['windows', 'macos', 'linux']);
    expect(allowedOs('perl')).toEqual([]);
  });

  it('keeps only OS targets the new language supports, falling back to all of them', () => {
    expect(clampOsTargets('bash', ['windows', 'linux'])).toEqual(['linux']);
    expect(clampOsTargets('powershell', ['linux'])).toEqual(['windows']);
    expect(clampOsTargets('python', ['macos'])).toEqual(['macos']);
  });
});

describe('parameter definitions', () => {
  it('validates names like the server (environment variable names, unique ignoring case)', () => {
    const a = newParameterDraft({ name: 'retention_days' });
    const b = newParameterDraft({ name: 'RETENTION_DAYS' });
    const c = newParameterDraft({ name: '1bad' });
    const d = newParameterDraft({ name: '' });
    const e = newParameterDraft({ name: 'OK', type: 'int', default: 'ten' });
    const f = newParameterDraft({ name: 'FLAG', type: 'bool', default: 'true' });
    const errors = validateParameterDrafts([a, b, c, d, e, f]);
    expect(errors[a.key]?.name).toMatch(/already/);
    expect(errors[b.key]?.name).toMatch(/already/);
    expect(errors[c.key]?.name).toMatch(/letters/);
    expect(errors[d.key]?.name).toBe('Enter a name.');
    expect(errors[e.key]?.default).toMatch(/whole number/);
    expect(errors[f.key]).toBeUndefined();
  });

  it('serialises definitions with null for an empty default', () => {
    expect(
      toScriptParameters([
        newParameterDraft({ name: ' A ', type: 'int', default: ' 5 ', required: true }),
        newParameterDraft({ name: 'B' }),
      ]),
    ).toEqual([
      { name: 'A', type: 'int', required: true, default: '5' },
      { name: 'B', type: 'string', required: false, default: null },
    ]);
  });
});

describe('parameter form validation', () => {
  it('requires required values unless the script has a default', () => {
    const values = initialParameterValues(params);
    expect(values).toEqual({ TARGET: '', DAYS: '30', DRY_RUN: '', NOTE: '' });
    expect(validateParameterValues(params, values)).toEqual({ TARGET: 'This parameter is required.' });
    // DAYS has a default, so clearing it is fine: the server applies the default.
    expect(validateParameterValues(params, { ...values, TARGET: 'x', DAYS: '' })).toEqual({});
  });

  it('checks types on the client', () => {
    const base = { TARGET: 'x', DAYS: '30', DRY_RUN: '', NOTE: '' };
    expect(validateParameterValues(params, { ...base, DAYS: '3.5' }).DAYS).toMatch(/whole number/);
    expect(validateParameterValues(params, { ...base, DAYS: '12abc' }).DAYS).toMatch(/whole number/);
    expect(validateParameterValues(params, { ...base, DAYS: '-7' })).toEqual({});
    expect(validateParameterValues(params, { ...base, DRY_RUN: 'yes' }).DRY_RUN).toMatch(/true or false/);
    expect(validateParameterValues(params, { ...base, NOTE: 'x'.repeat(4097) }).NOTE).toMatch(/4096/);
  });

  it('accepts exactly the 64-bit whole numbers the server accepts', () => {
    expect(isWholeNumber('9223372036854775807')).toBe(true);
    expect(isWholeNumber('9223372036854775808')).toBe(false);
    expect(isWholeNumber('-9223372036854775808')).toBe(true);
    expect(isWholeNumber('+12')).toBe(true);
    expect(isWholeNumber('1e3')).toBe(false);
    expect(isWholeNumber('')).toBe(false);
  });

  it('builds the payload: typed values, empty ones left out for the server default', () => {
    expect(buildParameterPayload(params, { TARGET: 'C:\\Temp', DAYS: ' +45 ', DRY_RUN: 'false', NOTE: '' })).toEqual({
      TARGET: 'C:\\Temp',
      DAYS: '45',
      DRY_RUN: false,
    });
    expect(buildParameterPayload(params, { TARGET: ' padded ', DAYS: '', DRY_RUN: 'true', NOTE: '' })).toEqual({
      TARGET: ' padded ',
      DRY_RUN: true,
    });
  });
});

describe('cron preview', () => {
  it('reads common schedules', () => {
    expect(describeCron('0 2 * * *')).toEqual({ ok: true, exact: true, text: 'Every day at 02:00' });
    expect(describeCron('30 8 * * 1-5')).toMatchObject({ text: 'Monday to Friday at 08:30' });
    expect(describeCron('0 3 * * 0')).toMatchObject({ text: 'Every Sunday at 03:00' });
    expect(describeCron('0 3 * * 7')).toMatchObject({ text: 'Every Sunday at 03:00' });
    expect(describeCron('0 22 * * MON,WED,FRI')).toMatchObject({
      text: 'Every Monday, Wednesday and Friday at 22:00',
    });
    expect(describeCron('0 1 1 * *')).toMatchObject({ text: 'On the 1st of every month at 01:00' });
    expect(describeCron('15 6 1,15 JAN *')).toMatchObject({ text: 'On the 1st and 15th of January at 06:15' });
    expect(describeCron('*/15 * * * *')).toMatchObject({ text: 'Every 15 minutes, every day' });
    expect(describeCron('0 * * * *')).toMatchObject({ text: 'Every hour on the hour, every day' });
    expect(describeCron('0 9,17 * * 6,0')).toMatchObject({ text: 'Saturday and Sunday at 09:00 and 17:00' });
  });

  it('accepts but does not summarise unusual expressions', () => {
    expect(describeCron('0 0 L * *')).toMatchObject({ ok: true, exact: false });
    expect(describeCron('0 0 1 * 1')).toMatchObject({ ok: true, exact: false });
    expect(describeCron('0,30 * * * *')).toMatchObject({ ok: true, exact: false });
    expect(describeCron('5-10/2 3 * * *')).toMatchObject({ text: 'Every day at 03:05, 03:07 and 03:09' });
  });

  it('explains mistakes', () => {
    expect(describeCron('')).toEqual({ ok: false, error: 'Enter a schedule.' });
    expect(describeCron('0 2 * *')).toMatchObject({ ok: false, error: expect.stringMatching(/five fields/) });
    expect(describeCron('60 2 * * *')).toMatchObject({ ok: false, error: expect.stringMatching(/minute/) });
    expect(describeCron('0 25 * * *')).toMatchObject({ ok: false, error: expect.stringMatching(/hour/) });
    expect(describeCron('0 2 * 13 *')).toMatchObject({ ok: false, error: expect.stringMatching(/month/) });
    expect(describeCron('0 5-2 * * *')).toMatchObject({ ok: false, error: expect.stringMatching(/backwards/) });
    expect(describeCron('*/0 * * * *')).toMatchObject({ ok: false, error: expect.stringMatching(/step/) });
  });

  it('every preset reads exactly', () => {
    for (const p of CRON_PRESETS) {
      expect(describeCron(p.cron), p.cron).toMatchObject({ ok: true, exact: true });
    }
  });
});
