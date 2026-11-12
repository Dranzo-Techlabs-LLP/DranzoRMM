import { describe, expect, it } from 'vitest';
import {
  describeRuleParams,
  paramsToForm,
  parseRecipients,
  parseRuleParams,
  ruleParamFields,
  validateChannel,
  type ChannelForm,
} from './rule-params';

describe('alert rule params', () => {
  it('has a minutes field for offline and a percent field for disk usage', () => {
    expect(ruleParamFields('device.offline').map((f) => f.key)).toEqual(['minutes']);
    expect(ruleParamFields('disk.usage').map((f) => f.key)).toEqual(['percent']);
    expect(ruleParamFields('firewall.off')).toEqual([]);
    expect(ruleParamFields('something.new')).toEqual([]);
  });

  it('fills the form from stored params, or from the server defaults', () => {
    expect(paramsToForm('device.offline', { minutes: 45 })).toEqual({ minutes: '45' });
    expect(paramsToForm('device.offline', null)).toEqual({ minutes: '30' });
    expect(paramsToForm('disk.usage', { percent: 'x' })).toEqual({ percent: '90' });
  });

  it('accepts values in range and builds the params object', () => {
    expect(parseRuleParams('device.offline', { minutes: ' 15 ' })).toEqual({ ok: true, params: { minutes: 15 } });
    expect(parseRuleParams('disk.usage', { percent: '92.5' })).toEqual({ ok: true, params: { percent: 92.5 } });
    expect(parseRuleParams('antivirus.off', {})).toEqual({ ok: true, params: {} });
  });

  it('refuses values the server would silently clamp', () => {
    for (const minutes of ['0', '43201', '1.5', '', 'abc', '-3']) {
      const r = parseRuleParams('device.offline', { minutes });
      expect(r.ok, minutes).toBe(false);
    }
    const disk = parseRuleParams('disk.usage', { percent: '101' });
    expect(disk.ok).toBe(false);
    if (!disk.ok) {
      expect(disk.errors.percent).toMatch(/1 to 100/);
    }
  });

  it('describes settings for the rules table', () => {
    expect(describeRuleParams('device.offline', { minutes: 10 })).toBe('Offline for 10 minutes');
    expect(describeRuleParams('disk.usage', {})).toBe('Used space at or above 90 percent');
  });
});

describe('notification channel form', () => {
  const base: ChannelForm = { type: 'email', name: 'Ops', recipients: '', url: '', secret: '', eventTypes: [] };

  it('splits recipients on commas, semicolons and new lines', () => {
    expect(parseRecipients('a@x.test, b@x.test;\nc@x.test a@x.test')).toEqual(['a@x.test', 'b@x.test', 'c@x.test']);
  });

  it('validates email recipients', () => {
    expect(validateChannel({ ...base, recipients: 'ops@example.test' }, false)).toEqual({
      ok: true,
      input: { name: 'Ops', to: ['ops@example.test'] },
    });
    expect(validateChannel({ ...base, recipients: 'not-an-address' }, false).ok).toBe(false);
    expect(validateChannel({ ...base, recipients: '' }, false).ok).toBe(false);
  });

  it('requires a URL for a new webhook but keeps the stored one when editing', () => {
    const hook: ChannelForm = { ...base, type: 'webhook', eventTypes: ['alert.opened'] };
    expect(validateChannel(hook, false).ok).toBe(false);
    expect(validateChannel({ ...hook, url: 'ftp://x' }, false).ok).toBe(false);
    expect(validateChannel({ ...hook, url: 'https://hooks.example.test/x', secret: 's3cret' }, false)).toEqual({
      ok: true,
      input: { name: 'Ops', url: 'https://hooks.example.test/x', secret: 's3cret', eventTypes: ['alert.opened'] },
    });
    // Editing with empty URL and secret sends neither, so the server keeps both.
    expect(validateChannel(hook, true)).toEqual({ ok: true, input: { name: 'Ops', eventTypes: ['alert.opened'] } });
  });

  it('does not send a secret or event types for Teams and Slack', () => {
    expect(validateChannel({ ...base, type: 'teams', url: 'https://x.test/hook', secret: 'ignored' }, false)).toEqual({
      ok: true,
      input: { name: 'Ops', url: 'https://x.test/hook' },
    });
  });
});
