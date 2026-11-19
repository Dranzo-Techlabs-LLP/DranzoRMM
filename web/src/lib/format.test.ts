import { describe, expect, it } from 'vitest';
import { currentUptimeSeconds, formatDuration } from './format';

describe('currentUptimeSeconds', () => {
  const now = Date.parse('2026-11-19T12:00:00Z');

  it('counts from the boot time while the device is online', () => {
    // The inventory said 0 s (collected right after a reboot); three hours later the uptime is three hours.
    expect(currentUptimeSeconds('2026-11-19T09:00:00Z', 0, true, now)).toBe(3 * 3600);
    expect(formatDuration(currentUptimeSeconds('2026-11-19T09:00:00Z', 0, true, now))).toBe('3h 0m');
  });

  it('keeps the last reported value while the device is offline', () => {
    expect(currentUptimeSeconds('2026-11-19T09:00:00Z', 120, false, now)).toBe(120);
  });

  it('falls back to the reported value when the boot time is missing, invalid or in the future', () => {
    expect(currentUptimeSeconds(undefined, 60, true, now)).toBe(60);
    expect(currentUptimeSeconds('not a date', 60, true, now)).toBe(60);
    expect(currentUptimeSeconds('2026-11-19T13:00:00Z', 60, true, now)).toBe(60);
    expect(currentUptimeSeconds(null, null, true, now)).toBeUndefined();
  });
});
