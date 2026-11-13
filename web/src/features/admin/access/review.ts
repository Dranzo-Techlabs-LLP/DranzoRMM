import type { AccessPrincipal } from '@/lib/api/access';

/** Status label for one user or API key. */
export function principalStatus(p: AccessPrincipal): { label: string; tone: 'ok' | 'warn' | 'idle' } {
  if (p.disabled) {
    return { label: p.kind === 'apikey' ? 'Expired' : 'Disabled', tone: 'idle' };
  }
  if (p.locked) {
    return { label: 'Locked', tone: 'warn' };
  }
  return { label: 'Active', tone: 'ok' };
}

/** Summary counts shown above the table. */
export function reviewSummary(rows: AccessPrincipal[]) {
  const active = rows.filter((p) => !p.disabled);
  return {
    users: rows.filter((p) => p.kind === 'user').length,
    apiKeys: rows.filter((p) => p.kind === 'apikey').length,
    withFindings: active.filter((p) => p.findings.length > 0).length,
    fullAdmins: active.filter((p) => p.findings.some((f) => f.startsWith('Full admin'))).length,
  };
}
