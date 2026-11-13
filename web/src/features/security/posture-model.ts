import type { PostureRow } from '@/lib/api/security';

export const VULN_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

/** NVD detail page for a well-formed CVE id; `null` for anything else, so odd ids are never put into a link. */
export function nvdUrl(cveId: string): string | null {
  return /^CVE-\d{4}-\d{4,}$/.test(cveId) ? `https://nvd.nist.gov/vuln/detail/${cveId}` : null;
}

export type PostureFilter =
  '' | 'antivirus' | 'firewall' | 'encryption' | 'not-reporting' | 'known-exploited' | 'low-score';

/** Scores below this count as low. */
export const LOW_SCORE = 60;

/** Colour for a score: green from 75, amber from 60, red below; grey without a score. */
export function scoreTone(score: number | null): 'ok' | 'warn' | 'danger' | 'idle' {
  if (score === null) {
    return 'idle';
  }
  return score >= 75 ? 'ok' : score >= LOW_SCORE ? 'warn' : 'danger';
}

export function matchesPostureFilter(row: PostureRow, filter: PostureFilter): boolean {
  switch (filter) {
    case 'antivirus':
      return row.antivirusOk === false;
    case 'firewall':
      return row.firewallOk === false;
    case 'encryption':
      return row.encryptionOk === false;
    case 'not-reporting':
      return row.collectedAt === null;
    case 'known-exploited':
      return row.knownExploited > 0;
    case 'low-score':
      return row.score !== null && row.score < LOW_SCORE;
    default:
      return true;
  }
}
