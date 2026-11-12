import type { PostureRow } from '@/lib/api/security';

export const VULN_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

/** NVD detail page for a well-formed CVE id; `null` for anything else, so odd ids are never put into a link. */
export function nvdUrl(cveId: string): string | null {
  return /^CVE-\d{4}-\d{4,}$/.test(cveId) ? `https://nvd.nist.gov/vuln/detail/${cveId}` : null;
}

export type PostureFilter = '' | 'antivirus' | 'firewall' | 'encryption' | 'not-reporting' | 'known-exploited';

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
    default:
      return true;
  }
}
