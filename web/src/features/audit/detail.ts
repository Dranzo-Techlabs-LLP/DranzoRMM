/**
 * Audit `detail` for display: indented JSON, or `null` when there is nothing to show. Current servers send a parsed
 * object; older ones sent JSON text, which is parsed when possible and otherwise shown exactly as stored.
 */
export function formatAuditDetail(detail: unknown): string | null {
  if (detail === null || detail === undefined || detail === '') {
    return null;
  }
  let value: unknown = detail;
  if (typeof detail === 'string') {
    try {
      value = JSON.parse(detail);
    } catch {
      return detail;
    }
  }
  if (value === null || (typeof value === 'object' && Object.keys(value).length === 0)) {
    return null;
  }
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

export function resultTone(result: string): 'ok' | 'danger' | 'warn' | 'idle' {
  switch (result.toLowerCase()) {
    case 'success':
      return 'ok';
    case 'denied':
    case 'failure':
    case 'failed':
    case 'error':
      return 'danger';
    default:
      return 'idle';
  }
}
