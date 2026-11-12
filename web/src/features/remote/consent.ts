import type { ConsentMode } from '@/lib/api';

/**
 * What the person at the computer experiences when a technician connects, in plain words (docs/SPEC.md section 1,
 * docs/PROTOCOL.md section 6.5). The on-screen indicator is part of every mode: there is no silent session.
 */
export const INDICATOR_NOTICE =
  'While the session is open, the computer shows an on-screen indicator with your name, and the person there can end the session at any time.';

export function consentNotice(mode: ConsentMode | null): string {
  switch (mode) {
    case 'require':
      return 'The person at this computer will be asked to allow this. If they decline, or do not answer within a minute, the session does not start. If nobody is logged in, there is nobody to ask and the session starts.';
    case 'notify':
      return 'The person at this computer will be notified that you are connecting. The session starts straight away.';
    case 'none':
      return 'This organization does not ask or notify before a session starts. The person at this computer will see an on-screen indicator.';
    default:
      return "Depending on the organization's setting, the person at this computer is asked to allow the session, notified, or shown only the on-screen indicator.";
  }
}

export const CONSENT_MODE_LABEL: Record<string, string> = {
  require: 'Ask first',
  notify: 'Notify',
  none: 'Indicator only',
};

export const CONSENT_RESULT_LABEL: Record<string, string> = {
  accepted: 'Allowed by the user',
  notified: 'User notified',
  not_required: 'Not asked',
  no_user_logged_in: 'Nobody logged in',
  denied: 'Declined by the user',
  timeout: 'No answer',
};

export const KIND_LABEL: Record<string, string> = {
  terminal: 'Terminal',
  files: 'Files',
  desktop: 'Desktop',
};
