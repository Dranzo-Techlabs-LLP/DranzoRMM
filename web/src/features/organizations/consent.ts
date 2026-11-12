import type { ConsentMode, UpdateRing } from '@/lib/api';

/** Plain-language explanation of what each remote-session consent mode means for the person at the computer. */
export const CONSENT: Record<ConsentMode, { label: string; explanation: string }> = {
  require: {
    label: 'Ask first',
    explanation:
      'The person at the computer must click Allow before a technician can connect. If nobody answers, the session does not start.',
  },
  notify: {
    label: 'Tell them',
    explanation:
      'The session starts straight away and the person at the computer sees a notice that a technician has connected.',
  },
  none: {
    label: 'No prompt',
    explanation:
      'The session starts without a prompt. An on-screen indicator is still shown for as long as the technician is connected.',
  },
};

export const RING: Record<UpdateRing, { label: string; explanation: string }> = {
  test: { label: 'Test', explanation: 'Gets agent updates first.' },
  pilot: { label: 'Pilot', explanation: 'Gets agent updates after the test ring.' },
  all: { label: 'Everyone', explanation: 'Gets agent updates last, once they are proven.' },
};
