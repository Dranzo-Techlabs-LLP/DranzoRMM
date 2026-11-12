import { toast } from 'sonner';
import { errorMessage, isApiError } from '@/lib/api';

/** Toast for a failed mutation. Cancelled step-ups are informational; a lost session is handled by the redirect. */
export function notifyError(error: unknown): void {
  if (isApiError(error)) {
    if (error.code === 'unauthenticated') {
      return;
    }
    if (error.code === 'step_up_cancelled') {
      toast.info(error.message);
      return;
    }
  }
  toast.error(errorMessage(error));
}

export function notifySuccess(message: string): void {
  toast.success(message);
}
