import { Info } from 'lucide-react';
import { cn } from '@/lib/utils';

/** Limits of patching that technicians should know before they rely on it (SPEC Phase 4). */
export function KnownLimits({ className }: { className?: string }) {
  return (
    <details className={cn('bg-info-surface group rounded-md px-3 py-2 text-sm', className)}>
      <summary className="text-info flex cursor-pointer items-center gap-2 font-semibold">
        <Info aria-hidden="true" className="size-4 shrink-0" />
        Known limits
      </summary>
      <ul className="text-foreground mt-2 grid list-disc gap-1.5 pl-9">
        <li>
          <span className="font-medium">macOS on Apple Silicon:</span> some macOS updates (especially major upgrades and
          updates that need a restart) can only be installed after a person signed in at the Mac authorises them, or
          through an MDM. The agent reports them, but an install may stay pending until someone approves it on the Mac.
        </li>
        <li>
          <span className="font-medium">Windows third-party updates</span> come from winget. They appear only where
          winget is available to the SYSTEM account (it ships with App Installer on recent Windows 10 and 11; it is
          usually missing on Windows Server and on locked-down images).
        </li>
        <li>
          <span className="font-medium">Homebrew updates</span> install as the person signed in at the Mac, never as
          root. Without a signed-in user they are reported but not installed.
        </li>
        <li>
          <span className="font-medium">Linux</span> covers apt and dnf repositories that are already configured on the
          device. Snap and Flatpak packages update themselves and are not managed here.
        </li>
      </ul>
    </details>
  );
}
