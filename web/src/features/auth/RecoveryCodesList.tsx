import { Download } from 'lucide-react';
import { CopyButton } from '@/components/copy-button';
import { Button } from '@/components/ui/button';

function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Recovery codes, shown once, with copy and download. Used at enrollment and when codes are regenerated. */
export function RecoveryCodesList({ codes }: { codes: string[] }) {
  const text = codes.join('\n');
  return (
    <>
      <ul aria-label="Recovery codes" className="bg-muted mb-3 grid grid-cols-2 gap-x-6 gap-y-1.5 rounded-md px-4 py-3">
        {codes.map((c) => (
          <li key={c} className="ident select-all">
            {c}
          </li>
        ))}
      </ul>
      <div className="mb-5 flex flex-wrap gap-2">
        <CopyButton value={text} label="Copy codes" />
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            downloadText(
              'dranzo-recovery-codes.txt',
              `DranzoRMM recovery codes\nEach code works once. Keep them somewhere safe.\n\n${text}\n`,
            );
          }}
        >
          <Download aria-hidden="true" />
          Download as text file
        </Button>
      </div>
    </>
  );
}
