import QRCode from 'qrcode';
import { useMemo } from 'react';

/**
 * QR code drawn as SVG from the module matrix: no data URL, no injected HTML.
 * Always dark-on-white with a quiet zone so phone cameras read it in either theme.
 */
export function QrCode({ value, size = 184, label }: { value: string; size?: number; label: string }) {
  const { path, count } = useMemo(() => {
    const qr = QRCode.create(value, { errorCorrectionLevel: 'M' });
    const n = qr.modules.size;
    let d = '';
    for (let row = 0; row < n; row++) {
      for (let col = 0; col < n; col++) {
        if (qr.modules.get(row, col)) {
          d += `M${col} ${row}h1v1h-1z`;
        }
      }
    }
    return { path: d, count: n };
  }, [value]);

  const quiet = 4;
  const box = count + quiet * 2;
  return (
    <svg
      role="img"
      aria-label={label}
      width={size}
      height={size}
      viewBox={`${-quiet} ${-quiet} ${box} ${box}`}
      shapeRendering="crispEdges"
      className="rounded-md border"
    >
      <rect x={-quiet} y={-quiet} width={box} height={box} fill="#ffffff" />
      <path d={path} fill="#000000" />
    </svg>
  );
}
