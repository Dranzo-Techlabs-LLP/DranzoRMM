import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { OutputViewer } from './OutputViewer';

describe('OutputViewer', () => {
  it('renders output as text, marks stderr, and shows the truncation banner', () => {
    const { container } = render(
      <OutputViewer
        chunks={[
          { seq: 0, stream: 'stdout', data: '<img src=x onerror=alert(1)>\u001b[31mred\u001b[0m\n' },
          { seq: 1, stream: 'stderr', data: 'boom\n' },
        ]}
        active={false}
        truncated
        maxOutputBytes={1024}
        fileName="out.txt"
        statusText="Succeeded."
      />,
    );
    const region = screen.getByRole('region', { name: 'Output text' });
    expect(region.querySelector('img')).toBeNull();
    expect(within(region).getByText(/<img src=x onerror=alert\(1\)>red/)).toBeInTheDocument();
    expect(region.textContent).not.toContain('\u001b');
    expect(container.querySelector('[data-stream="stderr"]')?.textContent).toBe('Error output: boom\n');
    expect(screen.getByRole('alert')).toHaveTextContent(/Output truncated.*1\.0 KB/);
    // Only the short status line is announced, not the output itself.
    expect(screen.getByRole('status')).toHaveTextContent('Succeeded. · 2 lines');
    expect(region).not.toHaveAttribute('aria-live');
  });

  it('says when there is no output yet', () => {
    render(<OutputViewer chunks={[]} active truncated={false} fileName="o.txt" statusText="Waiting." />);
    expect(screen.getByText('No output yet.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Pause scrolling' })).toHaveAttribute('aria-pressed', 'true');
  });
});
