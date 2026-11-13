/**
 * The `firewall.rules` policy check: the rule form and the same validation the server applies
 * (`server/src/Dranzo.Api/Features/FirewallRules.cs`, `agent/internal/firewall/rules.go`).
 */
export const FIREWALL_RULES_CHECK = 'firewall.rules';
export const MAX_FIREWALL_RULES = 100;

export interface FirewallRuleForm {
  name: string;
  direction: 'in' | 'out';
  action: 'allow' | 'block';
  protocol: 'tcp' | 'udp' | 'any';
  /** Comma or space separated: `443, 8000-8100`. */
  ports: string;
  /** Comma, space or line separated IPs or CIDR ranges. Empty = any address. */
  remoteAddresses: string;
  /** Full Windows path; Windows only. */
  program: string;
}

export interface FirewallRule {
  name: string;
  direction: 'in' | 'out';
  action: 'allow' | 'block';
  protocol: 'tcp' | 'udp' | 'any';
  ports?: string[];
  remoteAddresses?: string[];
  program?: string;
}

export const EMPTY_RULE: FirewallRuleForm = {
  name: '',
  direction: 'in',
  action: 'block',
  protocol: 'tcp',
  ports: '',
  remoteAddresses: '',
  program: '',
};

const NAME = /^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,63}$/;
// eslint-disable-next-line no-control-regex
const PROGRAM = /^[A-Za-z]:\\[^<>"|?*\u0000-\u001f]+$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function list(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function validPort(p: string): boolean {
  const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(p);
  if (!m) {
    return false;
  }
  const a = Number(m[1]);
  const b = m[2] === undefined ? a : Number(m[2]);
  return a >= 1 && b <= 65535 && a <= b;
}

export function validAddress(s: string): boolean {
  const [addr = '', prefix, extra] = s.split('/');
  if (extra !== undefined) {
    return false;
  }
  const v4 = IPV4.test(addr);
  const v6 = !v4 && addr.includes(':') && /^[0-9a-fA-F:.]+$/.test(addr) && !addr.includes(':::');
  if (!v4 && !v6) {
    return false;
  }
  if (prefix === undefined) {
    return true;
  }
  const bits = Number(prefix);
  return /^\d{1,3}$/.test(prefix) && bits >= 0 && bits <= (v4 ? 32 : 128);
}

export function rulesToForm(raw: unknown): FirewallRuleForm[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.map((r: Partial<FirewallRule>) => ({
    name: r.name ?? '',
    direction: r.direction === 'out' ? 'out' : 'in',
    action: r.action === 'allow' ? 'allow' : 'block',
    protocol: r.protocol === 'udp' || r.protocol === 'any' ? r.protocol : 'tcp',
    ports: (r.ports ?? []).join(', '),
    remoteAddresses: (r.remoteAddresses ?? []).join(', '),
    program: r.program ?? '',
  }));
}

/** The `rules` parameter, or the first problem found. */
export function buildFirewallRules(
  forms: FirewallRuleForm[],
): { ok: true; rules: FirewallRule[] } | { ok: false; error: string } {
  if (forms.length === 0) {
    return { ok: false, error: 'Add at least one rule.' };
  }
  if (forms.length > MAX_FIREWALL_RULES) {
    return { ok: false, error: `Use at most ${String(MAX_FIREWALL_RULES)} rules.` };
  }
  const rules: FirewallRule[] = [];
  for (const [i, f] of forms.entries()) {
    const label = `Rule ${String(i + 1)}${f.name.trim() ? ` (${f.name.trim()})` : ''}`;
    const name = f.name.trim();
    if (!NAME.test(name)) {
      return { ok: false, error: `${label}: give it a name of up to 64 letters, digits, spaces or ._()-` };
    }
    const ports = list(f.ports);
    if (ports.length > 0 && f.protocol === 'any') {
      return { ok: false, error: `${label}: ports need TCP or UDP.` };
    }
    if (ports.length > 32) {
      return { ok: false, error: `${label}: at most 32 ports.` };
    }
    const badPort = ports.find((p) => !validPort(p));
    if (badPort !== undefined) {
      return { ok: false, error: `${label}: "${badPort}" is not a port or range (use 443 or 8000-8100).` };
    }
    const addresses = list(f.remoteAddresses);
    if (addresses.length > 64) {
      return { ok: false, error: `${label}: at most 64 addresses.` };
    }
    const badAddress = addresses.find((a) => !validAddress(a));
    if (badAddress !== undefined) {
      return { ok: false, error: `${label}: "${badAddress}" is not an IP address or range.` };
    }
    const program = f.program.trim();
    if (program && (program.length > 260 || !PROGRAM.test(program))) {
      return {
        ok: false,
        error: `${label}: the program must be a full Windows path such as C:\\Program Files\\App\\app.exe.`,
      };
    }
    if (f.direction === 'out' && f.action === 'block' && ports.length === 0 && addresses.length === 0 && !program) {
      return {
        ok: false,
        error: `${label}: blocking all outgoing traffic would cut the device off. Use device isolation instead.`,
      };
    }
    rules.push({
      name,
      direction: f.direction,
      action: f.action,
      protocol: f.protocol,
      ...(ports.length > 0 ? { ports } : {}),
      ...(addresses.length > 0 ? { remoteAddresses: addresses } : {}),
      ...(program ? { program } : {}),
    });
  }
  return { ok: true, rules };
}

/** "Block in TCP 445 from 10.0.0.0/8" */
export function describeRule(r: FirewallRule): string {
  const ports = r.ports?.length ? ` ${r.ports.join(', ')}` : '';
  const proto = r.protocol === 'any' ? 'all traffic' : `${r.protocol.toUpperCase()}${ports}`;
  const where = r.remoteAddresses?.length
    ? ` ${r.direction === 'in' ? 'from' : 'to'} ${r.remoteAddresses.join(', ')}`
    : '';
  const program = r.program ? ` for ${r.program}` : '';
  return `${r.action === 'allow' ? 'Allow' : 'Block'} ${r.direction === 'in' ? 'incoming' : 'outgoing'} ${proto}${where}${program}`;
}
