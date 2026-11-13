import type { NetworkDevice, NetworkDeviceStatus } from '@/lib/api/network';

export const STATUS_LABEL: Record<NetworkDeviceStatus, string> = {
  unknown: 'Not reviewed',
  approved: 'Approved',
  blocked: 'Blocked',
};

export const STATUS_TONE = { unknown: 'warn', approved: 'ok', blocked: 'danger' } as const;

/** Best name for a discovered device: managed hostname, then reverse DNS, then the MAC. */
export function displayName(d: NetworkDevice): string {
  return d.managedHostname ?? d.hostname ?? d.mac;
}

/** Short description of what kind of device this probably is. */
export function deviceKind(d: NetworkDevice): string {
  if (d.isGateway) {
    return 'Router / gateway';
  }
  if (d.managedDeviceId) {
    return 'Managed by DranzoRMM';
  }
  if (d.randomized) {
    return 'Private address (phone or laptop)';
  }
  return d.vendor ?? 'Unknown device';
}

export interface ControllerForm {
  organizationId: string;
  siteId: string;
  name: string;
  baseUrl: string;
  unifiSite: string;
  unifiOs: boolean;
  authMode: 'apikey' | 'password';
  username: string;
  secret: string;
  certificateSha256: string;
}

export interface WifiForm {
  enabled: boolean;
  ssid: string;
  passphrase: string;
  vlan: string;
  subnet: string;
  clientIsolation: boolean;
}

const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;

/** Same rules as the server (`UniFiRules.NormalizeBaseUrl`); returns the problem or null. */
export function controllerProblem(f: ControllerForm, creating: boolean): string | null {
  if (!f.organizationId) {
    return 'Choose the organization.';
  }
  if (!f.name.trim()) {
    return 'Give the controller a name.';
  }
  let url: URL;
  try {
    url = new URL(f.baseUrl.trim());
  } catch {
    return 'Enter the address, for example https://192.168.1.1';
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    (url.pathname !== '/' && url.pathname !== '') ||
    url.search
  ) {
    return 'The address must be https://host or https://host:port, without a path.';
  }
  if (['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) || url.hostname.startsWith('169.254.')) {
    return 'Loopback and link-local addresses are not allowed.';
  }
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(f.unifiSite)) {
    return 'The UniFi site is the short site id, usually "default".';
  }
  if (f.authMode === 'password' && !f.username.trim()) {
    return 'Enter the local controller account for password sign-in.';
  }
  if ((creating || f.secret) && !f.secret) {
    return f.authMode === 'apikey' ? 'Paste the API key.' : 'Enter the password.';
  }
  const pin = f.certificateSha256.replace(/:/g, '').trim();
  if (pin && !/^[0-9A-Fa-f]{64}$/.test(pin)) {
    return 'The certificate fingerprint is the 64-digit SHA-256 hex value.';
  }
  return null;
}

/** Problems with one Wi-Fi network of the setup form. */
export function wifiProblem(label: string, w: WifiForm, passphraseRequired: boolean): string | null {
  if (!w.enabled) {
    return null;
  }
  if (w.ssid.length < 1 || w.ssid.length > 32) {
    return `${label}: the network name must be 1-32 characters.`;
  }
  if ((passphraseRequired || w.passphrase) && (w.passphrase.length < 8 || w.passphrase.length > 63)) {
    return `${label}: the Wi-Fi password must be 8-63 characters.`;
  }
  const vlan = Number(w.vlan);
  if (!/^\d+$/.test(w.vlan) || vlan < 2 || vlan > 4094) {
    return `${label}: choose a VLAN from 2 to 4094.`;
  }
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(w.subnet.trim());
  if (!m || !PRIVATE.test(m[1] ?? '') || Number(m[2]) < 16 || Number(m[2]) > 28 || /\.0$/.test(m[1] ?? '')) {
    return `${label}: enter the gateway address with prefix, for example 192.168.20.1/24.`;
  }
  return null;
}

const CIDR = /^(10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\/([89]|[12]\d|3[0-2])$/;

/** Problem with the 802.1X form, or null. */
export function radiusProblem(cidr: string, ssid: string): string | null {
  if (!CIDR.test(cidr.trim())) {
    return 'Enter the private address range of the access points, for example 192.168.1.0/24.';
  }
  if (ssid.length < 1 || ssid.length > 32) {
    return 'Enter the office Wi-Fi name (1-32 characters).';
  }
  return null;
}
