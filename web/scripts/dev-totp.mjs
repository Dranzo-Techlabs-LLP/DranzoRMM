#!/usr/bin/env node
// DEV ONLY. Prints the current TOTP code for a base32 secret, so the sign-in flow can be exercised against a local
// development server without a phone. Never use this with a real account's secret.
//
//   node scripts/dev-totp.mjs JBSWY3DPEHPK3PXP
//   node scripts/dev-totp.mjs JBSWY3DPEHPK3PXP --next   # wait for the next 30-second window, then print
import { Secret, TOTP } from 'otpauth';

const [secret, flag] = process.argv.slice(2);
if (!secret) {
  console.error('usage: node scripts/dev-totp.mjs <base32-secret> [--next]');
  process.exit(2);
}
const totp = new TOTP({ secret: Secret.fromBase32(secret.replace(/\s+/g, '')), digits: 6, period: 30 });
if (flag === '--next') {
  const ms = 30_000 - (Date.now() % 30_000) + 500;
  await new Promise((resolve) => setTimeout(resolve, ms));
}
console.log(totp.generate());
