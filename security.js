import crypto from 'node:crypto';
import argon2 from 'argon2';

const b64url = (n = 32) => crypto.randomBytes(n).toString('base64url');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function hashSessionToken(raw) {
  return crypto.createHmac('sha256', required('SESSION_PEPPER')).update(raw).digest('hex');
}
export function hashLicenseToken(raw) {
  return crypto.createHmac('sha256', required('TOKEN_PEPPER')).update(raw).digest('hex');
}
export function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
export function required(name) {
  const v = process.env[name];
  if (!v || v.startsWith('REPLACE_')) throw new Error(`${name} is not configured`);
  return v;
}
export function newOpaqueToken() { return b64url(32); }
export function newCsrfToken() { return b64url(32); }
export function hashText(value) { return sha256(value); }
export async function hashPassword(password) {
  return argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 });
}
export async function verifyPassword(hash, password) {
  try { return await argon2.verify(hash, password); } catch { return false; }
}
export function newLicenseToken() {
  return `MS-${crypto.randomBytes(24).toString('hex').toUpperCase()}`;
}
