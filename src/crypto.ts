/**
 * One seam for WebCrypto, the only cryptography this package uses.
 *
 * The package is compiled twice: once against the DOM lib, where a key
 * agreement takes `{ name: "X25519", public: key }`, and once against
 * `@cloudflare/workers-types`, whose generator renames that property to
 * `$public` and drops `KeyUsage` and `AlgorithmIdentifier` entirely. The
 * runtime is the same in both; only the type definitions disagree.
 *
 * Rather than scatter casts through the protocol code, the surface is narrowed
 * here, to the handful of calls actually used. What this loses in type safety
 * the tests and the runs against real servers give back: a wrong algorithm
 * name fails immediately and loudly.
 */

import type { Bytes } from './wire';

export const subtle = crypto.subtle as unknown as {
  digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
  generateKey(algorithm: unknown, extractable: boolean, usages: string[]): Promise<CryptoKeyPair>;
  importKey(
    format: 'raw' | 'pkcs8' | 'spki' | 'jwk',
    key: unknown,
    algorithm: unknown,
    extractable: boolean,
    usages: string[],
  ): Promise<CryptoKey>;
  exportKey(format: 'raw', key: CryptoKey): Promise<ArrayBuffer>;
  exportKey(format: 'jwk', key: CryptoKey): Promise<JsonWebKey>;
  deriveBits(algorithm: unknown, key: CryptoKey, length: number): Promise<ArrayBuffer>;
  sign(algorithm: unknown, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer>;
  verify(
    algorithm: unknown,
    key: CryptoKey,
    signature: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean>;
  encrypt(algorithm: unknown, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer>;
  decrypt(algorithm: unknown, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer>;
};

export type Hash = 'SHA-256' | 'SHA-384' | 'SHA-512';

export async function digest(hash: Hash, data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await subtle.digest(hash, data));
}

export function randomBytes(length: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function base64(bytes: Uint8Array): string {
  let binary = '';
  for (let at = 0; at < bytes.length; at += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(text: string): Bytes {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, ''));
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) out[index] = binary.charCodeAt(index);
  return out;
}

/** base64url without padding, as JWK writes its numbers. Leading zeros come off. */
export function base64Url(bytes: Uint8Array, keepLeadingZeros = false): string {
  let start = 0;
  if (!keepLeadingZeros) while (start < bytes.length - 1 && bytes[start] === 0) start++;
  return base64(bytes.subarray(start)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
