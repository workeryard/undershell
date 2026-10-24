/**
 * What this client offers, in the order it prefers, and how a choice is made
 * from what the server offers (RFC 4253 §7.1: the first of the client's that
 * the server also has).
 *
 * Every name here is something WebCrypto can do in Node and in workerd alike.
 * ChaCha20-Poly1305, which OpenSSH would otherwise prefer, is absent from
 * WebCrypto, so it is not offered and the server picks an AES cipher instead.
 */

export const KEX = [
  'curve25519-sha256',
  'curve25519-sha256@libssh.org',
  'ecdh-sha2-nistp256',
  // Finite-field Diffie-Hellman, last: BigInt arithmetic costs more CPU than
  // a curve, and only servers with no curve at all, such as RouterOS 6,
  // need it.
  'diffie-hellman-group-exchange-sha256',
  'diffie-hellman-group16-sha512',
  'diffie-hellman-group14-sha256',
] as const;

export const HOST_KEYS = [
  'ssh-ed25519',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'rsa-sha2-512',
  'rsa-sha2-256',
] as const;

export const CIPHERS = [
  'aes256-gcm@openssh.com',
  'aes128-gcm@openssh.com',
  'aes256-ctr',
  'aes192-ctr',
  'aes128-ctr',
] as const;

/** Only consulted for a CTR cipher: GCM authenticates the packet itself. */
export const MACS = [
  'hmac-sha2-256-etm@openssh.com',
  'hmac-sha2-512-etm@openssh.com',
  'hmac-sha2-256',
  'hmac-sha2-512',
  // Last, for servers that offer nothing better, RouterOS 6 among them.
  // SHA-1's collisions do not carry over to HMAC, which OpenSSH still
  // offers by default; SHA-1 signatures and key exchanges stay refused.
  'hmac-sha1-etm@openssh.com',
  'hmac-sha1',
] as const;

export type KexName = (typeof KEX)[number];
export type HostKeyName = (typeof HOST_KEYS)[number];
export type CipherName = (typeof CIPHERS)[number];
export type MacName = (typeof MACS)[number];

/**
 * A narrower or reordered list for any of the four. Names outside what this
 * client implements are refused, rather than offered and then failed on.
 */
export interface Algorithms {
  kex?: readonly KexName[];
  hostKey?: readonly HostKeyName[];
  cipher?: readonly CipherName[];
  mac?: readonly MacName[];
}

export interface Preference {
  kex: readonly KexName[];
  hostKey: readonly HostKeyName[];
  cipher: readonly CipherName[];
  mac: readonly MacName[];
}

function pick<T extends string>(
  what: string,
  given: readonly T[] | undefined,
  all: readonly T[],
): readonly T[] {
  if (!given) return all;
  if (given.length === 0) throw new Error(`no ${what} algorithm was left to offer`);
  for (const name of given) {
    if (!all.includes(name))
      throw new Error(`${name} is not a ${what} algorithm this client implements`);
  }
  return given;
}

export function preference(algorithms: Algorithms = {}): Preference {
  return {
    kex: pick('key exchange', algorithms.kex, KEX),
    hostKey: pick('host key', algorithms.hostKey, HOST_KEYS),
    cipher: pick('cipher', algorithms.cipher, CIPHERS),
    mac: pick('MAC', algorithms.mac, MACS),
  };
}

/** The first of ours the server also offers, or a message naming both sides. */
export function choose<T extends string>(
  what: string,
  ours: readonly T[],
  theirs: readonly string[],
): T {
  const chosen = ours.find((name) => theirs.includes(name));
  if (!chosen) {
    throw new Error(
      `the server offers no ${what} this client speaks; it has ${theirs.join(', ') || 'none'}, ` +
        `and this client ${ours.join(', ')}`,
    );
  }
  return chosen;
}

/** A MAC's hash, for WebCrypto, and its tag and key length in bytes. */
export function macSpec(mac: MacName): { hash: 'SHA-1' | 'SHA-256' | 'SHA-512'; length: number } {
  if (mac.startsWith('hmac-sha1')) return { hash: 'SHA-1', length: 20 };
  if (mac.includes('512')) return { hash: 'SHA-512', length: 64 };
  return { hash: 'SHA-256', length: 32 };
}

export function isGcm(cipher: CipherName): boolean {
  return cipher.endsWith('-gcm@openssh.com');
}
