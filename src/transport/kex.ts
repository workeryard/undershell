/**
 * The two key agreements offered, behind one shape: make an ephemeral key,
 * send its public half, combine it with the server's into the shared secret.
 *
 * curve25519-sha256 is RFC 8731, ecdh-sha2-nistp256 is RFC 5656 §4. Both hash
 * the exchange with SHA-256, and both put the secret into that hash as an
 * mpint of the raw bytes — for X25519 the 32-byte output, for P-256 the
 * shared point's x coordinate.
 */

import { subtle, type Hash } from '../crypto';
import type { Bytes } from '../wire';
import type { KexName } from './algorithms';

export interface Agreement {
  hash: Hash;
  /** Q_C, as it goes into SSH_MSG_KEX_ECDH_INIT. */
  clientPublic: Bytes;
  /** K, from the server's Q_S. */
  secret(serverPublic: Bytes): Promise<Bytes>;
}

async function x25519(): Promise<Agreement> {
  const pair = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const clientPublic = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  return {
    hash: 'SHA-256',
    clientPublic,
    async secret(serverPublic) {
      if (serverPublic.length !== 32) {
        throw new Error(`the server's X25519 key is ${serverPublic.length} bytes, not 32`);
      }
      const theirs = await subtle.importKey('raw', serverPublic, { name: 'X25519' }, false, []);
      const shared = new Uint8Array(
        await subtle.deriveBits({ name: 'X25519', public: theirs }, pair.privateKey, 256),
      );
      // RFC 7748 §6.1: an all-zero result means a low-order point was sent.
      if (shared.every((byte) => byte === 0))
        throw new Error("the server's X25519 key is a low-order point");
      return shared;
    },
  };
}

async function nistp256(): Promise<Agreement> {
  const curve = { name: 'ECDH', namedCurve: 'P-256' };
  const pair = await subtle.generateKey(curve, true, ['deriveBits']);
  // WebCrypto's raw export is the uncompressed point, 0x04 || x || y, which
  // is the encoding RFC 5656 asks for.
  const clientPublic = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  return {
    hash: 'SHA-256',
    clientPublic,
    async secret(serverPublic) {
      if (serverPublic.length !== 65 || serverPublic[0] !== 4) {
        throw new Error(
          `the server's P-256 key is not an uncompressed point (${serverPublic.length} bytes)`,
        );
      }
      // The import checks the point is on the curve, which RFC 5656 requires.
      const theirs = await subtle.importKey('raw', serverPublic, curve, false, []);
      return new Uint8Array(
        await subtle.deriveBits({ name: 'ECDH', public: theirs }, pair.privateKey, 256),
      );
    },
  };
}

export function agreement(name: KexName): Promise<Agreement> {
  return name === 'ecdh-sha2-nistp256' ? nistp256() : x25519();
}
