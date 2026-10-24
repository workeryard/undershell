/**
 * The key exchanges, each run to the point where the server's reply has
 * been read and the exchange hash computed; the transport then checks the
 * signature over it and derives the keys.
 *
 * - curve25519-sha256 (RFC 8731) and ecdh-sha2-nistp256 (RFC 5656 §4), by
 *   WebCrypto.
 * - diffie-hellman-group14-sha256 and -group16-sha512 (RFC 8268) over the
 *   fixed groups of RFC 3526, and diffie-hellman-group-exchange-sha256
 *   (RFC 4419), where the server picks the group. WebCrypto has no
 *   finite-field Diffie-Hellman, so these are BigInt arithmetic.
 */

import { digest, randomBytes, subtle, type Hash } from '../crypto';
import { Reader, Writer, type Bytes } from '../wire';
import type { KexName } from './algorithms';
import { MODP_2048, MODP_4096 } from './modp';

const MSG = {
  KEXDH_INIT: 30,
  KEXDH_REPLY: 31,
  GEX_GROUP: 31,
  GEX_INIT: 32,
  GEX_REPLY: 33,
  GEX_REQUEST: 34,
} as const;

/** What the exchange hash starts with, whatever the method. */
export interface Prefix {
  clientVersion: string;
  serverVersion: string;
  ours: Bytes;
  theirs: Bytes;
}

/** How a method talks to the server during the exchange. */
export interface Conversation {
  send(payload: Bytes): void;
  expect(type: number): Promise<Bytes>;
}

export interface KexResult {
  hash: Hash;
  hostKeyBlob: Bytes;
  signature: Bytes;
  /** K, encoded as the mpint it is everywhere it is used. */
  secret: Bytes;
  exchangeHash: Bytes;
}

/** Group sizes asked for in a group exchange: enough, and no more CPU than that. */
export const GEX_BITS = { min: 2048, preferred: 3072, max: 4096 } as const;

function head(prefix: Prefix, hostKeyBlob: Bytes): Writer {
  return new Writer()
    .string(prefix.clientVersion)
    .string(prefix.serverVersion)
    .string(prefix.ours)
    .string(prefix.theirs)
    .string(hostKeyBlob);
}

// --- elliptic curves, by WebCrypto -------------------------------------------

async function ecdh(name: KexName, talk: Conversation, prefix: Prefix): Promise<KexResult> {
  const curve =
    name === 'ecdh-sha2-nistp256' ? { name: 'ECDH', namedCurve: 'P-256' } : { name: 'X25519' };
  const pair = await subtle.generateKey(curve, true, ['deriveBits']);
  // WebCrypto's raw export is X25519's 32 bytes, or P-256's uncompressed
  // point 0x04 || x || y: the encodings the RFCs ask for.
  const clientPublic = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  talk.send(new Writer().byte(MSG.KEXDH_INIT).string(clientPublic).build());

  const reply = new Reader((await talk.expect(MSG.KEXDH_REPLY)).subarray(1));
  const hostKeyBlob = reply.string();
  const serverPublic = reply.string();
  const signature = reply.string();
  let shared: Bytes;
  if (curve.name === 'X25519') {
    if (serverPublic.length !== 32)
      throw new Error(`the server's X25519 key is ${serverPublic.length} bytes, not 32`);
    const theirs = await subtle.importKey('raw', serverPublic, curve, false, []);
    shared = new Uint8Array(
      await subtle.deriveBits({ name: 'X25519', public: theirs }, pair.privateKey, 256),
    );
    // RFC 7748 §6.1: an all-zero result means a low-order point was sent.
    if (shared.every((byte) => byte === 0))
      throw new Error("the server's X25519 key is a low-order point");
  } else {
    if (serverPublic.length !== 65 || serverPublic[0] !== 4) {
      throw new Error(
        `the server's P-256 key is not an uncompressed point (${serverPublic.length} bytes)`,
      );
    }
    // The import checks the point is on the curve, which RFC 5656 requires.
    const theirs = await subtle.importKey('raw', serverPublic, curve, false, []);
    shared = new Uint8Array(
      await subtle.deriveBits({ name: 'ECDH', public: theirs }, pair.privateKey, 256),
    );
  }
  const secret = new Writer().mpint(shared).build();
  const exchangeHash = await digest(
    'SHA-256',
    head(prefix, hostKeyBlob).string(clientPublic).string(serverPublic).raw(secret).build(),
  );
  return { hash: 'SHA-256', hostKeyBlob, signature, secret, exchangeHash };
}

// --- finite fields, by BigInt --------------------------------------------------

export const toBig = (bytes: Uint8Array): bigint =>
  bytes.length === 0
    ? 0n
    : BigInt(`0x${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`);

export function fromBig(value: bigint): Bytes {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return new Uint8Array(hex.match(/../g)?.map((pair) => parseInt(pair, 16)) ?? []);
}

/** base^exponent mod modulus, by squaring: exponents here are 512 bits. */
export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let square = base % modulus;
  for (let left = exponent; left > 0n; left >>= 1n) {
    if (left & 1n) result = (result * square) % modulus;
    square = (square * square) % modulus;
  }
  return result;
}

const bitLength = (value: bigint) => value.toString(2).length;

/**
 * A private exponent of 512 bits: twice the 256 bits of the strongest
 * cipher here, as OpenSSH chooses, and far cheaper than one as long as p.
 */
function privateExponent(p: bigint): bigint {
  const x = toBig(randomBytes(64)) % (p - 2n);
  return x < 2n ? 2n : x;
}

/** RFC 4253 §8: 1 < f < p - 1, or the shared secret is guessable. */
function checkPublic(value: bigint, p: bigint, what: string): void {
  if (value <= 1n || value >= p - 1n) throw new Error(`the server's ${what} is out of range`);
}

async function dh(name: KexName, talk: Conversation, prefix: Prefix): Promise<KexResult> {
  const hash: Hash = name === 'diffie-hellman-group16-sha512' ? 'SHA-512' : 'SHA-256';
  const gex = name === 'diffie-hellman-group-exchange-sha256';
  let p: bigint;
  let g = 2n;
  if (gex) {
    talk.send(
      new Writer()
        .byte(MSG.GEX_REQUEST)
        .uint32(GEX_BITS.min)
        .uint32(GEX_BITS.preferred)
        .uint32(GEX_BITS.max)
        .build(),
    );
    const group = new Reader((await talk.expect(MSG.GEX_GROUP)).subarray(1));
    p = toBig(group.mpint());
    g = toBig(group.mpint());
    const bits = bitLength(p);
    if (bits < GEX_BITS.min || bits > GEX_BITS.max) {
      throw new Error(
        `the server chose a ${bits}-bit group, outside the ${GEX_BITS.min}–${GEX_BITS.max} asked for`,
      );
    }
    if (p % 2n === 0n || g <= 1n || g >= p - 1n)
      throw new Error('the server chose a group that is not one');
  } else {
    p = BigInt(`0x${name === 'diffie-hellman-group16-sha512' ? MODP_4096 : MODP_2048}`);
  }

  const x = privateExponent(p);
  const e = modPow(g, x, p);
  talk.send(
    new Writer()
      .byte(gex ? MSG.GEX_INIT : MSG.KEXDH_INIT)
      .mpint(fromBig(e))
      .build(),
  );

  const reply = new Reader((await talk.expect(gex ? MSG.GEX_REPLY : MSG.KEXDH_REPLY)).subarray(1));
  const hostKeyBlob = reply.string();
  const f = toBig(reply.mpint());
  const signature = reply.string();
  checkPublic(f, p, 'Diffie-Hellman value');
  const secret = new Writer().mpint(fromBig(modPow(f, x, p))).build();

  const fields = head(prefix, hostKeyBlob);
  if (gex) {
    fields
      .uint32(GEX_BITS.min)
      .uint32(GEX_BITS.preferred)
      .uint32(GEX_BITS.max)
      .mpint(fromBig(p))
      .mpint(fromBig(g));
  }
  fields.mpint(fromBig(e)).mpint(fromBig(f)).raw(secret);
  return { hash, hostKeyBlob, signature, secret, exchangeHash: await digest(hash, fields.build()) };
}

export function runKex(name: KexName, talk: Conversation, prefix: Prefix): Promise<KexResult> {
  return name.startsWith('diffie-hellman-') ? dh(name, talk, prefix) : ecdh(name, talk, prefix);
}
