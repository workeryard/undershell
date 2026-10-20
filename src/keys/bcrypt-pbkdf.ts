/**
 * bcrypt_pbkdf, the derivation `ssh-keygen` protects a private key's
 * passphrase with (OpenBSD's bcrypt_pbkdf.c, which defines it): PBKDF2's
 * shape, with SHA-512 and a bcrypt-style Blowfish hash as the round function.
 *
 * WebCrypto has SHA-512 and nothing Blowfish, so Blowfish is here. It is
 * deliberately slow, 64 key schedules per round: a key from `ssh-keygen`
 * with its default 16 rounds costs a few hundred milliseconds of CPU, which
 * a Worker on a 10 ms plan does not have.
 */

import { digest } from '../crypto';
import { concat, Writer, type Bytes } from '../wire';
import { PI_HEX } from './blowfish-pi';

/** 32 bytes of output per hash, from this 32-byte magic string. */
const MAGIC = new TextEncoder().encode('OxychromaticBlowfishSwatDynamite');
const HASH_LENGTH = 32;

class Blowfish {
  readonly p = new Uint32Array(18);
  readonly s = new Uint32Array(1024);

  constructor() {
    for (let index = 0; index < 18; index++)
      this.p[index] = parseInt(PI_HEX.slice(index * 8, index * 8 + 8), 16);
    for (let index = 0; index < 1024; index++) {
      const at = (18 + index) * 8;
      this.s[index] = parseInt(PI_HEX.slice(at, at + 8), 16);
    }
  }

  #f(x: number): number {
    const s = this.s;
    return (
      (((s[x >>> 24]! + s[256 + ((x >>> 16) & 0xff)]!) ^ s[512 + ((x >>> 8) & 0xff)]!) +
        s[768 + (x & 0xff)]!) >>>
      0
    );
  }

  /** Enciphers block[at], block[at + 1] in place. */
  encipher(block: Uint32Array, at: number): void {
    const p = this.p;
    let left = block[at]! ^ p[0]!;
    let right = block[at + 1]!;
    for (let round = 1; round <= 16; round += 2) {
      right ^= this.#f(left) ^ p[round]!;
      left ^= this.#f(right) ^ p[round + 1]!;
    }
    block[at] = (right ^ p[17]!) >>> 0;
    block[at + 1] = left >>> 0;
  }

  /**
   * The bcrypt key schedule. With `data` it is Blowfish_expandstate, salting
   * every block; without, Blowfish_expand0state.
   */
  expand(key: Bytes, data?: Bytes): void {
    const keyStream = words(key);
    for (let index = 0; index < 18; index++) this.p[index] = (this.p[index]! ^ keyStream()) >>> 0;
    const dataStream = data ? words(data) : () => 0;
    const block = new Uint32Array(2);
    const fill = (table: Uint32Array, length: number) => {
      for (let index = 0; index < length; index += 2) {
        block[0] = (block[0]! ^ dataStream()) >>> 0;
        block[1] = (block[1]! ^ dataStream()) >>> 0;
        this.encipher(block, 0);
        table[index] = block[0];
        table[index + 1] = block[1];
      }
    };
    fill(this.p, 18);
    fill(this.s, 1024);
  }
}

/** Big-endian 32-bit words read cyclically over `bytes`, as stream2word does. */
function words(bytes: Uint8Array): () => number {
  let at = 0;
  return () => {
    let word = 0;
    for (let index = 0; index < 4; index++) {
      word = ((word << 8) | bytes[at]!) >>> 0;
      at = (at + 1) % bytes.length;
    }
    return word;
  };
}

/** bcrypt_hash: Blowfish keyed by the hashed passphrase and salt, run over MAGIC. */
function bcryptHash(sha2pass: Bytes, sha2salt: Bytes): Bytes {
  const state = new Blowfish();
  state.expand(sha2pass, sha2salt);
  for (let round = 0; round < 64; round++) {
    state.expand(sha2salt);
    state.expand(sha2pass);
  }
  const block = new Uint32Array(8);
  const next = words(MAGIC);
  for (let index = 0; index < 8; index++) block[index] = next();
  for (let round = 0; round < 64; round++)
    for (let at = 0; at < 8; at += 2) state.encipher(block, at);
  // Out little-endian, unlike everything going in.
  const out = new Uint8Array(HASH_LENGTH);
  const view = new DataView(out.buffer);
  for (let index = 0; index < 8; index++) view.setUint32(index * 4, block[index]!, true);
  return out;
}

export async function bcryptPbkdf(
  passphrase: Bytes,
  salt: Bytes,
  length: number,
  rounds: number,
): Promise<Bytes> {
  if (rounds < 1) throw new Error('bcrypt_pbkdf needs at least one round');
  // As OpenBSD's: an empty passphrase or salt is refused, not derived from.
  if (passphrase.length === 0 || salt.length === 0)
    throw new Error('bcrypt_pbkdf needs a passphrase and a salt');
  if (length < 1 || length > HASH_LENGTH * HASH_LENGTH)
    throw new Error(`bcrypt_pbkdf cannot make ${length} bytes`);
  // The output is interleaved, not concatenated: byte i of block n lands at
  // i * stride + n, so every block's work is needed for any prefix.
  const stride = Math.ceil(length / HASH_LENGTH);
  const perBlock = Math.ceil(length / stride);
  const key = new Uint8Array(length);
  const sha2pass = await digest('SHA-512', passphrase);

  for (let count = 1, left = length; left > 0; count++) {
    let tmp = bcryptHash(
      sha2pass,
      await digest('SHA-512', concat([salt, new Writer().uint32(count).build()])),
    );
    const out = new Uint8Array(tmp);
    for (let round = 1; round < rounds; round++) {
      tmp = bcryptHash(sha2pass, await digest('SHA-512', tmp));
      for (let index = 0; index < HASH_LENGTH; index++) out[index]! ^= tmp[index]!;
    }
    let placed = 0;
    for (; placed < Math.min(perBlock, left); placed++) {
      const at = placed * stride + (count - 1);
      if (at >= length) break;
      key[at] = out[placed]!;
    }
    left -= placed;
  }
  return key;
}
