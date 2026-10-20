/**
 * The binary packet protocol (RFC 4253 §6), one implementation per way a
 * packet can be protected:
 *
 * - none, during the first key exchange;
 * - AES-GCM (RFC 5647 as OpenSSH does it): the length in the clear as
 *   associated data, the rest sealed, a 12-byte nonce counted per packet;
 * - AES-CTR with HMAC-SHA2 (RFC 4344, RFC 6668), where the MAC is over the
 *   plaintext and the length is encrypted too;
 * - the same with OpenSSH's encrypt-then-MAC, where the length is in the
 *   clear and the MAC, over the ciphertext, is checked before any of it is
 *   decrypted.
 *
 * A `Sealer` turns a payload into the bytes that go on the wire; an `Opener`
 * reads one packet's worth off the connection and returns its payload.
 */

import { randomBytes, subtle } from '../crypto';
import { concat, Writer, type Bytes } from '../wire';
import type { Buffered } from './buffered';
import { isGcm, type CipherName, type MacName } from './algorithms';

/** Larger than any server sends (OpenSSH's own limit is 256 KiB). */
export const MAX_PACKET = 1024 * 1024;

export interface Sealer {
  seal(payload: Bytes, sequence: number): Promise<Bytes>;
}

export interface Opener {
  open(source: Buffered, sequence: number): Promise<Bytes>;
}

/** Padding so the encrypted part lands on a block boundary, at least 4 bytes of it. */
export function paddingFor(
  payloadLength: number,
  blockSize: number,
  countLengthField: boolean,
): number {
  const base = (countLengthField ? 4 : 0) + 1 + payloadLength;
  let padding = blockSize - (base % blockSize);
  if (padding < 4) padding += blockSize;
  return padding;
}

function lengthOf(bytes: Bytes, at = 0): number {
  return new DataView(bytes.buffer, bytes.byteOffset + at, 4).getUint32(0);
}

function checkLength(length: number, blockSize: number): void {
  if (length < 5 || length > MAX_PACKET || length % blockSize !== 0) {
    throw new Error(`a packet of ${length} bytes is out of range`);
  }
}

/** padding_length || payload || padding  →  payload */
function unpad(plain: Bytes): Bytes {
  const padding = plain[0]!;
  if (padding < 4 || padding + 1 > plain.length)
    throw new Error(`a packet with ${padding} bytes of padding`);
  return plain.subarray(1, plain.length - padding);
}

export const PLAIN: Sealer & Opener = {
  seal(payload) {
    const padding = paddingFor(payload.length, 8, true);
    return Promise.resolve(
      new Writer()
        .uint32(1 + payload.length + padding)
        .byte(padding)
        .raw(payload)
        .raw(new Uint8Array(padding))
        .build(),
    );
  },
  async open(source) {
    const length = lengthOf(await source.exactly(4));
    if (length < 5 || length > MAX_PACKET)
      throw new Error(`a packet of ${length} bytes is out of range`);
    return unpad(await source.exactly(length));
  },
};

/**
 * The GCM invocation counter, as a big-endian integer over the last 8 bytes.
 * Exported because reusing one is not a bug you want to find in production:
 * it is what the transport's send queue exists to prevent.
 */
export function bumpCounter(iv: Bytes): void {
  for (let index = 11; index >= 4; index--) {
    if (++iv[index]! <= 0xff) break;
    iv[index] = 0;
  }
}

/** Adds `blocks` to a 16-byte big-endian CTR counter, in place. */
export function advanceCounter(counter: Bytes, blocks: number): void {
  let carry = blocks;
  for (let index = 15; index >= 0 && carry > 0; index--) {
    const sum = counter[index]! + (carry % 256);
    counter[index] = sum & 0xff;
    carry = Math.floor(carry / 256) + (sum >> 8);
  }
}

class Gcm implements Sealer, Opener {
  constructor(
    private readonly key: CryptoKey,
    private readonly iv: Bytes,
  ) {}

  async seal(payload: Bytes): Promise<Bytes> {
    const padding = paddingFor(payload.length, 16, false);
    const lengthBytes = new Writer().uint32(1 + payload.length + padding).build();
    const plain = concat([new Uint8Array([padding]), payload, randomBytes(padding)]);
    const sealed = await subtle.encrypt(
      { name: 'AES-GCM', iv: this.iv, additionalData: lengthBytes },
      this.key,
      plain,
    );
    bumpCounter(this.iv);
    return concat([lengthBytes, new Uint8Array(sealed)]);
  }

  async open(source: Buffered): Promise<Bytes> {
    const lengthBytes = await source.exactly(4);
    const length = lengthOf(lengthBytes);
    checkLength(length, 16);
    const sealed = await source.exactly(length + 16);
    const plain = await subtle
      .decrypt({ name: 'AES-GCM', iv: this.iv, additionalData: lengthBytes }, this.key, sealed)
      .catch(() => {
        throw new Error('a packet failed its GCM authentication');
      });
    bumpCounter(this.iv);
    return unpad(new Uint8Array(plain));
  }
}

class CtrHmac implements Sealer, Opener {
  readonly #macLength: number;

  constructor(
    private readonly key: CryptoKey,
    private readonly counter: Bytes,
    private readonly macKey: CryptoKey,
    mac: MacName,
    private readonly etm: boolean,
  ) {
    this.#macLength = mac.includes('512') ? 64 : 32;
  }

  async #xor(data: Bytes): Promise<Bytes> {
    const out = await subtle.encrypt(
      { name: 'AES-CTR', counter: this.counter, length: 128 },
      this.key,
      data,
    );
    advanceCounter(this.counter, data.length / 16);
    return new Uint8Array(out);
  }

  #mac(sequence: number, data: Bytes): Promise<ArrayBuffer> {
    return subtle.sign('HMAC', this.macKey, concat([new Writer().uint32(sequence).build(), data]));
  }

  async #check(sequence: number, data: Bytes, mac: Bytes): Promise<void> {
    // verify(), not a comparison here: WebCrypto's is constant-time.
    const signed = concat([new Writer().uint32(sequence).build(), data]);
    if (!(await subtle.verify('HMAC', this.macKey, mac, signed)))
      throw new Error('a packet failed its MAC');
  }

  async seal(payload: Bytes, sequence: number): Promise<Bytes> {
    const padding = paddingFor(payload.length, 16, !this.etm);
    const length = new Writer().uint32(1 + payload.length + padding).build();
    const body = concat([new Uint8Array([padding]), payload, randomBytes(padding)]);
    if (this.etm) {
      const encrypted = await this.#xor(body);
      const mac = await this.#mac(sequence, concat([length, encrypted]));
      return concat([length, encrypted, new Uint8Array(mac)]);
    }
    const packet = concat([length, body]);
    const mac = await this.#mac(sequence, packet);
    return concat([await this.#xor(packet), new Uint8Array(mac)]);
  }

  async open(source: Buffered, sequence: number): Promise<Bytes> {
    if (this.etm) {
      const lengthBytes = await source.exactly(4);
      const length = lengthOf(lengthBytes);
      checkLength(length, 16);
      const encrypted = await source.exactly(length);
      await this.#check(
        sequence,
        concat([lengthBytes, encrypted]),
        await source.exactly(this.#macLength),
      );
      return unpad(await this.#xor(encrypted));
    }
    // The length is inside the first block, so that block is decrypted on
    // its own before the rest can be read.
    const first = await this.#xor(await source.exactly(16));
    const length = lengthOf(first);
    if (length + 4 < 16 || length > MAX_PACKET || (length + 4) % 16 !== 0) {
      throw new Error(`a packet of ${length} bytes is out of range`);
    }
    const rest = await this.#xor(await source.exactly(length + 4 - 16));
    const packet = concat([first, rest]);
    await this.#check(sequence, packet, await source.exactly(this.#macLength));
    return unpad(packet.subarray(4));
  }
}

export interface Keys {
  iv: Bytes;
  key: Bytes;
  /** Empty for GCM. */
  macKey: Bytes;
}

/** How many bytes of each to derive for a cipher and MAC (RFC 4253 §7.2). */
export function keyLengths(
  cipher: CipherName,
  mac: MacName,
): { iv: number; key: number; mac: number } {
  const key = cipher.startsWith('aes256') ? 32 : cipher.startsWith('aes192') ? 24 : 16;
  if (isGcm(cipher)) return { iv: 12, key, mac: 0 };
  return { iv: 16, key, mac: mac.includes('512') ? 64 : 32 };
}

export async function packetCipher(
  cipher: CipherName,
  mac: MacName,
  keys: Keys,
  usage: 'encrypt' | 'decrypt',
): Promise<Sealer & Opener> {
  if (isGcm(cipher)) {
    const key = await subtle.importKey('raw', keys.key, { name: 'AES-GCM' }, false, [usage]);
    return new Gcm(key, new Uint8Array(keys.iv));
  }
  // CTR decryption is encryption of the counter, so either way it encrypts.
  const key = await subtle.importKey('raw', keys.key, { name: 'AES-CTR' }, false, ['encrypt']);
  const hash = mac.includes('512') ? 'SHA-512' : 'SHA-256';
  const macKey = await subtle.importKey('raw', keys.macKey, { name: 'HMAC', hash }, false, [
    'sign',
    'verify',
  ]);
  return new CtrHmac(key, new Uint8Array(keys.iv), macKey, mac, mac.endsWith('-etm@openssh.com'));
}
