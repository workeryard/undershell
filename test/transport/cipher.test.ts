import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  type CipherGCMTypes,
} from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  CIPHERS,
  MACS,
  isGcm,
  type CipherName,
  type MacName,
} from '../../src/transport/algorithms';
import { Buffered } from '../../src/transport/buffered';
import { advanceCounter, keyLengths, packetCipher, PLAIN } from '../../src/transport/cipher';
import { Writer } from '../../src/wire';

/**
 * The binary packet protocol, checked against a second implementation of it
 * written here on Node's OpenSSL: what one side seals the other must open, in
 * both directions, across several packets so the counters and sequence
 * numbers are exercised, not just the first packet.
 */

const streamOf = (bytes: Uint8Array) =>
  new Buffered(
    new ReadableStream({
      start(controller) {
        // In uneven pieces, as a socket delivers them.
        for (let at = 0; at < bytes.length; at += 7) controller.enqueue(bytes.slice(at, at + 7));
        controller.close();
      },
    }),
  );

function keysFor(cipher: CipherName, mac: MacName) {
  const size = keyLengths(cipher, mac);
  return {
    iv: new Uint8Array(randomBytes(size.iv)),
    key: new Uint8Array(randomBytes(size.key)),
    macKey: new Uint8Array(randomBytes(size.mac)),
  };
}

/** RFC 4253 §6 / RFC 5647 / OpenSSH's PROTOCOL, on node:crypto, one packet at a time. */
function reference(cipher: CipherName, mac: MacName, keys: ReturnType<typeof keysFor>) {
  const bits = keys.key.length * 8;
  const etm = mac.endsWith('-etm@openssh.com');
  const hash = mac.includes('512') ? 'sha512' : 'sha256';
  const iv = Buffer.from(keys.iv);
  let gcmCounter = iv.readBigUInt64BE(4);
  const ctr = isGcm(cipher)
    ? null
    : {
        e: createCipheriv(`aes-${bits}-ctr`, keys.key, keys.iv),
        d: createDecipheriv(`aes-${bits}-ctr`, keys.key, keys.iv),
      };

  return {
    open(wire: Buffer, sequence: number): Buffer {
      if (isGcm(cipher)) {
        const nonce = Buffer.concat([iv.subarray(0, 4), Buffer.alloc(8)]);
        nonce.writeBigUInt64BE(gcmCounter++, 4);
        const length = wire.readUInt32BE(0);
        const decipher = createDecipheriv(`aes-${bits}-gcm` as CipherGCMTypes, keys.key, nonce);
        decipher.setAAD(wire.subarray(0, 4));
        decipher.setAuthTag(wire.subarray(4 + length, 4 + length + 16));
        const plain = Buffer.concat([
          decipher.update(wire.subarray(4, 4 + length)),
          decipher.final(),
        ]);
        return plain.subarray(1, plain.length - plain[0]!);
      }
      const seq = Buffer.alloc(4);
      seq.writeUInt32BE(sequence);
      const macLength = hash === 'sha512' ? 64 : 32;
      if (etm) {
        const length = wire.readUInt32BE(0);
        const body = wire.subarray(4, 4 + length);
        const tag = createHmac(hash, keys.macKey)
          .update(seq)
          .update(wire.subarray(0, 4 + length))
          .digest();
        expect(tag.equals(wire.subarray(4 + length, 4 + length + macLength))).toBe(true);
        const plain = ctr!.d.update(body);
        return plain.subarray(1, plain.length - plain[0]!);
      }
      const plain = ctr!.d.update(wire.subarray(0, wire.length - macLength));
      const tag = createHmac(hash, keys.macKey).update(seq).update(plain).digest();
      expect(tag.equals(wire.subarray(wire.length - macLength))).toBe(true);
      return plain.subarray(5, plain.length - plain[4]!);
    },
    seal(payload: Buffer, sequence: number): Buffer {
      const seq = Buffer.alloc(4);
      seq.writeUInt32BE(sequence);
      const countLength = !isGcm(cipher) && !etm;
      let padding = 16 - (((countLength ? 4 : 0) + 1 + payload.length) % 16);
      if (padding < 4) padding += 16;
      const length = Buffer.alloc(4);
      length.writeUInt32BE(1 + payload.length + padding);
      const body = Buffer.concat([Buffer.from([padding]), payload, randomBytes(padding)]);
      if (isGcm(cipher)) {
        const nonce = Buffer.concat([iv.subarray(0, 4), Buffer.alloc(8)]);
        nonce.writeBigUInt64BE(gcmCounter++, 4);
        const c = createCipheriv(`aes-${bits}-gcm` as CipherGCMTypes, keys.key, nonce);
        c.setAAD(length);
        return Buffer.concat([length, c.update(body), c.final(), c.getAuthTag()]);
      }
      if (etm) {
        const encrypted = ctr!.e.update(body);
        const tag = createHmac(hash, keys.macKey)
          .update(seq)
          .update(length)
          .update(encrypted)
          .digest();
        return Buffer.concat([length, encrypted, tag]);
      }
      const packet = Buffer.concat([length, body]);
      const tag = createHmac(hash, keys.macKey).update(seq).update(packet).digest();
      return Buffer.concat([ctr!.e.update(packet), tag]);
    },
  };
}

const PAIRS = CIPHERS.flatMap((cipher) =>
  isGcm(cipher) ? [[cipher, 'hmac-sha2-256'] as const] : MACS.map((mac) => [cipher, mac] as const),
);
const PAYLOADS = [1, 15, 16, 17, 100, 4096, 32768].map((size) => new Uint8Array(randomBytes(size)));

describe('the binary packet protocol', () => {
  for (const [cipher, mac] of PAIRS) {
    const label = isGcm(cipher) ? cipher : `${cipher} with ${mac}`;

    it(`seals ${label} as OpenSSL opens it`, async () => {
      const keys = keysFor(cipher, mac);
      const ours = await packetCipher(cipher, mac, keys, 'encrypt');
      const theirs = reference(cipher, mac, keys);
      for (const [sequence, payload] of PAYLOADS.entries()) {
        const wire = await ours.seal(payload, sequence + 3);
        expect([...theirs.open(Buffer.from(wire), sequence + 3)]).toEqual([...payload]);
      }
    });

    it(`opens ${label} as OpenSSL seals it`, async () => {
      const keys = keysFor(cipher, mac);
      const ours = await packetCipher(cipher, mac, keys, 'decrypt');
      const theirs = reference(cipher, mac, keys);
      const wire = Buffer.concat(
        PAYLOADS.map((payload, sequence) => theirs.seal(Buffer.from(payload), sequence)),
      );
      const source = streamOf(wire);
      for (const [sequence, payload] of PAYLOADS.entries()) {
        expect([...(await ours.open(source, sequence))]).toEqual([...payload]);
      }
    });

    it(`refuses a ${label} packet with one bit flipped`, async () => {
      const keys = keysFor(cipher, mac);
      const sealer = await packetCipher(cipher, mac, keys, 'encrypt');
      const opener = await packetCipher(cipher, mac, keys, 'decrypt');
      const wire = await sealer.seal(new Uint8Array(64).fill(1), 0);
      wire[wire.length - 20]! ^= 1;
      await expect(opener.open(streamOf(wire), 0)).rejects.toThrow(/MAC|GCM/);
    });

    it(`refuses a ${label} packet under the wrong sequence number`, async () => {
      if (isGcm(cipher)) return; // GCM counts its own nonce; the sequence number is not in it.
      const keys = keysFor(cipher, mac);
      const sealer = await packetCipher(cipher, mac, keys, 'encrypt');
      const opener = await packetCipher(cipher, mac, keys, 'decrypt');
      await expect(
        opener.open(streamOf(await sealer.seal(new Uint8Array(8), 5)), 6),
      ).rejects.toThrow(/MAC/);
    });
  }

  it('pads the unencrypted packets of the first exchange to eight bytes, at least four of padding', async () => {
    for (const size of [0, 3, 4, 11, 12]) {
      const wire = await PLAIN.seal(new Uint8Array(size), 0);
      expect(wire.length % 8).toBe(0);
      expect(wire[4]).toBeGreaterThanOrEqual(4);
      expect([...(await PLAIN.open(streamOf(wire), 0))]).toEqual([...new Uint8Array(size)]);
    }
  });

  it('refuses a packet length past the limit before reading it', async () => {
    const huge = new Writer()
      .uint32(64 * 1024 * 1024)
      .byte(4)
      .build();
    await expect(PLAIN.open(streamOf(huge), 0)).rejects.toThrow(/out of range/);
  });
});

describe('the CTR counter', () => {
  it('carries across all sixteen bytes', () => {
    const counter = new Uint8Array(16).fill(0xff);
    counter[0] = 0;
    advanceCounter(counter, 1);
    expect([...counter]).toEqual([1, ...Array<number>(15).fill(0)]);
  });

  it('adds counts of more than one byte', () => {
    const counter = new Uint8Array(16);
    counter[15] = 0xf0;
    advanceCounter(counter, 0x1234);
    expect([...counter.subarray(13)]).toEqual([0x00, 0x13, 0x24]);
  });
});
