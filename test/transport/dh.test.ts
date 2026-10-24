import { createDiffieHellman, getDiffieHellman } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { fromBig, modPow, toBig } from '../../src/transport/kex';
import { MODP_2048, MODP_4096 } from '../../src/transport/modp';

/**
 * Finite-field Diffie-Hellman is BigInt arithmetic here, with nothing from
 * WebCrypto to lean on, so it is checked against OpenSSL through Node: the
 * groups byte for byte, and the shared secret computed from both ends.
 */
describe('the MODP groups', () => {
  it('are RFC 3526 groups 14 and 16, as OpenSSL has them', () => {
    expect(MODP_2048.toLowerCase()).toBe(getDiffieHellman('modp14').getPrime('hex'));
    expect(MODP_4096.toLowerCase()).toBe(getDiffieHellman('modp16').getPrime('hex'));
  });
});

describe('Diffie-Hellman by BigInt', () => {
  for (const [name, hex] of [
    ['group 14', MODP_2048],
    ['group 16', MODP_4096],
  ] as const) {
    it(`agrees with OpenSSL on the shared secret in ${name}`, () => {
      const p = BigInt(`0x${hex}`);
      const openssl = createDiffieHellman(Buffer.from(hex, 'hex'), Buffer.from([2]));
      const theirs = toBig(openssl.generateKeys());
      const x = toBig(crypto.getRandomValues(new Uint8Array(64)));
      const ours = modPow(2n, x, p);
      const ourSecret = modPow(theirs, x, p);
      const theirSecret = toBig(openssl.computeSecret(Buffer.from(fromBig(ours))));
      expect(ourSecret).toBe(theirSecret);
    });
  }

  it('round-trips integers through bytes, leading zeros dropped', () => {
    expect(toBig(new Uint8Array([0, 1, 0]))).toBe(256n);
    expect([...fromBig(256n)]).toEqual([1, 0]);
    expect([...fromBig(0x0fffn)]).toEqual([0x0f, 0xff]);
  });

  it('raises small numbers to powers correctly', () => {
    expect(modPow(4n, 13n, 497n)).toBe(445n);
    expect(modPow(2n, 0n, 7n)).toBe(1n);
  });
});
