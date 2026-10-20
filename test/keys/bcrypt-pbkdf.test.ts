import { describe, expect, it } from 'vitest';
// The npm port of OpenBSD's bcrypt_pbkdf.c, kept as a second opinion only.
import reference from 'bcrypt-pbkdf';
import { bcryptPbkdf } from '../../src/keys/bcrypt-pbkdf';

const text = (value: string) => new TextEncoder().encode(value);

function expected(
  passphrase: Uint8Array,
  salt: Uint8Array,
  length: number,
  rounds: number,
): Uint8Array {
  const out = new Uint8Array(length);
  reference.pbkdf(passphrase, passphrase.length, salt, salt.length, out, length, rounds);
  return out;
}

describe('bcrypt_pbkdf', () => {
  // Lengths either side of the 32-byte block, where the interleaving starts,
  // and 48, which is what an aes256-ctr key and its IV take.
  const cases: [string, string, number, number][] = [
    ['password', 'salt', 32, 4],
    ['p', 'x', 48, 1],
    ['correct horse battery staple', 'saltsaltsaltsalt', 48, 16],
    ['a'.repeat(100), 'b', 7, 3],
    ['pw', 'salt', 65, 2],
  ];

  for (const [passphrase, salt, length, rounds] of cases) {
    it(`derives ${length} bytes in ${rounds} rounds as OpenBSD's does`, async () => {
      const got = await bcryptPbkdf(text(passphrase), text(salt), length, rounds);
      expect([...got]).toEqual([...expected(text(passphrase), text(salt), length, rounds)]);
    });
  }

  it('refuses an empty passphrase, as OpenBSD does', async () => {
    await expect(bcryptPbkdf(text(''), text('salt'), 32, 4)).rejects.toThrow(/needs a passphrase/);
  });

  it('refuses zero rounds', async () => {
    await expect(bcryptPbkdf(text('a'), text('b'), 32, 0)).rejects.toThrow(/at least one round/);
  });
});
