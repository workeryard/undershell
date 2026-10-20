import { describe, expect, it } from 'vitest';
import { parsePrivateKey } from '../../src/keys/pem';
import { concat, Writer } from '../../src/wire';

/**
 * Builds a file the way `ssh-keygen` does, so the parser can be exercised
 * without a real key sitting in the repository. The bytes are arbitrary: only
 * the container's shape is under test here, and a real key is what the
 * end-to-end run against a live sshd covers.
 */
function keyFile(
  options: {
    cipher?: string;
    keys?: number;
    type?: string;
    check?: [number, number];
    /** Fills the public blob stored outside the private section, to make the two disagree. */
    publicByte?: number;
  } = {},
): string {
  const type = options.type ?? 'ssh-ed25519';
  const publicPart = new Uint8Array(32).fill(7);
  const privatePart = concat([new Uint8Array(32).fill(3), publicPart]);
  const stored =
    options.publicByte === undefined ? publicPart : new Uint8Array(32).fill(options.publicByte);
  const publicBlob = new Writer().string(type).string(stored).build();
  const [check1, check2] = options.check ?? [1, 1];

  const secret = new Writer()
    .uint32(check1)
    .uint32(check2)
    .string(type)
    .string(publicPart)
    .string(privatePart)
    .string('comment')
    .build();

  const body = new Writer()
    .raw(new TextEncoder().encode('openssh-key-v1\0'))
    .string(options.cipher ?? 'none')
    .string(options.cipher ? 'bcrypt' : 'none')
    .string('')
    .uint32(options.keys ?? 1)
    .string(publicBlob)
    .string(secret)
    .build();

  let base64 = '';
  for (const byte of body) base64 += String.fromCharCode(byte);
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${btoa(base64)}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

describe('reading an OpenSSH private key', () => {
  it('finds the key and its public blob', async () => {
    const key = await parsePrivateKey(keyFile());
    expect(key.type).toBe('ssh-ed25519');
    expect(key.algorithms).toEqual(['ssh-ed25519']);
    // The blob is what goes on the wire: the type, then the 32-byte key.
    expect(key.publicKeyBlob.length).toBe(4 + 'ssh-ed25519'.length + 4 + 32);
  });

  it('signs in SSH encoding: the algorithm, then 64 bytes', async () => {
    const key = await parsePrivateKey(keyFile());
    const signature = await key.sign('ssh-ed25519', new Uint8Array([1, 2, 3]));
    expect(signature.length).toBe(4 + 'ssh-ed25519'.length + 4 + 64);
  });

  it('asks for the passphrase a locked key needs', async () => {
    await expect(parsePrivateKey(keyFile({ cipher: 'aes256-ctr' }))).rejects.toThrow(
      /has a passphrase, and none was given/,
    );
  });

  it('refuses a cipher it cannot read rather than guessing at it', async () => {
    await expect(parsePrivateKey(keyFile({ cipher: 'aes256-cbc' }), 'anything')).rejects.toThrow(
      /encrypted with aes256-cbc, which this client cannot read/,
    );
  });

  it('refuses a file holding more than one key', async () => {
    await expect(parsePrivateKey(keyFile({ keys: 2 }))).rejects.toThrow(/expected one key/);
  });

  it('refuses a key of a type it cannot sign with', async () => {
    await expect(parsePrivateKey(keyFile({ type: 'ssh-dss' }))).rejects.toThrow(
      /ssh-dss keys are not read/,
    );
  });

  it('refuses a key whose private half does not match the public key stored with it', async () => {
    await expect(parsePrivateKey(keyFile({ publicByte: 9 }))).rejects.toThrow(
      /does not match the public key/,
    );
  });

  it('notices a file that did not decrypt, where the two check values differ', async () => {
    await expect(parsePrivateKey(keyFile({ check: [1, 2] }))).rejects.toThrow(/did not decrypt/);
  });

  it('refuses something that is not a key at all', async () => {
    await expect(parsePrivateKey('hello')).rejects.toThrow();
  });
});
