import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { fromBase64 } from '../../src/crypto';
import { parsePrivateKey } from '../../src/keys/pem';
import { fingerprintOf, sshToEcdsa, verifySignature } from '../../src/keys/public-key';
import { Reader } from '../../src/wire';

/**
 * Every key format the client reads, as ssh-keygen and openssl wrote it.
 * Each signature is checked twice: by this package's own verifier, which
 * checks host keys, and by Node's OpenSSL from the .pub file, which shares
 * no code with either.
 */
const fixture = (name: string) =>
  readFileSync(new URL(`../fixtures/keys/${name}`, import.meta.url), 'utf8');
const PASSPHRASE = 'fixture passphrase';

const KEYS = [
  'ed25519',
  'ed25519-gcm',
  'ed25519-pkcs8',
  'ecdsa256',
  'ecdsa256-aes128ctr',
  'ecdsa256-sec1',
  'ecdsa384',
  'ecdsa384-pkcs8',
  'ecdsa521',
  'rsa',
  'rsa-pkcs1',
  'rsa-pkcs8',
];

/** The .pub line as Node's OpenSSL reads it, to check a signature without this package. */
function nodeVerify(
  algorithm: string,
  pub: string,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  const blob = fromBase64(pub.split(' ')[1]!);
  const reader = new Reader(blob);
  const type = reader.text();
  const signed = new Reader(signature as Uint8Array<ArrayBuffer>);
  signed.text();
  let bytes = signed.string();
  if (type === 'ssh-ed25519') {
    const key = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(reader.string()).toString('base64url') },
      format: 'jwk',
    });
    return verify(null, data, key, bytes);
  }
  if (type === 'ssh-rsa') {
    const e = Buffer.from(reader.mpint()).toString('base64url');
    const n = Buffer.from(reader.mpint()).toString('base64url');
    const key = createPublicKey({ key: { kty: 'RSA', n, e }, format: 'jwk' });
    return verify(algorithm === 'rsa-sha2-512' ? 'sha512' : 'sha256', data, key, bytes);
  }
  const size = { nistp256: 32, nistp384: 48, nistp521: 66 }[reader.text()]!;
  const point = reader.string();
  const crv = { 32: 'P-256', 48: 'P-384', 66: 'P-521' }[size]!;
  const x = Buffer.from(point.subarray(1, 1 + size)).toString('base64url');
  const y = Buffer.from(point.subarray(1 + size)).toString('base64url');
  const key = createPublicKey({ key: { kty: 'EC', crv, x, y }, format: 'jwk' });
  bytes = sshToEcdsa(bytes, size);
  const hash = { 32: 'sha256', 48: 'sha384', 66: 'sha512' }[size]!;
  return verify(hash, data, { key, dsaEncoding: 'ieee-p1363' }, bytes);
}

describe('keys as ssh-keygen and openssl write them', () => {
  for (const name of KEYS) {
    it(`reads ${name}, and signs what OpenSSL and this verifier accept`, async () => {
      const key = await parsePrivateKey(fixture(name), PASSPHRASE);
      const pub = fixture(`${name}.pub`).trim();
      // The public blob is exactly what the .pub file holds.
      expect(`${key.type} ${Buffer.from(key.publicKeyBlob).toString('base64')}`).toBe(
        pub.split(' ').slice(0, 2).join(' '),
      );
      expect(`SHA256:${await fingerprintOf(key.publicKeyBlob)}`).toBe(
        fixture(`${name}.fingerprint`).trim(),
      );

      const data = new TextEncoder().encode(`signed by ${name}`);
      for (const algorithm of key.algorithms) {
        const signature = await key.sign(algorithm, data);
        expect(await verifySignature(algorithm, key.publicKeyBlob, signature, data)).toBe(true);
        expect(nodeVerify(algorithm, pub, data, signature)).toBe(true);
        // And not over anything else.
        expect(
          await verifySignature(algorithm, key.publicKeyBlob, signature, new Uint8Array([1])),
        ).toBe(false);
      }
    });
  }

  it('offers RSA as rsa-sha2-512 first, and never SHA-1', async () => {
    const key = await parsePrivateKey(fixture('rsa'));
    expect(key.algorithms).toEqual(['rsa-sha2-512', 'rsa-sha2-256']);
    await expect(key.sign('ssh-rsa', new Uint8Array(1))).rejects.toThrow(
      /SHA-1 ssh-rsa is not offered/,
    );
  });

  it('says a GCM-encrypted key was given the wrong passphrase', async () => {
    await expect(parsePrivateKey(fixture('ed25519-gcm'), 'wrong')).rejects.toThrow(
      /passphrase does not open this key/,
    );
  });

  it('refuses an encrypted PEM, and says how to convert it', async () => {
    const pem =
      '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----';
    await expect(parsePrivateKey(pem)).rejects.toThrow(/ssh-keygen -p/);
  });

  it('names a PuTTY key for what it is', async () => {
    await expect(parsePrivateKey('PuTTY-User-Key-File-3: ssh-ed25519\n')).rejects.toThrow(
      /PuTTYgen/,
    );
  });
});

describe('Ed25519 against RFC 8032', () => {
  // §7.1, TEST 1: the empty message.
  const seed = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
  const publicKey = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
  const expected =
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

  it('signs the empty message as the RFC says, from an OpenSSH container', async () => {
    const { Writer } = await import('../../src/wire');
    const hex = (value: string) => Uint8Array.from(Buffer.from(value, 'hex'));
    const blob = new Writer().string('ssh-ed25519').string(hex(publicKey)).build();
    const secret = new Writer()
      .uint32(7)
      .uint32(7)
      .string('ssh-ed25519')
      .string(hex(publicKey))
      .string(new Uint8Array([...hex(seed), ...hex(publicKey)]))
      .string('')
      .raw(new Uint8Array([1, 2, 3, 4, 5, 6, 7]))
      .build();
    const body = new Writer()
      .raw(new TextEncoder().encode('openssh-key-v1\0'))
      .string('none')
      .string('none')
      .string('')
      .uint32(1)
      .string(blob)
      .string(secret)
      .build();
    const file = `-----BEGIN OPENSSH PRIVATE KEY-----\n${Buffer.from(body).toString('base64')}\n-----END OPENSSH PRIVATE KEY-----`;
    const key = await parsePrivateKey(file);
    const signature = new Reader(await key.sign('ssh-ed25519', new Uint8Array(0)));
    expect(signature.text()).toBe('ssh-ed25519');
    expect(Buffer.from(signature.string()).toString('hex')).toBe(expected);
  });
});
