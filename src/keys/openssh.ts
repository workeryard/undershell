/**
 * Reading a private key as `ssh-keygen` writes it: the "openssh-key-v1"
 * container (OpenSSH's PROTOCOL.key), not PEM, so WebCrypto cannot be handed
 * it directly; the numbers are dug out and re-wrapped.
 *
 * A key with a passphrase is unlocked here too: bcrypt_pbkdf for the key and
 * IV, then AES-CTR or AES-GCM over the private section. CBC is refused rather
 * than half-supported; `ssh-keygen` has not written it by default since 2018.
 */

import { subtle } from '../crypto';
import { Reader, type Bytes } from '../wire';
import { bcryptPbkdf } from './bcrypt-pbkdf';
import { ecdsaKey, ed25519Key, rsaKey, type PrivateKey } from './private-key';

const MAGIC = 'openssh-key-v1\0';

const CIPHERS: Record<string, { keyLength: number; ivLength: number; gcm: boolean }> = {
  'aes256-ctr': { keyLength: 32, ivLength: 16, gcm: false },
  'aes192-ctr': { keyLength: 24, ivLength: 16, gcm: false },
  'aes128-ctr': { keyLength: 16, ivLength: 16, gcm: false },
  'aes256-gcm@openssh.com': { keyLength: 32, ivLength: 12, gcm: true },
  'aes128-gcm@openssh.com': { keyLength: 16, ivLength: 12, gcm: true },
};

/**
 * Whether the passphrase was right is not known here: the two check values
 * inside the plaintext say so (or, for GCM, the tag), which is why they are
 * compared rather than trusted.
 */
async function unlock(
  section: Bytes,
  tag: Bytes,
  cipher: string,
  kdf: string,
  options: Bytes,
  passphrase: string,
): Promise<Bytes> {
  const spec = CIPHERS[cipher];
  if (!spec) throw new Error(`the key is encrypted with ${cipher}, which this client cannot read`);
  if (kdf !== 'bcrypt')
    throw new Error(`the key uses the ${kdf} derivation, which this client cannot read`);
  if (!passphrase) throw new Error('the key has a passphrase, and none was given');

  const reader = new Reader(options);
  const salt = reader.string();
  const rounds = reader.uint32();
  const material = await bcryptPbkdf(
    // Copied: a Worker's TextEncoder may hand back a view WebCrypto will not take.
    new Uint8Array(new TextEncoder().encode(passphrase)),
    salt,
    spec.keyLength + spec.ivLength,
    rounds,
  );
  const raw = material.subarray(0, spec.keyLength);
  const iv = material.subarray(spec.keyLength);

  if (spec.gcm) {
    const key = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
    const sealed = new Uint8Array(section.length + tag.length);
    sealed.set(section);
    sealed.set(tag, section.length);
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv }, key, sealed).catch(() => {
      throw new Error('the passphrase does not open this key');
    });
    return new Uint8Array(plain);
  }
  const key = await subtle.importKey('raw', raw, { name: 'AES-CTR' }, false, ['decrypt']);
  return new Uint8Array(
    await subtle.decrypt({ name: 'AES-CTR', counter: iv, length: 128 }, key, section),
  );
}

export function isOpenSshKey(der: Bytes): boolean {
  return new TextDecoder().decode(der.subarray(0, MAGIC.length)) === MAGIC;
}

export async function parseOpenSshKey(der: Bytes, passphrase: string): Promise<PrivateKey> {
  if (!isOpenSshKey(der)) throw new Error('not an OpenSSH private key');
  const reader = new Reader(der);
  reader.take(MAGIC.length);

  const cipher = reader.text();
  const kdf = reader.text();
  const kdfOptions = reader.string();
  const locked = cipher !== 'none';

  const count = reader.uint32();
  if (count !== 1) throw new Error(`expected one key in the file, found ${count}`);
  const publicKeyBlob = reader.string();

  const section = reader.string();
  // An AEAD cipher's tag follows the section, outside its length.
  const tag = locked && CIPHERS[cipher]?.gcm ? reader.take(16) : new Uint8Array(0);
  const secret = new Reader(
    locked ? await unlock(section, tag, cipher, kdf, kdfOptions, passphrase) : section,
  );
  if (secret.uint32() !== secret.uint32()) {
    // The format has no other way to tell a wrong passphrase from a corrupt file.
    throw new Error(
      locked
        ? 'the passphrase does not open this key'
        : 'the key did not decrypt (check values differ)',
    );
  }

  const type = secret.text();
  let key: PrivateKey;
  if (type === 'ssh-ed25519') {
    const publicKey = secret.string();
    const both = secret.string(); // seed (32) || public key (32)
    if (both.length !== 64) throw new Error(`expected a 64-byte private part, got ${both.length}`);
    key = await ed25519Key(both.slice(0, 32), publicKey.slice());
  } else if (type === 'ssh-rsa') {
    // n, e, d, iqmp, p, q: not the order the public blob uses.
    const n = secret.mpint();
    const e = secret.mpint();
    const d = secret.mpint();
    const qi = secret.mpint();
    const p = secret.mpint();
    const q = secret.mpint();
    key = await rsaKey({ n, e, d, p, q, qi });
  } else if (type.startsWith('ecdsa-sha2-')) {
    secret.skipString(); // the curve's name, which the type already says
    const point = secret.string();
    key = await ecdsaKey(type, point.slice(), secret.mpint().slice());
  } else {
    throw new Error(`${type} keys are not read here; ed25519, RSA and ECDSA are`);
  }
  secret.skipString(); // the comment

  const padding = secret.rest();
  if (padding.some((byte, index) => byte !== index + 1))
    throw new Error('the key has corrupt padding');
  if (!sameBytes(key.publicKeyBlob, publicKeyBlob)) {
    throw new Error("the key's private half does not match the public key stored with it");
  }
  return key;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}
