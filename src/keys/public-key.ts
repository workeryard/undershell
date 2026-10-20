/**
 * Public keys as SSH writes them (RFC 4253 §6.6, RFC 5656 §3.1, RFC 8709),
 * and checking a signature made with one. Used for the server's host key, and
 * by the tests to check what a client key signs.
 */

import { base64, base64Url, digest, subtle, type Hash } from '../crypto';
import { concat, fixedLength, Reader, Writer, type Bytes } from '../wire';

export interface Curve {
  /** The curve's SSH identifier, as it appears inside the key blob. */
  id: 'nistp256' | 'nistp384' | 'nistp521';
  webCrypto: 'P-256' | 'P-384' | 'P-521';
  hash: Hash;
  /** Bytes in a coordinate, a private scalar, and each half of a signature. */
  size: number;
}

export const CURVES: Record<string, Curve> = {
  'ecdsa-sha2-nistp256': { id: 'nistp256', webCrypto: 'P-256', hash: 'SHA-256', size: 32 },
  'ecdsa-sha2-nistp384': { id: 'nistp384', webCrypto: 'P-384', hash: 'SHA-384', size: 48 },
  'ecdsa-sha2-nistp521': { id: 'nistp521', webCrypto: 'P-521', hash: 'SHA-512', size: 66 },
};

/** OpenSSH refuses RSA keys below this, and so does this client. */
const MIN_RSA_BITS = 1024;

/** Base64 SHA-256 of the blob, as `ssh-keygen -lf` prints it, without the "SHA256:". */
export async function fingerprintOf(blob: Bytes): Promise<string> {
  return base64(await digest('SHA-256', blob)).replace(/=+$/, '');
}

/** The type a blob declares, which for RSA is "ssh-rsa" whatever hash signs. */
export function blobType(blob: Bytes): string {
  return new Reader(blob).text();
}

function rsaHash(algorithm: string): Hash | null {
  if (algorithm === 'rsa-sha2-256') return 'SHA-256';
  if (algorithm === 'rsa-sha2-512') return 'SHA-512';
  return null;
}

/** The RSA modulus's size in bits, from its big-endian bytes. */
function bitLength(value: Bytes): number {
  let start = 0;
  while (start < value.length && value[start] === 0) start++;
  if (start === value.length) return 0;
  return (value.length - start - 1) * 8 + (32 - Math.clz32(value[start]!));
}

/** r || s, as WebCrypto signs ECDSA, into SSH's mpint r, mpint s. */
export function ecdsaToSsh(signature: Bytes): Bytes {
  const half = signature.length / 2;
  return new Writer().mpint(signature.subarray(0, half)).mpint(signature.subarray(half)).build();
}

/** SSH's mpint r, mpint s, into the fixed-width r || s WebCrypto verifies. */
export function sshToEcdsa(blob: Bytes, size: number): Bytes {
  const reader = new Reader(blob);
  const r = reader.mpint();
  const s = reader.mpint();
  return concat([fixedLength(r, size), fixedLength(s, size)]);
}

/** A blob as a WebCrypto key that verifies signatures of `algorithm`. */
export async function importPublicKey(
  algorithm: string,
  blob: Bytes,
): Promise<{ key: CryptoKey; verify: unknown }> {
  const reader = new Reader(blob);
  const type = reader.text();

  if (algorithm === 'ssh-ed25519') {
    if (type !== 'ssh-ed25519') throw new Error(`the key is a ${type}, not the ssh-ed25519 agreed`);
    const raw = reader.string();
    if (raw.length !== 32) throw new Error(`an ed25519 key of ${raw.length} bytes`);
    const key = await subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
    return { key, verify: { name: 'Ed25519' } };
  }

  const curve = CURVES[algorithm];
  if (curve) {
    if (type !== algorithm) throw new Error(`the key is a ${type}, not the ${algorithm} agreed`);
    const id = reader.text();
    if (id !== curve.id) throw new Error(`a ${algorithm} key on the curve ${id}`);
    const point = reader.string();
    const key = await subtle.importKey(
      'raw',
      point,
      { name: 'ECDSA', namedCurve: curve.webCrypto },
      false,
      ['verify'],
    );
    return { key, verify: { name: 'ECDSA', hash: curve.hash } };
  }

  const hash = rsaHash(algorithm);
  if (hash) {
    // rsa-sha2-256/512 sign with an "ssh-rsa" blob: the algorithm names the
    // hash, not the key.
    if (type !== 'ssh-rsa') throw new Error(`the key is a ${type}, not the RSA agreed`);
    const exponent = reader.mpint();
    const modulus = reader.mpint();
    const bits = bitLength(modulus);
    if (bits < MIN_RSA_BITS)
      throw new Error(`an RSA key of ${bits} bits, below the ${MIN_RSA_BITS} accepted`);
    const key = await subtle.importKey(
      'jwk',
      {
        kty: 'RSA',
        n: base64Url(modulus),
        e: base64Url(exponent),
        alg: hash === 'SHA-512' ? 'RS512' : 'RS256',
      },
      { name: 'RSASSA-PKCS1-v1_5', hash },
      false,
      ['verify'],
    );
    return { key, verify: { name: 'RSASSA-PKCS1-v1_5' } };
  }

  throw new Error(`${algorithm} is not a signature this client can check`);
}

/**
 * Whether `signature` — SSH's string algorithm, string bytes — is `algorithm`
 * over `data` by the key in `blob`. A signature of another algorithm than the
 * one agreed is refused, not tried.
 */
export async function verifySignature(
  algorithm: string,
  blob: Bytes,
  signature: Bytes,
  data: Bytes,
): Promise<boolean> {
  const signed = new Reader(signature);
  const signatureType = signed.text();
  if (signatureType !== algorithm) {
    throw new Error(`the signature is a ${signatureType}, not the ${algorithm} that was agreed`);
  }
  let bytes = signed.string();
  const { key, verify } = await importPublicKey(algorithm, blob);
  const curve = CURVES[algorithm];
  if (curve) bytes = sshToEcdsa(bytes, curve.size);
  return subtle.verify(verify, key, bytes, data);
}

/** The `type base64` form of a key, as in authorized_keys and known_hosts. */
export function openSshPublicKey(blob: Bytes): string {
  return `${blobType(blob)} ${base64(blob)}`;
}
