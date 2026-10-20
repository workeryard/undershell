/**
 * A client key, reduced to what authentication needs: the public blob the
 * server looks up in authorized_keys, and a way to sign. Whatever file it
 * came from, it ends up as non-extractable WebCrypto keys; the private
 * numbers are not kept once those exist.
 */

import { base64Url, subtle } from '../crypto';
import { fixedLength, Writer, type Bytes } from '../wire';
import { CURVES, ecdsaToSsh } from './public-key';

export interface PrivateKey {
  /** The key's type as its public blob names it: ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256… */
  type: string;
  /** The blob as it goes on the wire, and in authorized_keys after the type. */
  publicKeyBlob: Bytes;
  /** The signature algorithms it can make, the one to prefer first. */
  algorithms: readonly string[];
  /** SSH's signature encoding: string algorithm, string signature. */
  sign(algorithm: string, data: Bytes): Promise<Bytes>;
}

const signature = (algorithm: string, bytes: Uint8Array) =>
  new Writer().string(algorithm).string(bytes).build();

/** PKCS#8 for Ed25519 is this fixed prefix and then the seed. */
const ED25519_PKCS8 = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export async function ed25519Key(seed: Bytes, publicKey: Bytes): Promise<PrivateKey> {
  if (seed.length !== 32 || publicKey.length !== 32)
    throw new Error('an ed25519 key that is not 32 bytes');
  const pkcs8 = new Uint8Array(ED25519_PKCS8.length + 32);
  pkcs8.set(ED25519_PKCS8);
  pkcs8.set(seed, ED25519_PKCS8.length);
  const key = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  return {
    type: 'ssh-ed25519',
    publicKeyBlob: new Writer().string('ssh-ed25519').string(publicKey).build(),
    algorithms: ['ssh-ed25519'],
    async sign(_algorithm, data) {
      return signature(
        'ssh-ed25519',
        new Uint8Array(await subtle.sign({ name: 'Ed25519' }, key, data)),
      );
    },
  };
}

const toBig = (bytes: Uint8Array) =>
  BigInt(`0x${[...bytes].map((b) => b.toString(16).padStart(2, '0')).join('') || '0'}`);
function fromBig(value: bigint): Bytes {
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return new Uint8Array(hex.match(/../g)!.map((pair) => parseInt(pair, 16)));
}

export interface RsaNumbers {
  n: Bytes;
  e: Bytes;
  d: Bytes;
  p: Bytes;
  q: Bytes;
  /** q⁻¹ mod p, which OpenSSH calls iqmp and JWK calls qi. */
  qi: Bytes;
}

export async function rsaKey(numbers: RsaNumbers): Promise<PrivateKey> {
  const d = toBig(numbers.d);
  const jwk = {
    kty: 'RSA',
    n: base64Url(numbers.n),
    e: base64Url(numbers.e),
    d: base64Url(numbers.d),
    p: base64Url(numbers.p),
    q: base64Url(numbers.q),
    // OpenSSH's file has no CRT exponents; WebCrypto wants them.
    dp: base64Url(fromBig(d % (toBig(numbers.p) - 1n))),
    dq: base64Url(fromBig(d % (toBig(numbers.q) - 1n))),
    qi: base64Url(numbers.qi),
  };
  // WebCrypto binds the hash to the key, so one key per signature algorithm.
  const keys = {
    'rsa-sha2-512': await subtle.importKey(
      'jwk',
      { ...jwk, alg: 'RS512' },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
      false,
      ['sign'],
    ),
    'rsa-sha2-256': await subtle.importKey(
      'jwk',
      { ...jwk, alg: 'RS256' },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign'],
    ),
  };
  return {
    type: 'ssh-rsa',
    publicKeyBlob: new Writer().string('ssh-rsa').mpint(numbers.e).mpint(numbers.n).build(),
    algorithms: ['rsa-sha2-512', 'rsa-sha2-256'],
    async sign(algorithm, data) {
      const key = keys[algorithm as keyof typeof keys];
      if (!key)
        throw new Error(`an RSA key does not sign ${algorithm} here; SHA-1 ssh-rsa is not offered`);
      return signature(
        algorithm,
        new Uint8Array(await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, key, data)),
      );
    },
  };
}

/** `point` is the uncompressed 0x04 || x || y; `scalar` the private d. */
export async function ecdsaKey(type: string, point: Bytes, scalar: Bytes): Promise<PrivateKey> {
  const curve = CURVES[type];
  if (!curve) throw new Error(`${type} is not an ECDSA key this client signs with`);
  if (point.length !== 1 + 2 * curve.size || point[0] !== 4)
    throw new Error(`a ${type} public key that is not an uncompressed point`);
  const key = await subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: curve.webCrypto,
      x: base64Url(point.subarray(1, 1 + curve.size), true),
      y: base64Url(point.subarray(1 + curve.size), true),
      d: base64Url(fixedLength(scalar, curve.size), true),
    },
    { name: 'ECDSA', namedCurve: curve.webCrypto },
    false,
    ['sign'],
  );
  return {
    type,
    publicKeyBlob: new Writer().string(type).string(curve.id).string(point).build(),
    algorithms: [type],
    async sign(_algorithm, data) {
      const raw = new Uint8Array(await subtle.sign({ name: 'ECDSA', hash: curve.hash }, key, data));
      return signature(type, ecdsaToSsh(raw));
    },
  };
}
