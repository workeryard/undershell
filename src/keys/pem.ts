/**
 * The other files a private key arrives in: the PEM forms OpenSSL writes and
 * `ssh-keygen -m PEM` or `-m PKCS8` export. Unencrypted only; an encrypted
 * PEM uses OpenSSL's own MD5-based derivation or PBES2, and `ssh-keygen -p`
 * turns either into an OpenSSH file this reads with its passphrase.
 */

import { subtle } from '../crypto';
import { type Bytes } from '../wire';
import { Der, element, oid, TAG } from './der';
import { fromBase64 } from '../crypto';
import { isOpenSshKey, parseOpenSshKey } from './openssh';
import { ecdsaKey, ed25519Key, rsaKey, type PrivateKey } from './private-key';

const RSA = '1.2.840.113549.1.1.1';
const EC = '1.2.840.10045.2.1';
const ED25519 = '1.3.101.112';
const NAMED_CURVES: Record<string, string> = {
  '1.2.840.10045.3.1.7': 'ecdsa-sha2-nistp256',
  '1.3.132.0.34': 'ecdsa-sha2-nistp384',
  '1.3.132.0.35': 'ecdsa-sha2-nistp521',
};

/** PKCS#1 RSAPrivateKey: version, n, e, d, p, q, dp, dq, qi. */
function pkcs1(der: Bytes): Promise<PrivateKey> {
  const key = new Der(der).sequence();
  key.integer();
  const n = key.integer();
  const e = key.integer();
  const d = key.integer();
  const p = key.integer();
  const q = key.integer();
  key.integer();
  key.integer();
  return rsaKey({ n, e, d, p, q, qi: key.integer() });
}

/**
 * SEC1 ECPrivateKey. Its public point is optional, so rather than compute it
 * the key is wrapped in PKCS#8 and WebCrypto is asked for its JWK.
 */
async function sec1(der: Bytes, curveOid?: string): Promise<PrivateKey> {
  const key = new Der(der).sequence();
  key.integer();
  const scalar = key.octetString();
  let named = curveOid;
  let point: Bytes | undefined;
  while (!key.done) {
    const { tag, content } = key.next();
    if (tag === 0xa0) named = new Der(content).oid();
    if (tag === 0xa1) point = new Der(content).next(TAG.BIT_STRING).content.subarray(1);
  }
  const type = named && NAMED_CURVES[named];
  if (!type)
    throw new Error(
      `the EC key is on a curve this client does not sign with (${named ?? 'unnamed'})`,
    );
  if (!point) {
    const pkcs8 = element(
      TAG.SEQUENCE,
      element(TAG.INTEGER, new Uint8Array([0])),
      element(TAG.SEQUENCE, oid(EC), oid(named!)),
      element(TAG.OCTET_STRING, der),
    );
    const curve = { name: 'ECDSA', namedCurve: `P-${type.slice(-3)}` };
    const jwk = await subtle.exportKey(
      'jwk',
      await subtle.importKey('pkcs8', pkcs8, curve, true, ['sign']),
    );
    point = new Uint8Array([4, ...fromBase64(jwk.x!), ...fromBase64(jwk.y!)]);
  }
  return ecdsaKey(type, point, scalar);
}

async function pkcs8(der: Bytes): Promise<PrivateKey> {
  const outer = new Der(der).sequence();
  outer.integer();
  const algorithm = outer.sequence();
  const kind = algorithm.oid();
  const inner = outer.octetString();
  if (kind === RSA) return pkcs1(inner);
  if (kind === EC) return sec1(inner, algorithm.oid());
  if (kind === ED25519) {
    const seed = new Der(inner).octetString();
    const jwk = await subtle.exportKey(
      'jwk',
      await subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign']),
    );
    return ed25519Key(seed.slice(), fromBase64(jwk.x!));
  }
  throw new Error(`the PKCS#8 key is a ${kind}, which this client does not sign with`);
}

/**
 * Any private key file this client reads, recognised by its PEM label:
 * OpenSSH's own, PKCS#1 RSA, SEC1 EC, or unencrypted PKCS#8.
 */
export async function parsePrivateKey(text: string, passphrase = ''): Promise<PrivateKey> {
  const match = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(text);
  if (!match) {
    if (/PuTTY-User-Key-File/.test(text)) {
      throw new Error('this is a PuTTY key; export it from PuTTYgen as an OpenSSH key first');
    }
    throw new Error('no PEM private key was found in the text');
  }
  const [, label, body = ''] = match;
  if (/Proc-Type:\s*4,ENCRYPTED/.test(body) || label === 'ENCRYPTED PRIVATE KEY') {
    throw new Error(
      'the PEM key is encrypted, which only OpenSSH files are here; ssh-keygen -p -f <file> rewrites it as one',
    );
  }
  const der = fromBase64(body.replace(/^[A-Za-z-]+:.*$/gm, ''));
  switch (label) {
    case 'OPENSSH PRIVATE KEY':
      return parseOpenSshKey(der, passphrase);
    case 'RSA PRIVATE KEY':
      return pkcs1(der);
    case 'EC PRIVATE KEY':
      return sec1(der);
    case 'PRIVATE KEY':
      return isOpenSshKey(der) ? parseOpenSshKey(der, passphrase) : pkcs8(der);
    default:
      throw new Error(`a "${label}" is not a private key this client reads`);
  }
}
