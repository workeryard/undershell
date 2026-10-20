/**
 * One seam for WebCrypto.
 *
 * This package is compiled twice: once against the DOM lib, where a key
 * agreement takes `{ name: "X25519", public: key }`, and once against
 * `@cloudflare/workers-types`, whose generator renames that property to
 * `$public` and drops `KeyUsage` and `AlgorithmIdentifier` entirely. The
 * runtime is the same in both; only the type definitions disagree.
 *
 * Rather than scatter casts through the protocol code, the surface is narrowed
 * here, to the handful of calls actually used. What this loses in type safety
 * the tests and the end-to-end run against a live sshd give back: a wrong
 * algorithm name fails immediately and loudly.
 */
export const subtle = crypto.subtle as unknown as {
  digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer>;
  generateKey(algorithm: unknown, extractable: boolean, usages: string[]): Promise<CryptoKeyPair>;
  importKey(
    format: "raw" | "pkcs8" | "jwk",
    key: unknown,
    algorithm: unknown,
    extractable: boolean,
    usages: string[],
  ): Promise<CryptoKey>;
  exportKey(format: "raw", key: CryptoKey): Promise<ArrayBuffer>;
  deriveBits(algorithm: unknown, key: CryptoKey, length: number): Promise<ArrayBuffer>;
  sign(algorithm: unknown, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer>;
  verify(algorithm: unknown, key: CryptoKey, signature: Uint8Array, data: Uint8Array): Promise<boolean>;
  encrypt(algorithm: unknown, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer>;
  decrypt(algorithm: unknown, key: CryptoKey, data: Uint8Array): Promise<ArrayBuffer>;
};
