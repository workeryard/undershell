/**
 * `bcrypt-pbkdf` ships no types. Only `pbkdf` is used, and only the way
 * OpenSSH calls it: a passphrase and a salt in, key material out.
 */
declare module "bcrypt-pbkdf" {
  export function pbkdf(
    password: Uint8Array,
    passwordLength: number,
    salt: Uint8Array,
    saltLength: number,
    out: Uint8Array,
    outLength: number,
    rounds: number,
  ): number;
  const _default: { pbkdf: typeof pbkdf };
  export default _default;
}
