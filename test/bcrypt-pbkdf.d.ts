/** The reference implementation the tests compare with ships no types. */
declare module 'bcrypt-pbkdf' {
  const bcrypt: {
    pbkdf(
      password: Uint8Array,
      passwordLength: number,
      salt: Uint8Array,
      saltLength: number,
      out: Uint8Array,
      outLength: number,
      rounds: number,
    ): number;
  };
  export default bcrypt;
}
