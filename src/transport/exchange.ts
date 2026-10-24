/**
 * The parts of a key exchange that are calculation, not conversation:
 * the KEXINIT we send, what is chosen from the server's, the exchange hash
 * (RFC 4253 §8, RFC 5656 §4) and the keys derived from it (§7.2).
 */

import { digest, randomBytes, type Hash } from '../crypto';
import { Reader, Writer, type Bytes } from '../wire';
import {
  choose,
  isGcm,
  type CipherName,
  type KexName,
  type MacName,
  type Preference,
} from './algorithms';
import { keyLengths, packetCipher, type Opener, type Sealer } from './cipher';
import { MSG } from './messages';

export const KEX_STRICT = 'kex-strict-c-v00@openssh.com';
export const KEX_STRICT_SERVER = 'kex-strict-s-v00@openssh.com';
const EXT_INFO = 'ext-info-c';

export function kexinit(p: Preference, first: boolean): Bytes {
  return (
    new Writer()
      .byte(MSG.KEXINIT)
      .raw(randomBytes(16))
      // ext-info-c and strict KEX are asked for in the first exchange only.
      .nameList(first ? [...p.kex, EXT_INFO, KEX_STRICT] : p.kex)
      .nameList(p.hostKey)
      .nameList(p.cipher)
      .nameList(p.cipher)
      .nameList(p.mac)
      .nameList(p.mac)
      .nameList(['none'])
      .nameList(['none'])
      .nameList([])
      .nameList([])
      .bool(false)
      .uint32(0)
      .build()
  );
}

export interface Chosen {
  kex: KexName;
  hostKey: string;
  cipher: { out: CipherName; in: CipherName };
  /** Null in a direction whose cipher is GCM. */
  mac: { out: MacName | null; in: MacName | null };
  strictOffered: boolean;
  /** The server sent a guessed key exchange packet, and guessed wrong: it is to be dropped. */
  dropGuess: boolean;
}

export function negotiate(p: Preference, theirs: Bytes): Chosen {
  const reader = new Reader(theirs.subarray(17)); // the message byte and a 16-byte cookie
  const kexList = reader.nameList();
  const hostKeyList = reader.nameList();
  const cipherOut = reader.nameList();
  const cipherIn = reader.nameList();
  const macOut = reader.nameList();
  const macIn = reader.nameList();
  for (let index = 0; index < 4; index++) reader.skipString(); // compression and languages
  const guessFollows = reader.bool();

  const kex = choose('key exchange', p.kex, kexList);
  const hostKey = choose('host key algorithm', p.hostKey, hostKeyList);
  const cipher = {
    out: choose('cipher to the server', p.cipher, cipherOut),
    in: choose('cipher to the client', p.cipher, cipherIn),
  };
  return {
    kex,
    hostKey,
    cipher,
    mac: {
      out: isGcm(cipher.out) ? null : choose('MAC to the server', p.mac, macOut),
      in: isGcm(cipher.in) ? null : choose('MAC to the client', p.mac, macIn),
    },
    strictOffered: kexList.includes(KEX_STRICT_SERVER),
    // RFC 4253 §7: a wrong guess is a key exchange packet sent ahead, to be ignored.
    dropGuess: guessFollows && (kexList[0] !== kex || hostKeyList[0] !== hostKey),
  };
}

/** The two directions' packet ciphers, from K, H and the session id. */
export async function deriveCiphers(
  hash: Hash,
  secret: Bytes,
  exchange: Bytes,
  sessionId: Bytes,
  chosen: Chosen,
): Promise<{ outgoing: Sealer; incoming: Opener }> {
  const prefix = new Writer().raw(secret).raw(exchange).build();
  const derive = async (letter: string, length: number): Promise<Bytes> => {
    let material = await digest(
      hash,
      new Writer().raw(prefix).byte(letter.charCodeAt(0)).raw(sessionId).build(),
    );
    while (material.length < length) {
      const more = await digest(hash, new Writer().raw(prefix).raw(material).build());
      material = new Writer().raw(material).raw(more).build();
    }
    return material.slice(0, length);
  };
  // A GCM direction has no MAC; the name stands in only to size nothing.
  const macOut = chosen.mac.out ?? 'hmac-sha2-256';
  const macIn = chosen.mac.in ?? 'hmac-sha2-256';
  const sizeOut = keyLengths(chosen.cipher.out, macOut);
  const sizeIn = keyLengths(chosen.cipher.in, macIn);
  const keysOut = {
    iv: await derive('A', sizeOut.iv),
    key: await derive('C', sizeOut.key),
    macKey: await derive('E', sizeOut.mac),
  };
  const keysIn = {
    iv: await derive('B', sizeIn.iv),
    key: await derive('D', sizeIn.key),
    macKey: await derive('F', sizeIn.mac),
  };
  return {
    outgoing: await packetCipher(chosen.cipher.out, macOut, keysOut, 'encrypt'),
    incoming: await packetCipher(chosen.cipher.in, macIn, keysIn, 'decrypt'),
  };
}
