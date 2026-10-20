/**
 * Just enough DER to read the PEM private keys OpenSSL and `ssh-keygen -m`
 * write (PKCS#1, SEC1 and PKCS#8), and to wrap one in PKCS#8 for WebCrypto.
 * Lengths up to four bytes, no indefinite forms: DER has none.
 */

import { concat, type Bytes } from '../wire';

export const TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  SEQUENCE: 0x30,
} as const;

export class Der {
  #at = 0;

  constructor(readonly bytes: Bytes) {}

  get done(): boolean {
    return this.#at >= this.bytes.length;
  }

  /** The next element's tag, without reading it. */
  peek(): number | undefined {
    return this.bytes[this.#at];
  }

  next(expected?: number): { tag: number; content: Bytes } {
    const tag = this.bytes[this.#at];
    if (tag === undefined) throw new Error('the key ended early');
    if (expected !== undefined && tag !== expected) {
      throw new Error(
        `the key has element 0x${tag.toString(16)} where 0x${expected.toString(16)} belongs`,
      );
    }
    let at = this.#at + 1;
    let length = this.bytes[at++] ?? 0;
    if (length & 0x80) {
      const count = length & 0x7f;
      if (count === 0 || count > 4) throw new Error('the key has a length DER does not allow');
      length = 0;
      for (let index = 0; index < count; index++) length = length * 256 + (this.bytes[at++] ?? 0);
    }
    if (at + length > this.bytes.length) throw new Error('the key ended early');
    this.#at = at + length;
    return { tag, content: this.bytes.subarray(at, at + length) };
  }

  sequence(): Der {
    return new Der(this.next(TAG.SEQUENCE).content);
  }

  /** An INTEGER's magnitude, its sign byte dropped. */
  integer(): Bytes {
    const value = this.next(TAG.INTEGER).content;
    return value[0] === 0 && value.length > 1 ? value.subarray(1) : value;
  }

  octetString(): Bytes {
    return this.next(TAG.OCTET_STRING).content;
  }

  /** An OBJECT IDENTIFIER, dotted. */
  oid(): string {
    const bytes = this.next(TAG.OID).content;
    const parts = [Math.floor(bytes[0]! / 40), bytes[0]! % 40];
    let value = 0;
    for (const byte of bytes.subarray(1)) {
      value = value * 128 + (byte & 0x7f);
      if (!(byte & 0x80)) {
        parts.push(value);
        value = 0;
      }
    }
    return parts.join('.');
  }
}

function length(value: number): Bytes {
  if (value < 0x80) return new Uint8Array([value]);
  const bytes: number[] = [];
  for (let left = value; left > 0; left = Math.floor(left / 256)) bytes.unshift(left & 0xff);
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

export function element(tag: number, ...content: Uint8Array[]): Bytes {
  const body = concat(content);
  return concat([new Uint8Array([tag]), length(body.length), body]);
}

/** A dotted OBJECT IDENTIFIER, encoded. */
export function oid(dotted: string): Bytes {
  const [first = 0, second = 0, ...rest] = dotted.split('.').map(Number);
  const bytes = [first * 40 + second];
  for (const part of rest) {
    const groups = [part & 0x7f];
    for (let left = Math.floor(part / 128); left > 0; left = Math.floor(left / 128))
      groups.unshift(0x80 | (left & 0x7f));
    bytes.push(...groups);
  }
  return element(TAG.OID, new Uint8Array(bytes));
}
