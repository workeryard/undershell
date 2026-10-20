/**
 * SSH's wire types (RFC 4251 §5). Everything in the protocol is built from
 * these five, so they are worth having exactly right: a `string` is a
 * length-prefixed byte array, not text, and an `mpint` is a signed big-endian
 * integer that grows a leading zero when its top bit is set.
 */

/** A view over a plain ArrayBuffer: what WebCrypto and the streams accept. */
export type Bytes = Uint8Array<ArrayBuffer>;

export class Writer {
  #parts: Uint8Array[] = [];
  #length = 0;

  #push(part: Uint8Array): this {
    this.#parts.push(part);
    this.#length += part.length;
    return this;
  }

  byte(value: number): this {
    return this.#push(new Uint8Array([value]));
  }

  bool(value: boolean): this {
    return this.byte(value ? 1 : 0);
  }

  uint32(value: number): this {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value >>> 0);
    return this.#push(out);
  }

  /** Raw bytes, with no length in front of them. */
  raw(value: Uint8Array): this {
    return this.#push(value);
  }

  string(value: Uint8Array | string): this {
    const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
    return this.uint32(bytes.length).#push(bytes);
  }

  nameList(names: string[]): this {
    return this.string(names.join(","));
  }

  /** A positive integer: leading zeros dropped, one added back if the top bit is set. */
  mpint(value: Uint8Array): this {
    let start = 0;
    while (start < value.length && value[start] === 0) start++;
    const trimmed = value.subarray(start);
    if (trimmed.length === 0) return this.uint32(0);
    if (trimmed[0]! & 0x80) {
      const padded = new Uint8Array(trimmed.length + 1);
      padded.set(trimmed, 1);
      return this.string(padded);
    }
    return this.string(trimmed);
  }

  build(): Bytes {
    const out = new Uint8Array(this.#length);
    let at = 0;
    for (const part of this.#parts) {
      out.set(part, at);
      at += part.length;
    }
    return out;
  }
}

export class Reader {
  #at = 0;
  readonly #view: DataView;

  constructor(readonly bytes: Bytes) {
    this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get done(): boolean {
    return this.#at >= this.bytes.length;
  }

  byte(): number {
    if (this.#at >= this.bytes.length) throw new Error("packet ended early");
    return this.bytes[this.#at++]!;
  }

  bool(): boolean {
    return this.byte() !== 0;
  }

  uint32(): number {
    if (this.#at + 4 > this.bytes.length) throw new Error("packet ended early");
    const value = this.#view.getUint32(this.#at);
    this.#at += 4;
    return value;
  }

  string(): Bytes {
    const length = this.uint32();
    if (this.#at + length > this.bytes.length) throw new Error("packet ended early");
    const value = this.bytes.subarray(this.#at, this.#at + length);
    this.#at += length;
    return value;
  }

  text(): string {
    return new TextDecoder().decode(this.string());
  }

  nameList(): string[] {
    const value = this.text();
    return value === "" ? [] : value.split(",");
  }

  skipString(): void {
    this.string();
  }
}

export function concat(parts: Uint8Array[]): Bytes {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}
