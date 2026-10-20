import { concat, type Bytes } from '../wire';

/**
 * All this package needs from a runtime: two byte streams and a way to hang
 * up. `cloudflare:sockets` provides one, underfetch's proxy tunnel provides
 * one, a WebSocket to Cloudflare Tunnel provides one, an SSH channel to a jump
 * host is one, and so is a pair of in-memory streams in a test.
 */
export interface ByteSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close?(): Promise<void>;
}

/** A readable stream read by exact lengths and by lines. */
export class Buffered {
  #buffer: Bytes = new Uint8Array(0);
  #ended = false;
  readonly #reader: ReadableStreamDefaultReader<Uint8Array>;

  constructor(stream: ReadableStream<Uint8Array>) {
    this.#reader = stream.getReader();
  }

  async #pull(): Promise<boolean> {
    if (this.#ended) return false;
    const { value, done } = await this.#reader.read();
    if (done) {
      this.#ended = true;
      return false;
    }
    if (value?.length) {
      this.#buffer = this.#buffer.length ? concat([this.#buffer, value]) : new Uint8Array(value);
    }
    return true;
  }

  async exactly(length: number): Promise<Bytes> {
    while (this.#buffer.length < length) {
      if (!(await this.#pull())) {
        throw new Error(`the connection ended after ${this.#buffer.length} of ${length} bytes`);
      }
    }
    const taken = this.#buffer.slice(0, length);
    this.#buffer = this.#buffer.subarray(length);
    return taken;
  }

  /** One CRLF-terminated line, refusing to buffer a hostile server's flood. */
  async line(limit: number): Promise<string> {
    for (;;) {
      const at = this.#buffer.indexOf(10);
      if (at !== -1) {
        const line = this.#buffer.subarray(0, at);
        this.#buffer = this.#buffer.subarray(at + 1);
        return new TextDecoder().decode(line).replace(/\r$/, '');
      }
      if (this.#buffer.length > limit) {
        throw new Error(`the server sent ${this.#buffer.length} bytes without a line`);
      }
      if (!(await this.#pull())) throw new Error('the connection ended before a line arrived');
    }
  }

  cancel(): void {
    void this.#reader.cancel().catch(() => {});
  }
}
