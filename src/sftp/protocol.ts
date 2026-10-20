/**
 * SFTP version 3's framing and requests (draft-ietf-secsh-filexfer-02),
 * which is what every OpenSSH since 2001 speaks. It rides a session channel
 * running the `sftp` subsystem, so everything below the channel — the
 * cipher, the host key, flow control — is not repeated here.
 *
 * Requests carry ids and may be answered in any order, so several can be in
 * flight at once; that is what makes a transfer fast over a long round trip.
 */

import type { Session } from '../connection/session';
import { Buffered } from '../transport/buffered';
import { toError } from '../transport/messages';
import { Reader, Writer, type Bytes } from '../wire';

export const FXP = {
  INIT: 1,
  VERSION: 2,
  OPEN: 3,
  CLOSE: 4,
  READ: 5,
  WRITE: 6,
  LSTAT: 7,
  FSTAT: 8,
  OPENDIR: 11,
  READDIR: 12,
  REMOVE: 13,
  MKDIR: 14,
  RMDIR: 15,
  REALPATH: 16,
  STAT: 17,
  RENAME: 18,
  STATUS: 101,
  HANDLE: 102,
  DATA: 103,
  NAME: 104,
  ATTRS: 105,
  EXTENDED: 200,
} as const;

export const STATUS = { OK: 0, EOF: 1, NO_SUCH_FILE: 2 } as const;

/** What a status code means, when the server does not say. */
const STATUS_TEXT: Record<number, string> = {
  2: 'no such file',
  3: 'permission denied',
  4: 'failed',
  5: 'a bad message',
  6: 'no connection',
  7: 'the connection was lost',
  8: 'an unsupported operation',
};

const VERSION = 3;
/** OpenSSH's sftp-server takes up to 256 KiB a message; nothing sent here is larger. */
const MAX_MESSAGE = 512 * 1024;

export class SftpError extends Error {
  override name = 'SftpError';
  constructor(
    /** SSH_FX_*: 2 no such file, 3 permission denied, 4 failure, 8 unsupported. */
    readonly code: number,
    message: string,
  ) {
    super(message);
  }
}

export interface Reply {
  type: number;
  reader: Reader;
}

interface Pending {
  resolve(reply: Reply): void;
  reject(error: unknown): void;
}

export class Protocol {
  #nextId = 1;
  #failure: unknown = null;
  readonly #pending = new Map<number, Pending>();
  readonly #writer: WritableStreamDefaultWriter<Uint8Array>;
  /** What the server's VERSION offered beyond v3, such as posix-rename@openssh.com. */
  readonly extensions = new Map<string, string>();

  private constructor(readonly session: Session) {
    this.#writer = session.stdin.getWriter();
  }

  static async start(session: Session): Promise<Protocol> {
    const protocol = new Protocol(session);
    // sftp-server's own diagnostics; nothing reads them, so they are let go.
    void session.stderr.cancel().catch(() => {});
    const input = new Buffered(session.stdout);
    try {
      await protocol.#write(new Writer().byte(FXP.INIT).uint32(VERSION).build());
      const hello = new Reader(await Protocol.#frame(input));
      const type = hello.byte();
      if (type !== FXP.VERSION)
        throw new Error(`expected the sftp version, got packet type ${type}`);
      const version = hello.uint32();
      if (version < VERSION)
        throw new Error(`the server speaks sftp ${version}, and this client needs ${VERSION}`);
      while (!hello.done) protocol.extensions.set(hello.text(), hello.text());
    } catch (error) {
      await session.close().catch(() => {});
      throw error;
    }
    void protocol.#read(input);
    return protocol;
  }

  static async #frame(input: Buffered): Promise<Bytes> {
    const length = new Reader(await input.exactly(4)).uint32();
    if (length === 0 || length > MAX_MESSAGE) throw new Error(`an sftp packet of ${length} bytes`);
    return input.exactly(length);
  }

  async #read(input: Buffered): Promise<void> {
    try {
      for (;;) {
        const reader = new Reader(await Protocol.#frame(input));
        const type = reader.byte();
        const id = reader.uint32();
        const pending = this.#pending.get(id);
        if (!pending)
          throw new Error(`the server answered sftp request ${id}, which was not asked`);
        this.#pending.delete(id);
        pending.resolve({ type, reader });
      }
    } catch (error) {
      this.#fail(
        error instanceof Error && /connection ended/.test(error.message)
          ? new Error('the server closed the sftp channel')
          : error,
      );
    }
  }

  #fail(error: unknown): void {
    this.#failure ??= error;
    for (const pending of this.#pending.values()) pending.reject(this.#failure);
    this.#pending.clear();
  }

  #write(packet: Bytes): Promise<void> {
    return this.#writer.write(new Writer().uint32(packet.length).raw(packet).build());
  }

  /** Sends one request and waits for the answer with its id. */
  request(type: number, build: (writer: Writer) => Writer): Promise<Reply> {
    if (this.#failure) return Promise.reject(toError(this.#failure));
    const id = this.#nextId;
    this.#nextId = (this.#nextId + 1) >>> 0 || 1;
    const reply = new Promise<Reply>((resolve, reject) =>
      this.#pending.set(id, { resolve, reject }),
    );
    this.#write(build(new Writer().byte(type).uint32(id)).build()).catch((error: unknown) =>
      this.#fail(error),
    );
    return reply;
  }

  /** A request answered by a STATUS: resolves on OK, and on EOF when `eof` allows it. */
  async status(type: number, build: (writer: Writer) => Writer, what: string): Promise<void> {
    expectStatus(await this.request(type, build), what);
  }

  async end(): Promise<void> {
    this.#fail(new Error('the sftp session has ended'));
    await this.#writer.close().catch(() => {});
    await this.session.close().catch(() => {});
  }
}

/** Throws the server's error for a STATUS other than OK; true for EOF. */
export function expectStatus(reply: Reply, what: string, allowEof = false): boolean {
  if (reply.type !== FXP.STATUS)
    throw new Error(`expected a status for ${what}, got packet type ${reply.type}`);
  const code = reply.reader.uint32();
  if (code === STATUS.OK) return false;
  if (code === STATUS.EOF && allowEof) return true;
  const said = reply.reader.done ? '' : reply.reader.text();
  throw new SftpError(code, `${what}: ${said || STATUS_TEXT[code] || `sftp error ${code}`}`);
}

/** The reply of `type`, or the server's error if it answered with a STATUS instead. */
export function expectType(reply: Reply, type: number, what: string): Reader {
  if (reply.type === type) return reply.reader;
  expectStatus(reply, what);
  throw new Error(`expected packet type ${type} for ${what}, got ${reply.type}`);
}
