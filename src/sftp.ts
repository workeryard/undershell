/**
 * SFTP version 3, which is what every OpenSSH since 2001 speaks
 * (draft-ietf-secsh-filexfer-02). It rides an ordinary session channel asked
 * to start the `sftp` subsystem, so everything below the channel — key
 * exchange, the cipher, the host key — is the transport's job and not
 * repeated here.
 *
 * Only what a workflow does with a file: put one there, take one back, see
 * what is in a directory, remove one, make a directory.
 */

import { MSG, type Transport } from "./transport";
import { concat, Reader, Writer, type Bytes } from "./wire";

const FXP = {
  INIT: 1,
  VERSION: 2,
  OPEN: 3,
  CLOSE: 4,
  READ: 5,
  WRITE: 6,
  OPENDIR: 11,
  READDIR: 12,
  REMOVE: 13,
  MKDIR: 14,
  RMDIR: 15,
  STAT: 17,
  STATUS: 101,
  HANDLE: 102,
  DATA: 103,
  NAME: 104,
  ATTRS: 105,
} as const;

/** Open flags (§6.3). Only the combinations a transfer needs. */
const READ_FLAG = 0x1;
const WRITE_FLAG = 0x2;
const CREATE_FLAG = 0x8;
const TRUNCATE_FLAG = 0x10;

const STATUS_OK = 0;
const STATUS_EOF = 1;

/** What a status code means, when the server does not say. */
const STATUS_TEXT: Record<number, string> = {
  2: "no such file",
  3: "permission denied",
  4: "failed",
  5: "a bad message",
  6: "no connection",
  7: "the connection was lost",
  8: "an unsupported operation",
};

const VERSION = 3;
const WINDOW_SIZE = 2 * 1024 * 1024;
/** Each write is a channel packet; the server's own limit is honoured too. */
const CHUNK = 30 * 1024;
const MAX_FILE = 64 * 1024 * 1024;

export interface RemoteEntry {
  name: string;
  /** Bytes, from the attributes the server sent; null when it sent no size. */
  size: number | null;
  directory: boolean;
  /** Seconds since the epoch, or null when the server sent no time. */
  modifiedAt: number | null;
}

interface Attributes {
  size: number | null;
  permissions: number | null;
  modifiedAt: number | null;
}

function readAttributes(reader: Reader): Attributes {
  const flags = reader.uint32();
  const attributes: Attributes = { size: null, permissions: null, modifiedAt: null };
  if (flags & 0x1) {
    const high = reader.uint32();
    attributes.size = high * 2 ** 32 + reader.uint32();
  }
  if (flags & 0x2) {
    reader.uint32();
    reader.uint32();
  }
  if (flags & 0x4) attributes.permissions = reader.uint32();
  if (flags & 0x8) {
    reader.uint32();
    attributes.modifiedAt = reader.uint32();
  }
  if (flags & 0x80000000) {
    const count = reader.uint32();
    for (let index = 0; index < count; index++) {
      reader.skipString();
      reader.skipString();
    }
  }
  return attributes;
}

/** uint64, written as two words: file sizes exceed what a uint32 holds. */
function uint64(writer: Writer, value: number): Writer {
  return writer.uint32(Math.floor(value / 2 ** 32)).uint32(value >>> 0);
}

export class SftpError extends Error {
  override name = "SftpError";
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
  }
}

/**
 * One SFTP conversation over one channel. It owns the transport while it
 * lives, the way a command does, because a durable step holds neither open
 * afterwards.
 */
export class Sftp {
  #requestId = 1;
  #buffer: Bytes = new Uint8Array(0);
  #window = WINDOW_SIZE;
  #closed = false;

  private constructor(
    private readonly transport: Transport,
    private readonly channel: number,
    private readonly maxPacket: number,
  ) {}

  static async open(transport: Transport): Promise<Sftp> {
    await transport.send(
      new Writer().byte(MSG.CHANNEL_OPEN).string("session").uint32(0).uint32(WINDOW_SIZE).uint32(32768).build(),
    );

    let peer = 0;
    let maxPacket = 32768;
    for (;;) {
      const reply = await transport.receive();
      const type = reply[0];
      if (type === MSG.CHANNEL_OPEN_CONFIRMATION) {
        const reader = new Reader(reply.subarray(1));
        reader.uint32();
        peer = reader.uint32();
        reader.uint32();
        maxPacket = Math.min(reader.uint32(), 32768);
        break;
      }
      if (type === MSG.CHANNEL_OPEN_FAILURE) {
        const reader = new Reader(reply.subarray(1));
        reader.uint32();
        throw new Error(`the server would not open a session (reason ${reader.uint32()}): ${reader.text()}`);
      }
      throw new Error(`unexpected message ${type} while opening a channel`);
    }

    const sftp = new Sftp(transport, peer, maxPacket);
    await transport.send(
      new Writer().byte(MSG.CHANNEL_REQUEST).uint32(peer).string("subsystem").bool(true).string("sftp").build(),
    );
    const started = await sftp.#awaitChannelReply();
    if (!started) throw new Error("the server has no sftp subsystem, so files cannot be transferred over this SSH");

    await sftp.#send(new Writer().byte(FXP.INIT).uint32(VERSION).build());
    const hello = await sftp.#receive();
    if (hello.type !== FXP.VERSION) throw new Error(`expected the sftp version, got packet type ${hello.type}`);
    const version = new Reader(hello.payload).uint32();
    if (version < VERSION) throw new Error(`the server speaks sftp ${version}, and this client needs ${VERSION}`);
    return sftp;
  }

  async #awaitChannelReply(): Promise<boolean> {
    for (;;) {
      const reply = await this.transport.receive();
      if (reply[0] === MSG.CHANNEL_SUCCESS) return true;
      if (reply[0] === MSG.CHANNEL_FAILURE) return false;
      if (reply[0] === MSG.CHANNEL_WINDOW_ADJUST) continue;
      throw new Error(`unexpected message ${reply[0]} while starting the subsystem`);
    }
  }

  /** One SFTP packet, split to fit the channel's packets. */
  async #send(packet: Bytes): Promise<void> {
    const framed = concat([new Writer().uint32(packet.length).build(), packet]);
    for (let at = 0; at < framed.length; at += Math.min(CHUNK, this.maxPacket - 64)) {
      const slice = framed.subarray(at, at + Math.min(CHUNK, this.maxPacket - 64));
      await this.transport.send(new Writer().byte(MSG.CHANNEL_DATA).uint32(this.channel).string(slice).build());
    }
  }

  /** The next SFTP packet, reassembled from however the channel delivered it. */
  async #receive(): Promise<{ type: number; payload: Bytes }> {
    for (;;) {
      if (this.#buffer.length >= 4) {
        const length = new DataView(this.#buffer.buffer, this.#buffer.byteOffset, 4).getUint32(0);
        if (length > 0 && this.#buffer.length >= 4 + length) {
          const packet = this.#buffer.subarray(4, 4 + length);
          this.#buffer = this.#buffer.slice(4 + length);
          return { type: packet[0]!, payload: packet.slice(1) };
        }
      }
      await this.#pull();
    }
  }

  async #pull(): Promise<void> {
    const message = await this.transport.receive();
    const type = message[0];
    const reader = new Reader(message.subarray(1));
    switch (type) {
      case MSG.CHANNEL_DATA: {
        reader.uint32();
        const data = reader.string();
        this.#buffer = concat([this.#buffer, data]);
        this.#window -= data.length;
        if (this.#window < WINDOW_SIZE / 2) {
          const top = WINDOW_SIZE - this.#window;
          this.#window = WINDOW_SIZE;
          await this.transport.send(
            new Writer().byte(MSG.CHANNEL_WINDOW_ADJUST).uint32(this.channel).uint32(top).build(),
          );
        }
        return;
      }
      case MSG.CHANNEL_EXTENDED_DATA:
        // The subsystem's stderr. sftp-server uses it for its own diagnostics.
        return;
      case MSG.CHANNEL_WINDOW_ADJUST:
      case MSG.CHANNEL_SUCCESS:
      case MSG.CHANNEL_FAILURE:
      case MSG.CHANNEL_REQUEST:
        return;
      case MSG.CHANNEL_EOF:
      case MSG.CHANNEL_CLOSE:
        this.#closed = true;
        throw new Error("the server closed the sftp channel");
      default:
        throw new Error(`unexpected message ${type} during a transfer`);
    }
  }

  /** Sends a request and reads the one answer that carries its id. */
  async #request(build: (writer: Writer, id: number) => Writer): Promise<{ type: number; reader: Reader }> {
    const id = this.#requestId++;
    await this.#send(build(new Writer(), id).build());
    for (;;) {
      const { type, payload } = await this.#receive();
      const reader = new Reader(payload);
      if (reader.uint32() !== id) continue;
      if (type === FXP.STATUS) {
        const code = reader.uint32();
        if (code === STATUS_OK) return { type, reader };
        if (code === STATUS_EOF) return { type, reader };
        const said = reader.text();
        throw new SftpError(code, said || STATUS_TEXT[code] || `sftp error ${code}`);
      }
      return { type, reader };
    }
  }

  async #openFile(path: string, flags: number): Promise<Bytes> {
    const { type, reader } = await this.#request((writer, id) =>
      writer.byte(FXP.OPEN).uint32(id).string(path).uint32(flags).uint32(0),
    );
    if (type !== FXP.HANDLE) throw new Error(`expected a handle for "${path}", got packet type ${type}`);
    return reader.string();
  }

  async #close(handle: Bytes): Promise<void> {
    await this.#request((writer, id) => writer.byte(FXP.CLOSE).uint32(id).string(handle)).catch(() => {});
  }

  /** Writes a whole file, replacing whatever was there. */
  async put(path: string, data: Uint8Array): Promise<void> {
    const handle = await this.#openFile(path, WRITE_FLAG | CREATE_FLAG | TRUNCATE_FLAG);
    try {
      const size = Math.min(CHUNK, this.maxPacket - 128);
      for (let at = 0; at < data.length; at += size) {
        const slice = data.subarray(at, at + size);
        const offset = at;
        await this.#request((writer, id) =>
          uint64(writer.byte(FXP.WRITE).uint32(id).string(handle), offset).string(slice),
        );
      }
    } finally {
      await this.#close(handle);
    }
  }

  /** Reads a whole file. Capped, since it becomes an item's attachment. */
  async get(path: string, limit = MAX_FILE): Promise<Bytes> {
    const handle = await this.#openFile(path, READ_FLAG);
    const parts: Bytes[] = [];
    let total = 0;
    try {
      for (;;) {
        const offset = total;
        const { type, reader } = await this.#request((writer, id) =>
          uint64(writer.byte(FXP.READ).uint32(id).string(handle), offset).uint32(Math.min(CHUNK, limit - total)),
        );
        if (type !== FXP.DATA) break; // a STATUS here is the end of the file
        const chunk = reader.string();
        if (chunk.length === 0) break;
        parts.push(chunk);
        total += chunk.length;
        if (total >= limit) throw new Error(`"${path}" is larger than the ${Math.round(limit / 1024)} KB limit`);
      }
    } finally {
      await this.#close(handle);
    }
    return concat(parts);
  }

  async list(path: string): Promise<RemoteEntry[]> {
    const { type, reader } = await this.#request((writer, id) => writer.byte(FXP.OPENDIR).uint32(id).string(path));
    if (type !== FXP.HANDLE) throw new Error(`expected a handle for "${path}", got packet type ${type}`);
    const handle = reader.string();

    const entries: RemoteEntry[] = [];
    try {
      for (;;) {
        const answer = await this.#request((writer, id) => writer.byte(FXP.READDIR).uint32(id).string(handle));
        if (answer.type !== FXP.NAME) break; // a STATUS here is the end of the directory
        const count = answer.reader.uint32();
        for (let index = 0; index < count; index++) {
          const name = answer.reader.text();
          answer.reader.skipString(); // the long name, which is `ls -l` output
          const attributes = readAttributes(answer.reader);
          if (name === "." || name === "..") continue;
          entries.push({
            name,
            size: attributes.size,
            // The high bits of the mode are the file type; 0o040000 is a directory.
            directory: attributes.permissions === null ? false : (attributes.permissions & 0o170000) === 0o040000,
            modifiedAt: attributes.modifiedAt,
          });
        }
      }
    } finally {
      await this.#close(handle);
    }
    return entries;
  }

  async remove(path: string): Promise<void> {
    await this.#request((writer, id) => writer.byte(FXP.REMOVE).uint32(id).string(path));
  }

  async makeDirectory(path: string): Promise<void> {
    await this.#request((writer, id) => writer.byte(FXP.MKDIR).uint32(id).string(path).uint32(0));
  }

  async exists(path: string): Promise<boolean> {
    try {
      const { type } = await this.#request((writer, id) => writer.byte(FXP.STAT).uint32(id).string(path));
      return type === FXP.ATTRS;
    } catch (error) {
      if (error instanceof SftpError) return false;
      throw error;
    }
  }

  async end(): Promise<void> {
    if (this.#closed) return;
    await this.transport.send(new Writer().byte(MSG.CHANNEL_CLOSE).uint32(this.channel).build()).catch(() => {});
  }
}
