/**
 * An SFTP session: files read and written as streams or whole, directories
 * listed a page at a time, and the operations a script does to a tree —
 * stat, mkdir, rename, remove.
 */

import type { Session } from '../connection/session';
import { concat, type Bytes } from '../wire';
import { readAttributes, writeAttributes, type Stats } from './attributes';
import { expectStatus, expectType, FXP, Protocol, SftpError, STATUS } from './protocol';
import {
  closeHandle,
  openHandle,
  readStream,
  writeStream,
  type ReadStreamOptions,
} from './streams';

/** Open flags (§6.3). */
const READ = 0x1;
const WRITE = 0x2;
const APPEND = 0x4;
const CREATE = 0x8;
const TRUNCATE = 0x10;
const EXCLUSIVE = 0x20;

const MAX_FILE = 64 * 1024 * 1024;

export interface RemoteEntry {
  name: string;
  /** Bytes, from the attributes the server sent; null when it sent no size. */
  size: number | null;
  directory: boolean;
  /** Seconds since the epoch, or null when the server sent no time. */
  modifiedAt: number | null;
  attributes: Stats;
}

export interface WriteStreamOptions {
  /** `truncate` (the default) replaces the file, `append` adds to it, `exclusive` fails if it exists. */
  mode?: 'truncate' | 'append' | 'exclusive';
  /** The permissions a new file gets, such as 0o600. */
  permissions?: number;
  /** Requests in flight at once. Default 16. */
  concurrency?: number;
}

export class Sftp {
  private constructor(private readonly protocol: Protocol) {}

  static async start(session: Session): Promise<Sftp> {
    return new Sftp(await Protocol.start(session));
  }

  /** Extensions the server offered, by name, such as `posix-rename@openssh.com`. */
  get extensions(): ReadonlyMap<string, string> {
    return this.protocol.extensions;
  }

  async #stat(type: number, path: string): Promise<Stats> {
    const reply = await this.protocol.request(type, (w) => w.string(path));
    return readAttributes(expectType(reply, FXP.ATTRS, `stat "${path}"`));
  }

  /** The file's attributes, following a symbolic link. */
  stat(path: string): Promise<Stats> {
    return this.#stat(FXP.STAT, path);
  }

  /** The attributes of the link itself, where `path` is one. */
  lstat(path: string): Promise<Stats> {
    return this.#stat(FXP.LSTAT, path);
  }

  async exists(path: string): Promise<boolean> {
    try {
      await this.stat(path);
      return true;
    } catch (error) {
      if (error instanceof SftpError && error.code === STATUS.NO_SUCH_FILE) return false;
      throw error;
    }
  }

  /** The canonical absolute path, which is also how to learn the home directory: `realpath('.')`. */
  async realpath(path: string): Promise<string> {
    const reader = expectType(
      await this.protocol.request(FXP.REALPATH, (w) => w.string(path)),
      FXP.NAME,
      `realpath "${path}"`,
    );
    if (reader.uint32() < 1) throw new Error(`realpath "${path}" came back empty`);
    return reader.text();
  }

  /**
   * A directory's entries, read one page — one READDIR — at a time, so a
   * directory of a million files never sits in memory whole.
   */
  async *readdir(path: string): AsyncGenerator<RemoteEntry, void, undefined> {
    const reply = await this.protocol.request(FXP.OPENDIR, (w) => w.string(path));
    const handle = expectType(reply, FXP.HANDLE, `opening "${path}"`).string().slice();
    try {
      for (;;) {
        const page = await this.protocol.request(FXP.READDIR, (w) => w.string(handle));
        if (page.type !== FXP.NAME && expectStatus(page, `listing "${path}"`, true)) return;
        const count = page.reader.uint32();
        for (let index = 0; index < count; index++) {
          const name = page.reader.text();
          page.reader.skipString(); // the long name, which is `ls -l` output
          const attributes = readAttributes(page.reader);
          if (name === '.' || name === '..') continue;
          yield {
            name,
            size: attributes.size,
            directory: attributes.isDirectory,
            modifiedAt: attributes.modifiedAt,
            attributes,
          };
        }
      }
    } finally {
      await closeHandle(this.protocol, handle);
    }
  }

  /** Every entry of a directory, collected. */
  async list(path: string): Promise<RemoteEntry[]> {
    const entries: RemoteEntry[] = [];
    for await (const entry of this.readdir(path)) entries.push(entry);
    return entries;
  }

  async mkdir(path: string, options: { permissions?: number } = {}): Promise<void> {
    await this.protocol.status(
      FXP.MKDIR,
      (w) => writeAttributes(w.string(path), options.permissions),
      `mkdir "${path}"`,
    );
  }

  /** The older name, kept for Flowker's callers. */
  makeDirectory(path: string): Promise<void> {
    return this.mkdir(path);
  }

  async rmdir(path: string): Promise<void> {
    await this.protocol.status(FXP.RMDIR, (w) => w.string(path), `rmdir "${path}"`);
  }

  /** Removes a file. A directory needs `rmdir`. */
  async remove(path: string): Promise<void> {
    await this.protocol.status(FXP.REMOVE, (w) => w.string(path), `remove "${path}"`);
  }

  /**
   * Renames a file or directory. SFTP v3's own rename fails if the target
   * exists; `overwrite: true` asks for POSIX rename(2), which replaces it,
   * where the server offers posix-rename@openssh.com.
   */
  async rename(from: string, to: string, options: { overwrite?: boolean } = {}): Promise<void> {
    const what = `rename "${from}" to "${to}"`;
    if (options.overwrite) {
      if (!this.extensions.has('posix-rename@openssh.com')) {
        throw new SftpError(
          8,
          `${what}: the server cannot replace a file by renaming (no posix-rename@openssh.com)`,
        );
      }
      return this.protocol.status(
        FXP.EXTENDED,
        (w) => w.string('posix-rename@openssh.com').string(from).string(to),
        what,
      );
    }
    return this.protocol.status(FXP.RENAME, (w) => w.string(from).string(to), what);
  }

  /** A file as a stream, read ahead a bounded number of requests at a time. */
  createReadStream(path: string, options: ReadStreamOptions = {}): ReadableStream<Uint8Array> {
    const opened = openHandle(this.protocol, path, READ);
    let inner: ReadableStream<Uint8Array> | null = null;
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
    // The open is lazy in effect: an error in it surfaces on the first read.
    return new ReadableStream<Uint8Array>(
      {
        pull: async (controller) => {
          if (!reader) {
            const handle = await opened;
            inner = readStream(this.protocol, handle, `reading "${path}"`, options, () =>
              closeHandle(this.protocol, handle),
            );
            reader = inner.getReader();
          }
          const { value, done } = await reader.read();
          if (done) controller.close();
          else controller.enqueue(value);
        },
        cancel: async (reason) => {
          if (reader) await reader.cancel(reason);
          else await opened.then((handle) => closeHandle(this.protocol, handle)).catch(() => {});
        },
      },
      { highWaterMark: 0 },
    );
  }

  /** A file to write as a stream; it is complete, and closed, when the stream is. */
  createWriteStream(path: string, options: WriteStreamOptions = {}): WritableStream<Uint8Array> {
    const flags =
      WRITE |
      CREATE |
      (options.mode === 'append' ? APPEND : options.mode === 'exclusive' ? EXCLUSIVE : TRUNCATE);
    const opened = openHandle(this.protocol, path, flags, options.permissions);
    opened.catch(() => {});
    let inner: WritableStreamDefaultWriter<Uint8Array> | null = null;
    const writer = async () => {
      if (!inner) {
        const handle = await opened;
        let start = 0;
        if (options.mode === 'append') {
          // APPEND is advisory in v3; writing at the current size is what works everywhere.
          start =
            readAttributes(
              expectType(
                await this.protocol.request(FXP.FSTAT, (w) => w.string(handle)),
                FXP.ATTRS,
                'fstat',
              ),
            ).size ?? 0;
        }
        const stream = writeStream(
          this.protocol,
          handle,
          `writing "${path}"`,
          { start, ...(options.concurrency && { concurrency: options.concurrency }) },
          () => closeHandle(this.protocol, handle),
        );
        inner = stream.getWriter();
      }
      return inner;
    };
    return new WritableStream<Uint8Array>({
      write: async (chunk) => (await writer()).write(chunk),
      close: async () => (await writer()).close(),
      abort: async (reason) => (await writer()).abort(reason),
    });
  }

  /** Reads a whole file into memory, refusing one larger than `limit` (default 64 MiB). */
  async get(path: string, limit = MAX_FILE): Promise<Bytes> {
    const parts: Uint8Array[] = [];
    let total = 0;
    const stream = this.createReadStream(path);
    for await (const chunk of stream) {
      total += chunk.length;
      if (total > limit) {
        throw new Error(`"${path}" is larger than the ${Math.round(limit / 1024)} KiB limit`);
      }
      parts.push(chunk);
    }
    return concat(parts);
  }

  /** Writes a whole file, from bytes or a stream, replacing whatever was there. */
  async put(
    path: string,
    data: Uint8Array | ReadableStream<Uint8Array>,
    options: WriteStreamOptions = {},
  ): Promise<void> {
    const target = this.createWriteStream(path, options);
    if (data instanceof ReadableStream) return data.pipeTo(target);
    const writer = target.getWriter();
    await writer.write(data);
    await writer.close();
  }

  /** Ends the session and its channel; the connection stays open. */
  end(): Promise<void> {
    return this.protocol.end();
  }
}
