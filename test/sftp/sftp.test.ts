import { describe, expect, it } from 'vitest';
import type { Session } from '../../src/connection/session';
import { SftpError } from '../../src/sftp/protocol';
import { Sftp } from '../../src/sftp/sftp';
import { Reader, Writer, type Bytes } from '../../src/wire';

/**
 * A scripted sftp-server on the other end of a fake session. What is under
 * test is the client's side of the protocol: framing that the channel splits
 * and joins at will, answers out of order, short reads, and pages.
 */
type Handler = (type: number, id: number, reader: Reader) => Bytes[] | Promise<Bytes[]>;

function serve(handle: Handler, options: { split?: number; reorder?: boolean } = {}) {
  const requests: { type: number; id: number }[] = [];
  let output!: ReadableStreamDefaultController<Uint8Array>;
  const stdout = new ReadableStream<Uint8Array>({ start: (c) => void (output = c) });
  let pending = new Uint8Array(0);
  let held: Bytes[] = [];
  const emit = (packets: Bytes[]) => {
    const framed = packets.map((p) => new Writer().uint32(p.length).raw(p).build());
    for (const frame of framed) {
      // Delivered in pieces of `split` bytes, so one packet spans several reads.
      for (let at = 0; at < frame.length; at += options.split ?? frame.length)
        output.enqueue(frame.slice(at, at + (options.split ?? frame.length)));
    }
  };
  const stdin = new WritableStream<Uint8Array>({
    async write(chunk) {
      const joined = new Uint8Array(pending.length + chunk.length);
      joined.set(pending);
      joined.set(chunk, pending.length);
      pending = joined;
      while (pending.length >= 4) {
        const length = new Reader(pending.slice(0, 4)).uint32();
        if (pending.length < 4 + length) break;
        const reader = new Reader(pending.slice(4, 4 + length));
        pending = pending.slice(4 + length);
        const type = reader.byte();
        if (type === 1) {
          emit([
            new Writer().byte(2).uint32(3).string('posix-rename@openssh.com').string('1').build(),
          ]);
          continue;
        }
        const id = reader.uint32();
        requests.push({ type, id });
        const replies = await handle(type, id, reader);
        if (options.reorder) {
          // Held a moment and answered in reverse: ids, not order, have to match them up.
          if (held.length === 0) setTimeout(() => (emit(held.reverse()), (held = [])), 1);
          held.push(...replies);
        } else emit(replies);
      }
    },
  });
  const session = {
    stdin,
    stdout,
    stderr: new ReadableStream<Uint8Array>(),
    close: async () => {},
  } as unknown as Session;
  return { session, requests };
}

const status = (id: number, code: number, message = '') =>
  new Writer().byte(101).uint32(id).uint32(code).string(message).string('').build();
const handle = (id: number) => new Writer().byte(102).uint32(id).string('h').build();
const data = (id: number, bytes: Uint8Array) =>
  new Writer().byte(103).uint32(id).string(bytes).build();
const attrs = (id: number, size: number, mode: number) =>
  new Writer().byte(105).uint32(id).uint32(0x5).uint64(size).uint32(mode).build();

function names(id: number, entries: [string, number][]): Bytes {
  const writer = new Writer().byte(104).uint32(id).uint32(entries.length);
  for (const [name, mode] of entries)
    writer.string(name).string(`-rw-r--r-- 1 x x 0 ${name}`).uint32(0x4).uint32(mode);
  return writer.build();
}

describe('an sftp session', () => {
  it('lists a directory a page at a time, over packets the channel split', async () => {
    let page = 0;
    const { session } = serve(
      (type, id) => {
        if (type === 11) return [handle(id)];
        if (type === 12) {
          page++;
          if (page === 1)
            return [
              names(id, [
                ['a.csv', 0o100644],
                ['.', 0o040755],
              ]),
            ];
          if (page === 2) return [names(id, [['logs', 0o040755]])];
          return [status(id, 1)];
        }
        if (type === 4) return [status(id, 0)];
        throw new Error(`no answer for ${type}`);
      },
      { split: 3 },
    );
    const sftp = await Sftp.start(session);
    const entries = await sftp.list('/home/x');
    expect(entries.map((e) => [e.name, e.directory])).toEqual([
      ['a.csv', false],
      ['logs', true],
    ]);
    expect(sftp.extensions.get('posix-rename@openssh.com')).toBe('1');
  });

  it('reads a file as a stream with requests in flight, answered out of order', async () => {
    const file = Uint8Array.from({ length: 100_000 }, (_, i) => i % 251);
    const { session, requests } = serve(
      (type, id, reader) => {
        if (type === 3) return [handle(id)];
        if (type === 5) {
          reader.skipString();
          const offset = reader.uint64();
          const length = reader.uint32();
          if (offset >= file.length) return [status(id, 1)];
          // Never more than 10,000 at once: short reads that are not the end.
          return [data(id, file.slice(offset, offset + Math.min(length, 10_000)))];
        }
        if (type === 4) return [status(id, 0)];
        throw new Error(`no answer for ${type}`);
      },
      { reorder: true },
    );
    const sftp = await Sftp.start(session);
    const back = await sftp.get('/f');
    expect(back.length).toBe(file.length);
    expect(back.every((byte, i) => byte === file[i])).toBe(true);
    // More than one READ went out before the first answer came back.
    expect(requests.filter((r) => r.type === 5).length).toBeGreaterThan(10);
  });

  it('writes a stream at the right offsets, and closes the handle at the end', async () => {
    const written = new Map<number, number>();
    const { session, requests } = serve((type, id, reader) => {
      if (type === 3) return [handle(id)];
      if (type === 6) {
        reader.skipString();
        const offset = reader.uint64();
        written.set(offset, reader.string().length);
        return [status(id, 0)];
      }
      if (type === 4) return [status(id, 0)];
      throw new Error(`no answer for ${type}`);
    });
    const sftp = await Sftp.start(session);
    await sftp.put('/f', new Uint8Array(100_000));
    const offsets = [...written.keys()].sort((a, b) => a - b);
    expect(offsets).toEqual([0, 32768, 65536, 98304]);
    expect([...written.values()].reduce((a, b) => a + b)).toBe(100_000);
    expect(requests.at(-1)!.type).toBe(4);
  });

  it('repeats what the server said when it refuses, with its code', async () => {
    const { session } = serve((type, id) => [status(id, 3, 'Permission denied')]);
    const sftp = await Sftp.start(session);
    const error = await sftp.get('/root/secret').catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(SftpError);
    expect((error as SftpError).code).toBe(3);
    expect((error as SftpError).message).toMatch(/Permission denied/);
  });

  it('names the code when the server sends no message of its own', async () => {
    const { session } = serve((type, id) => [status(id, 2)]);
    const sftp = await Sftp.start(session);
    await expect(sftp.stat('/nope')).rejects.toThrow(/no such file/);
    expect(await sftp.exists('/nope')).toBe(false);
  });

  it('reads attributes: size past 4 GiB, and the type from the mode', async () => {
    const { session } = serve((type, id) => [attrs(id, 5 * 2 ** 32, 0o040755)]);
    const sftp = await Sftp.start(session);
    const stats = await sftp.stat('/big');
    expect(stats.size).toBe(5 * 2 ** 32);
    expect(stats.isDirectory).toBe(true);
  });

  it('asks for posix-rename only when replacing, and only where offered', async () => {
    const { session, requests } = serve((type, id) => [status(id, 0)]);
    const sftp = await Sftp.start(session);
    await sftp.rename('/a', '/b');
    await sftp.rename('/a', '/b', { overwrite: true });
    expect(requests.map((r) => r.type)).toEqual([18, 200]);
  });
});
