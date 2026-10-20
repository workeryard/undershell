/**
 * Files as streams, a bounded number of requests in flight: a transfer moves
 * at the speed the round trip allows, and memory holds what is in flight —
 * `concurrency` × `chunkSize` — never the file.
 */

import { Writer, type Bytes } from '../wire';
import { expectStatus, expectType, FXP, type Protocol } from './protocol';

export const CHUNK = 32 * 1024;
export const CONCURRENCY = 16;

export interface ReadStreamOptions {
  /** The first byte to read. Default 0. */
  start?: number;
  /** One past the last byte to read. Default the end of the file. */
  end?: number;
  /** Bytes per request. Default 32 KiB. */
  chunkSize?: number;
  /** Requests in flight at once. Default 16. */
  concurrency?: number;
}

interface Slot {
  offset: number;
  length: number;
  data: Promise<Bytes | null>;
}

export function readStream(
  protocol: Protocol,
  handle: Bytes,
  what: string,
  options: ReadStreamOptions,
  close: () => Promise<void>,
): ReadableStream<Uint8Array> {
  const chunkSize = options.chunkSize ?? CHUNK;
  const concurrency = Math.max(1, options.concurrency ?? CONCURRENCY);
  const end = options.end ?? Infinity;
  let next = options.start ?? 0;
  let finished = false;
  const slots: Slot[] = [];

  const read = (offset: number, length: number): Slot => ({
    offset,
    length,
    data: protocol
      .request(FXP.READ, (w) => w.string(handle).uint64(offset).uint32(length))
      .then((reply) =>
        reply.type === FXP.DATA
          ? reply.reader.string().slice()
          : expectStatus(reply, what, true)
            ? null
            : new Uint8Array(0),
      ),
  });
  const fill = () => {
    while (!finished && slots.length < concurrency && next < end) {
      const length = Math.min(chunkSize, end - next);
      slots.push(read(next, length));
      next += length;
    }
  };
  let closing: Promise<void> | null = null;
  const settle = () => {
    finished = true;
    // Answers still in flight are waited for, so none arrives for a closed handle.
    closing ??= Promise.allSettled(slots.splice(0).map((slot) => slot.data)).then(close);
    return closing;
  };

  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        fill();
        const slot = slots.shift();
        if (!slot) {
          await settle();
          return controller.close();
        }
        let data: Bytes | null;
        try {
          data = await slot.data;
        } catch (error) {
          await settle().catch(() => {});
          throw error;
        }
        if (data === null || data.length === 0) {
          // The end of the file: what was asked beyond it can only be the end too.
          await settle();
          return controller.close();
        }
        // A short read is not the end, only less than asked: the rest is asked
        // for again, ahead of everything after it.
        if (data.length < slot.length)
          slots.unshift(read(slot.offset + data.length, slot.length - data.length));
        controller.enqueue(data);
      },
      async cancel() {
        await settle();
      },
    },
    { highWaterMark: 0 },
  );
}

export function writeStream(
  protocol: Protocol,
  handle: Bytes,
  what: string,
  options: { start?: number; concurrency?: number },
  close: () => Promise<void>,
): WritableStream<Uint8Array> {
  const concurrency = Math.max(1, options.concurrency ?? CONCURRENCY);
  let offset = options.start ?? 0;
  const inFlight: Promise<void>[] = [];
  let failure: unknown = null;

  const write = (at: number, data: Uint8Array) => {
    const done = protocol
      .request(FXP.WRITE, (w) => w.string(handle).uint64(at).string(data))
      .then((reply) => void expectStatus(reply, what))
      .catch((error: unknown) => {
        failure ??= error;
      });
    inFlight.push(done);
  };
  const drain = async (room: number) => {
    while (inFlight.length > room) await inFlight.shift();
    if (failure) throw failure as Error;
  };

  return new WritableStream<Uint8Array>({
    async write(chunk) {
      for (let at = 0; at < chunk.length; at += CHUNK) {
        await drain(concurrency - 1);
        // Copied: the caller may reuse its buffer once write() resolves.
        write(offset, chunk.slice(at, at + CHUNK));
        offset += Math.min(CHUNK, chunk.length - at);
      }
    },
    async close() {
      try {
        await drain(0);
      } finally {
        await close();
      }
    },
    async abort() {
      await drain(0).catch(() => {});
      await close();
    },
  });
}

export async function openHandle(
  protocol: Protocol,
  path: string,
  flags: number,
  mode?: number,
): Promise<Bytes> {
  const reply = await protocol.request(FXP.OPEN, (w) => {
    const writer = w.string(path).uint32(flags);
    return mode === undefined ? writer.uint32(0) : writer.uint32(0x4).uint32(mode);
  });
  return expectType(reply, FXP.HANDLE, `opening "${path}"`).string().slice();
}

export function closeHandle(protocol: Protocol, handle: Bytes): Promise<void> {
  return protocol
    .status(FXP.CLOSE, (w: Writer) => w.string(handle), 'closing a handle')
    .catch(() => {});
}
