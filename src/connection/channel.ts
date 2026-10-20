/**
 * One channel (RFC 4254 §5): two byte streams each way under flow control.
 *
 * The window is the point. The server may send only as much as we have said
 * we have room for, and we say there is more room only as the reader takes
 * what arrived — so a caller that stops reading stops the server, within
 * one window, instead of piling its output up in memory. Data and stderr
 * share that window: a caller that reads one must read or cancel the other.
 *
 * A channel is a `ByteSocket` too, which is how a `direct-tcpip` channel
 * carries the next SSH connection to a host behind a bastion.
 */

import type { ByteSocket } from '../transport/buffered';
import { MSG } from '../transport/messages';
import { Reader, Writer, type Bytes } from '../wire';

export const WINDOW = 2 * 1024 * 1024;
export const MAX_PACKET = 32 * 1024;

export interface ExitStatus {
  /** Null when the server closed the channel without reporting one. */
  code: number | null;
  /** The signal that ended it, without "SIG", when it was killed rather than exited. */
  signal?: string;
  coreDumped?: boolean;
  /** What the server said about the signal, if anything. */
  message?: string;
}

export interface ChannelHost {
  send(payload: Bytes): Promise<void>;
  fail(error: unknown): void;
  forget(id: number): void;
}

/** Inbound bytes, credited back to the window as the reader takes them. */
class Inbox {
  #chunks: Bytes[] = [];
  #wake: (() => void) | null = null;
  #ended = false;
  #error: unknown = null;
  #cancelled = false;
  readonly stream: ReadableStream<Uint8Array>;

  constructor(private readonly credit: (bytes: number) => void) {
    this.stream = new ReadableStream<Uint8Array>(
      {
        pull: async (controller) => {
          while (this.#chunks.length === 0 && !this.#ended) {
            await new Promise<void>((resolve) => (this.#wake = resolve));
          }
          const chunk = this.#chunks.shift();
          if (chunk) {
            controller.enqueue(chunk);
            credit(chunk.length);
          } else if (this.#error) controller.error(this.#error);
          else controller.close();
        },
        cancel: () => {
          this.#cancelled = true;
          credit(this.#chunks.reduce((sum, chunk) => sum + chunk.length, 0));
          this.#chunks = [];
        },
      },
      // Nothing is pulled ahead of the reader, or the window would mean nothing.
      { highWaterMark: 0 },
    );
  }

  push(chunk: Bytes): void {
    if (this.#cancelled || this.#ended) {
      this.credit(chunk.length);
      return;
    }
    this.#chunks.push(chunk);
    this.#wake?.();
  }

  end(error?: unknown): void {
    if (this.#ended) return;
    this.#ended = true;
    this.#error = error ?? null;
    this.#wake?.();
  }
}

export class Channel implements ByteSocket {
  readonly readable: ReadableStream<Uint8Array>;
  /** Extended data of type 1, which a session's command writes as stderr. */
  readonly stderr: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  /** Settles once both sides have closed, with whatever exit the server reported. */
  readonly closed: Promise<ExitStatus>;

  #remoteWindow: number;
  readonly #remoteMax: number;
  #unacknowledged = 0;
  #localWindow = WINDOW;
  #windowWaiters: (() => void)[] = [];
  #replies: ((ok: boolean) => void)[] = [];
  #eofSent = false;
  #closeSent = false;
  #done = false;
  #error: unknown = null;
  #exit: ExitStatus = { code: null };
  #settle!: (exit: ExitStatus) => void;
  readonly #data: Inbox;
  readonly #extended: Inbox;

  constructor(
    private readonly host: ChannelHost,
    readonly id: number,
    readonly remoteId: number,
    remoteWindow: number,
    remoteMaxPacket: number,
  ) {
    this.#remoteWindow = remoteWindow;
    // Some servers announce a large maximum and choke on it; 32 KiB is what
    // RFC 4253 §6.1 says everyone handles.
    this.#remoteMax = Math.max(1, Math.min(remoteMaxPacket, MAX_PACKET));
    this.closed = new Promise((resolve) => (this.#settle = resolve));
    const credit = (bytes: number) => this.#credit(bytes);
    this.#data = new Inbox(credit);
    this.#extended = new Inbox(credit);
    this.readable = this.#data.stream;
    this.stderr = this.#extended.stream;
    this.writable = new WritableStream<Uint8Array>({
      write: (chunk) => this.#write(chunk),
      close: () => this.eof(),
      abort: () => this.close(),
    });
  }

  #send(payload: Bytes): void {
    void this.host.send(payload).catch((error: unknown) => this.host.fail(error));
  }

  #credit(bytes: number): void {
    if (this.#done || bytes === 0) return;
    this.#unacknowledged += bytes;
    if (this.#unacknowledged >= WINDOW / 2) {
      this.#localWindow += this.#unacknowledged;
      this.#send(
        new Writer()
          .byte(MSG.CHANNEL_WINDOW_ADJUST)
          .uint32(this.remoteId)
          .uint32(this.#unacknowledged)
          .build(),
      );
      this.#unacknowledged = 0;
    }
  }

  async #write(chunk: Uint8Array): Promise<void> {
    for (let at = 0; at < chunk.length;) {
      while (this.#remoteWindow === 0 && !this.#done)
        await new Promise<void>((resolve) => this.#windowWaiters.push(resolve));
      if (this.#done || this.#eofSent)
        throw (this.#error as Error | null) ?? new Error('the channel is closed');
      const size = Math.min(chunk.length - at, this.#remoteWindow, this.#remoteMax);
      this.#remoteWindow -= size;
      const data = new Writer()
        .byte(MSG.CHANNEL_DATA)
        .uint32(this.remoteId)
        .string(chunk.subarray(at, at + size))
        .build();
      await this.host.send(data);
      at += size;
    }
  }

  /** A channel request (RFC 4254 §5.4); with `wantReply`, whether the server agreed. */
  async request(
    type: string,
    wantReply: boolean,
    data: Uint8Array = new Uint8Array(0),
  ): Promise<boolean> {
    if (this.#done) throw (this.#error as Error | null) ?? new Error('the channel is closed');
    const reply = wantReply
      ? new Promise<boolean>((resolve) => this.#replies.push(resolve))
      : Promise.resolve(true);
    await this.host.send(
      new Writer()
        .byte(MSG.CHANNEL_REQUEST)
        .uint32(this.remoteId)
        .string(type)
        .bool(wantReply)
        .raw(data)
        .build(),
    );
    return reply;
  }

  /** Says nothing more will be sent; the other direction stays open. */
  async eof(): Promise<void> {
    if (this.#eofSent || this.#closeSent) return;
    this.#eofSent = true;
    await this.host.send(new Writer().byte(MSG.CHANNEL_EOF).uint32(this.remoteId).build());
  }

  /** Closes both directions and waits for the server to close its side. */
  async close(): Promise<void> {
    if (!this.#closeSent && !this.#done) {
      this.#closeSent = true;
      await this.host
        .send(new Writer().byte(MSG.CHANNEL_CLOSE).uint32(this.remoteId).build())
        .catch(() => {});
    }
    await this.closed;
  }

  /** A message the connection routed here, the recipient channel already read. */
  handle(type: number, reader: Reader): void {
    switch (type) {
      case MSG.CHANNEL_DATA:
        return this.#arrived(this.#data, reader.string());
      case MSG.CHANNEL_EXTENDED_DATA: {
        const code = reader.uint32();
        const data = reader.string();
        // 1 is stderr, and nothing else is defined; anything else is dropped, but counted.
        if (code === 1) this.#arrived(this.#extended, data);
        else this.#arrived(null, data);
        return;
      }
      case MSG.CHANNEL_WINDOW_ADJUST:
        this.#remoteWindow = Math.min(this.#remoteWindow + reader.uint32(), 2 ** 32 - 1);
        for (const wake of this.#windowWaiters.splice(0)) wake();
        return;
      case MSG.CHANNEL_EOF:
        this.#data.end();
        this.#extended.end();
        return;
      case MSG.CHANNEL_REQUEST:
        return this.#requested(reader);
      case MSG.CHANNEL_SUCCESS:
      case MSG.CHANNEL_FAILURE:
        this.#replies.shift()?.(type === MSG.CHANNEL_SUCCESS);
        return;
      case MSG.CHANNEL_CLOSE:
        if (!this.#closeSent) {
          this.#closeSent = true;
          this.#send(new Writer().byte(MSG.CHANNEL_CLOSE).uint32(this.remoteId).build());
        }
        return this.end();
      default:
        throw new Error(`unexpected message ${type} on channel ${this.id}`);
    }
  }

  #arrived(inbox: Inbox | null, data: Bytes): void {
    this.#localWindow -= data.length;
    if (this.#localWindow < 0) throw new Error(`the server overran channel ${this.id}'s window`);
    if (inbox) inbox.push(data.slice());
    else this.#credit(data.length);
  }

  #requested(reader: Reader): void {
    const type = reader.text();
    const wantReply = reader.bool();
    if (type === 'exit-status') this.#exit.code = reader.uint32();
    else if (type === 'exit-signal') {
      this.#exit.signal = reader.text();
      this.#exit.coreDumped = reader.bool();
      const message = reader.text();
      if (message) this.#exit.message = message;
    }
    // keepalive@openssh.com and anything else unknown: declined, as RFC 4254 §5.4 says.
    if (wantReply) this.#send(new Writer().byte(MSG.CHANNEL_FAILURE).uint32(this.remoteId).build());
  }

  /** The channel is over, cleanly or because the connection failed. */
  end(error?: unknown): void {
    if (this.#done) return;
    this.#done = true;
    this.#error = error ?? null;
    this.#data.end(error);
    this.#extended.end(error);
    for (const wake of this.#windowWaiters.splice(0)) wake();
    for (const reply of this.#replies.splice(0)) reply(false);
    this.host.forget(this.id);
    this.#settle(this.#exit);
  }
}
