/**
 * The connection protocol's dispatcher (RFC 4254): after authentication one
 * pump reads every message and hands it to the channel it names, so a shell,
 * a forwarded port and an SFTP session can share one connection.
 *
 * The pump never waits on a send. A send can be held by a key exchange in
 * progress, and only the pump can read the messages that finish it.
 */

import { MSG, toError } from '../transport/messages';
import type { Transport } from '../transport/transport';
import { Reader, Writer, type Bytes } from '../wire';
import { Channel, MAX_PACKET, WINDOW } from './channel';

export class ChannelOpenError extends Error {
  override name = 'ChannelOpenError';
  constructor(
    /** RFC 4254 §5.1: 1 prohibited, 2 connect failed, 3 unknown type, 4 out of resources. */
    readonly reason: number,
    message: string,
  ) {
    super(message);
  }
}

interface Opening {
  resolve(channel: Channel): void;
  reject(error: unknown): void;
}

export class Connection {
  #nextId = 0;
  #failure: unknown = null;
  readonly #channels = new Map<number, Channel>();
  readonly #opening = new Map<number, Opening>();
  readonly #ended: Promise<void>;
  readonly #host = {
    send: (payload: Bytes) => this.transport.send(payload),
    fail: (error: unknown) => this.#fail(error),
    forget: (id: number) => this.#channels.delete(id),
  };

  constructor(readonly transport: Transport) {
    this.#ended = this.#pump();
  }

  /** Settles when the connection has ended, with the error that ended it, if one did. */
  get ended(): Promise<void> {
    return this.#ended;
  }

  async #pump(): Promise<void> {
    try {
      for (;;) this.#dispatch(await this.transport.receive());
    } catch (error) {
      this.#fail(error);
    }
  }

  #fail(error: unknown): void {
    if (this.#failure) return;
    this.#failure = error;
    for (const channel of [...this.#channels.values()]) channel.end(error);
    for (const opening of this.#opening.values()) opening.reject(error);
    this.#opening.clear();
    void this.transport.close();
  }

  #dispatch(message: Bytes): void {
    const type = message[0]!;
    const reader = new Reader(message.subarray(1));
    if (type === MSG.CHANNEL_OPEN) return this.#refuseOpen(reader);
    if (type === MSG.REQUEST_SUCCESS || type === MSG.REQUEST_FAILURE) return;
    if (type < MSG.CHANNEL_OPEN_CONFIRMATION || type > MSG.CHANNEL_FAILURE) {
      throw new Error(`unexpected message ${type} on an open connection`);
    }
    const id = reader.uint32();
    if (type === MSG.CHANNEL_OPEN_CONFIRMATION || type === MSG.CHANNEL_OPEN_FAILURE) {
      const opening = this.#opening.get(id);
      if (!opening)
        throw new Error(`the server answered an open of channel ${id}, which was not asked for`);
      this.#opening.delete(id);
      if (type === MSG.CHANNEL_OPEN_FAILURE) {
        const reason = reader.uint32();
        opening.reject(
          new ChannelOpenError(
            reason,
            `the server would not open the channel (reason ${reason}): ${reader.text()}`,
          ),
        );
        return;
      }
      const remoteId = reader.uint32();
      const window = reader.uint32();
      const channel = new Channel(this.#host, id, remoteId, window, reader.uint32());
      this.#channels.set(id, channel);
      opening.resolve(channel);
      return;
    }
    // A message for a channel already closed and forgotten is late, not wrong.
    this.#channels.get(id)?.handle(type, reader);
  }

  /**
   * The server opening a channel to us: forwarded ports, X11, an agent.
   * None of them was asked for, so each is refused.
   */
  #refuseOpen(reader: Reader): void {
    const kind = reader.text();
    const sender = reader.uint32();
    void this.transport
      .send(
        new Writer()
          .byte(MSG.CHANNEL_OPEN_FAILURE)
          .uint32(sender)
          .uint32(1)
          .string(`${kind} channels are not accepted by this client`)
          .string('')
          .build(),
      )
      .catch((error: unknown) => this.#fail(error));
  }

  /** Opens a channel of `type`, with whatever that type puts after the common fields. */
  open(type: string, extra: Uint8Array = new Uint8Array(0)): Promise<Channel> {
    if (this.#failure) return Promise.reject(toError(this.#failure));
    const id = this.#nextId++;
    const opened = new Promise<Channel>((resolve, reject) =>
      this.#opening.set(id, { resolve, reject }),
    );
    const request = new Writer()
      .byte(MSG.CHANNEL_OPEN)
      .string(type)
      .uint32(id)
      .uint32(WINDOW)
      .uint32(MAX_PACKET)
      .raw(extra);
    this.transport.send(request.build()).catch((error: unknown) => {
      this.#opening.delete(id);
      this.#fail(error);
    });
    return opened;
  }

  async close(): Promise<void> {
    this.#fail(new Error('the connection was closed'));
    await this.transport.close();
    await this.#ended;
  }
}
