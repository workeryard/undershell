/**
 * A `ByteSocket` over a WebSocket, which is how `cloudflared access ssh`
 * reaches a server published through Cloudflare Tunnel: the TCP stream's
 * bytes in binary messages, in order, with no framing of their own.
 *
 * It takes a WebSocket that is already open, from wherever the runtime makes
 * one — `fetch()` with an Upgrade header in a Worker (see `./workers`), the
 * global `WebSocket` in Node 22 or a browser.
 */

import type { ByteSocket } from '../transport/buffered';

/** The part of a WebSocket this needs, which both the DOM's and workerd's have. */
export interface WebSocketLike {
  binaryType?: string;
  send(data: Uint8Array | ArrayBuffer): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  addEventListener(
    type: 'close',
    listener: (event: { code?: number; reason?: string }) => void,
  ): void;
  addEventListener(type: 'error', listener: (event: unknown) => void): void;
}

async function bytesOf(data: unknown): Promise<Uint8Array | null> {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data))
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (typeof Blob !== 'undefined' && data instanceof Blob)
    return new Uint8Array(await data.arrayBuffer());
  return null;
}

export function webSocketStream(socket: WebSocketLike): ByteSocket {
  socket.binaryType = 'arraybuffer';
  let closed = false;
  // A second close() throws in some runtimes; once is all that is meant.
  let hungUp = false;
  const hangUp = (code = 1000, reason?: string) => {
    if (hungUp) return;
    hungUp = true;
    try {
      socket.close(code, reason);
    } catch {
      // Already closing from the other side.
    }
  };
  // Messages are read in order; a Blob's bytes arrive later than an ArrayBuffer's would.
  let order: Promise<void> = Promise.resolve();

  const readable = new ReadableStream<Uint8Array>({
    start(controller) {
      socket.addEventListener('message', (event) => {
        order = order.then(async () => {
          const bytes = await bytesOf(event.data);
          if (closed) return;
          if (!bytes) {
            closed = true;
            controller.error(new Error('the tunnel sent a text message where only bytes belong'));
            hangUp(1003, 'binary only');
            return;
          }
          controller.enqueue(bytes);
        });
      });
      socket.addEventListener('close', (event) => {
        void order.then(() => {
          if (closed) return;
          closed = true;
          if (event.code === undefined || event.code === 1000 || event.code === 1005)
            controller.close();
          else
            controller.error(
              new Error(
                `the tunnel closed (${event.code}${event.reason ? `: ${event.reason}` : ''})`,
              ),
            );
        });
      });
      socket.addEventListener('error', () => {
        void order.then(() => {
          if (closed) return;
          closed = true;
          controller.error(new Error('the tunnel failed'));
        });
      });
    },
    cancel() {
      closed = true;
      hangUp();
    },
  });

  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      if (closed) throw new Error('the tunnel is closed');
      // A copy: a Worker's send() may hold the buffer past this call.
      socket.send(chunk.slice());
    },
    close() {
      hangUp();
    },
    abort() {
      hangUp();
    },
  });

  return {
    readable,
    writable,
    close: () => {
      closed = true;
      hangUp();
      return Promise.resolve();
    },
  };
}
