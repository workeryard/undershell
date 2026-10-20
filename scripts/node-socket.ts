/**
 * A `ByteSocket` from Node's TCP, for the scripts that prove the client
 * against real servers. The library itself names no runtime; this is the
 * Node counterpart of `src/workers/`'s `openSocket`.
 */

import { connect } from 'node:net';
import { Duplex } from 'node:stream';
import type { ByteSocket } from '../src/index';

export function openNodeSocket(host: string, port: number): Promise<ByteSocket> {
  return new Promise((resolve, reject) => {
    const socket = connect({ host, port });
    socket.once('error', reject);
    socket.once('connect', () => {
      socket.off('error', reject);
      const { readable, writable } = Duplex.toWeb(socket) as {
        readable: ReadableStream<Uint8Array>;
        writable: WritableStream<Uint8Array>;
      };
      resolve({
        readable,
        writable,
        close: () => {
          socket.destroy();
          return Promise.resolve();
        },
      });
    });
  });
}
