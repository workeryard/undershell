import { describe, expect, it } from 'vitest';
import { webSocketStream, type WebSocketLike } from '../../src/carriers/websocket';

class FakeSocket implements WebSocketLike {
  binaryType = 'blob';
  sent: Uint8Array[] = [];
  closes = 0;
  readonly #listeners: Record<string, ((event: never) => void)[]> = {};
  send(data: Uint8Array | ArrayBuffer) {
    this.sent.push(new Uint8Array(data as ArrayBuffer));
  }
  close() {
    this.closes++;
  }
  addEventListener(type: string, listener: (event: never) => void) {
    (this.#listeners[type] ??= []).push(listener);
  }
  emit(type: string, event: unknown) {
    for (const listener of this.#listeners[type] ?? []) listener(event as never);
  }
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<number[]> {
  const out: number[] = [];
  for await (const chunk of stream) out.push(...chunk);
  return out;
}

describe('a WebSocket carrier', () => {
  it('asks for binary as ArrayBuffers, and keeps messages in order whatever their form', async () => {
    const ws = new FakeSocket();
    const socket = webSocketStream(ws);
    expect(ws.binaryType).toBe('arraybuffer');
    ws.emit('message', { data: new Blob([new Uint8Array([1, 2])]) });
    ws.emit('message', { data: new Uint8Array([3]).buffer });
    ws.emit('message', { data: new Uint8Array([4]) });
    ws.emit('close', { code: 1000 });
    expect(await readAll(socket.readable)).toEqual([1, 2, 3, 4]);
  });

  it('fails on a text message, which no tunnel sends', async () => {
    const ws = new FakeSocket();
    const socket = webSocketStream(ws);
    ws.emit('message', { data: 'hello' });
    await expect(readAll(socket.readable)).rejects.toThrow(/text message/);
  });

  it('reports an abnormal close as an error, with its code', async () => {
    const ws = new FakeSocket();
    const socket = webSocketStream(ws);
    ws.emit('close', { code: 1011, reason: 'origin down' });
    await expect(readAll(socket.readable)).rejects.toThrow(/1011: origin down/);
  });

  it('sends copies, and closes the socket once however often asked', async () => {
    const ws = new FakeSocket();
    const socket = webSocketStream(ws);
    const writer = socket.writable.getWriter();
    const chunk = new Uint8Array([9, 9]);
    await writer.write(chunk);
    chunk[0] = 0;
    expect([...ws.sent[0]!]).toEqual([9, 9]);
    await writer.close();
    await socket.close!();
    expect(ws.closes).toBe(1);
  });
});
