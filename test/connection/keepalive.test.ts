import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Connection } from '../../src/connection/connection';
import { MSG } from '../../src/transport/messages';
import type { Transport } from '../../src/transport/transport';
import { Reader, type Bytes } from '../../src/wire';

/** A transport whose server answers only when told to. */
function server() {
  const sent: Bytes[] = [];
  let deliver: ((message: Bytes) => void) | null = null;
  const transport = {
    send(payload: Bytes) {
      sent.push(payload);
      return Promise.resolve();
    },
    receive() {
      return new Promise<Bytes>((resolve) => (deliver = resolve));
    },
    close: () => Promise.resolve(),
  } as unknown as Transport;
  const asks = () =>
    sent.filter(
      (p) =>
        p[0] === MSG.GLOBAL_REQUEST && new Reader(p.subarray(1)).text() === 'keepalive@openssh.com',
    );
  return { transport, asks, answer: () => deliver?.(new Uint8Array([MSG.REQUEST_FAILURE])) };
}

describe('keepalives', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('asks every interval, and gives up after maxMissed unanswered', async () => {
    const { transport, asks } = server();
    const connection = new Connection(transport, { intervalMs: 1000, maxMissed: 2 });
    await vi.advanceTimersByTimeAsync(2000);
    expect(asks()).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1000);
    await expect(connection.open('session')).rejects.toThrow(
      /answered none of 2 keepalives, 1000 ms apart/,
    );
  });

  it('counts anything the server says as an answer', async () => {
    const { transport, asks, answer } = server();
    const connection = new Connection(transport, { intervalMs: 1000, maxMissed: 2 });
    for (let round = 0; round < 6; round++) {
      await vi.advanceTimersByTimeAsync(1000);
      answer();
      await vi.advanceTimersByTimeAsync(0);
    }
    expect(asks().length).toBeGreaterThanOrEqual(6);
    // Still up: an open is not refused.
    let refused = false;
    void connection.open('session').catch(() => (refused = true));
    await vi.advanceTimersByTimeAsync(0);
    expect(refused).toBe(false);
  });

  it('sends nothing unless asked to', async () => {
    const { transport, asks } = server();
    new Connection(transport);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(asks()).toHaveLength(0);
  });
});
