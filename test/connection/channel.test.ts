import { describe, expect, it } from 'vitest';
import { Channel, WINDOW } from '../../src/connection/channel';
import { MSG } from '../../src/transport/messages';
import { Reader, Writer, type Bytes } from '../../src/wire';

/** A channel with its sends recorded instead of sent. */
function channel(remoteWindow = 1 << 20, remoteMax = 32768) {
  const sent: Bytes[] = [];
  const failures: unknown[] = [];
  const ch = new Channel(
    {
      send: (payload) => Promise.resolve(void sent.push(payload)),
      fail: (error) => void failures.push(error),
      forget: () => {},
    },
    0,
    9,
    remoteWindow,
    remoteMax,
  );
  const deliver = (type: number, build: (w: Writer) => Writer = (w) => w) =>
    ch.handle(type, new Reader(build(new Writer()).build()));
  return { ch, sent, failures, deliver };
}

const adjustments = (sent: Bytes[]) =>
  sent
    .filter((p) => p[0] === MSG.CHANNEL_WINDOW_ADJUST)
    .map((p) => new Reader(p.subarray(5)).uint32());

describe('a channel', () => {
  it('gives the window back as the reader takes data, not as it arrives', async () => {
    const { ch, sent, deliver } = channel();
    const half = new Uint8Array(WINDOW / 2);
    deliver(MSG.CHANNEL_DATA, (w) => w.string(half));
    // Arrived, unread: no room is given back, so the server stops at one window.
    expect(adjustments(sent)).toEqual([]);
    const reader = ch.readable.getReader();
    await reader.read();
    expect(adjustments(sent)).toEqual([WINDOW / 2]);
  });

  it('refuses a server that sends past the window', () => {
    const { deliver } = channel();
    deliver(MSG.CHANNEL_DATA, (w) => w.string(new Uint8Array(WINDOW)));
    expect(() => deliver(MSG.CHANNEL_DATA, (w) => w.string(new Uint8Array(1)))).toThrow(/overran/);
  });

  it('credits what a cancelled stream would have held', async () => {
    const { ch, sent, deliver } = channel();
    deliver(MSG.CHANNEL_EXTENDED_DATA, (w) => w.uint32(1).string(new Uint8Array(WINDOW / 4)));
    await ch.stderr.cancel();
    deliver(MSG.CHANNEL_EXTENDED_DATA, (w) => w.uint32(1).string(new Uint8Array(WINDOW / 4)));
    expect(adjustments(sent)).toEqual([WINDOW / 2]);
  });

  it('splits writes to the packet size and waits for the window', async () => {
    const { ch, sent, deliver } = channel(50_000, 32768);
    const writer = ch.writable.getWriter();
    const done = writer.write(new Uint8Array(100_000));
    await new Promise((resolve) => setTimeout(resolve, 10));
    const sizes = () =>
      sent
        .filter((p) => p[0] === MSG.CHANNEL_DATA)
        .map((p) => new Reader(p.subarray(5)).string().length);
    expect(sizes()).toEqual([32768, 50_000 - 32768]);
    deliver(MSG.CHANNEL_WINDOW_ADJUST, (w) => w.uint32(1 << 20));
    await done;
    expect(sizes().reduce((a, b) => a + b)).toBe(100_000);
    expect(Math.max(...sizes())).toBe(32768);
  });

  it('reports the exit status and signal when it closes', async () => {
    const { ch, deliver } = channel();
    deliver(MSG.CHANNEL_REQUEST, (w) =>
      w.string('exit-signal').bool(false).string('KILL').bool(true).string('killed').string(''),
    );
    deliver(MSG.CHANNEL_CLOSE);
    expect(await ch.closed).toEqual({
      code: null,
      signal: 'KILL',
      coreDumped: true,
      message: 'killed',
    });
  });

  it('answers a close with a close, and ends both streams', async () => {
    const { ch, sent, deliver } = channel();
    deliver(MSG.CHANNEL_DATA, (w) => w.string(new Uint8Array([1, 2])));
    deliver(MSG.CHANNEL_EOF);
    deliver(MSG.CHANNEL_CLOSE);
    const chunks: number[] = [];
    for await (const chunk of ch.readable) chunks.push(...chunk);
    expect(chunks).toEqual([1, 2]);
    expect(sent.some((p) => p[0] === MSG.CHANNEL_CLOSE)).toBe(true);
  });

  it('declines a request it does not know, such as a keepalive', () => {
    const { sent, deliver } = channel();
    deliver(MSG.CHANNEL_REQUEST, (w) => w.string('keepalive@openssh.com').bool(true));
    expect(sent.at(-1)![0]).toBe(MSG.CHANNEL_FAILURE);
  });

  it('matches replies to its own requests in order', async () => {
    const { ch, deliver } = channel();
    const first = ch.request('pty-req', true);
    const second = ch.request('shell', true);
    deliver(MSG.CHANNEL_FAILURE);
    deliver(MSG.CHANNEL_SUCCESS);
    expect([await first, await second]).toEqual([false, true]);
  });
});
