import { describe, expect, it } from 'vitest';
import { MSG } from '../../src/transport/messages';
import { Transport } from '../../src/transport/transport';
import { Writer } from '../../src/wire';
import { hostKey, server } from './fake-server';

describe('the key exchange', () => {
  it('completes, and reports the key the server proved it holds', async () => {
    const fake = server({ strict: true });
    const transport = new Transport(fake.socket);
    await transport.handshake();
    expect(transport.hostKey!.fingerprint).toBe(fake.fingerprint);
    expect(transport.negotiated).toMatchObject({
      kex: 'curve25519-sha256',
      cipher: 'aes256-gcm@openssh.com',
      strictKex: true,
    });
    expect(transport.keyExchanges).toBe(1);
  });

  it('refuses a host key before sending anything under its keys', async () => {
    const fake = server();
    const transport = new Transport(fake.socket, {
      checkHostKey: () => Promise.reject(new Error('not this one')),
    });
    await expect(transport.handshake()).rejects.toThrow(/not this one/);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(fake.received).not.toContain(MSG.NEWKEYS);
  });

  it('under strict KEX, refuses a server that sends anything before KEXINIT', async () => {
    const fake = server({
      strict: true,
      before: [new Writer().byte(MSG.IGNORE).string('').build()],
    });
    await expect(new Transport(fake.socket).handshake()).rejects.toThrow(/strict KEX/);
  });

  it('without strict KEX, lets an IGNORE before KEXINIT pass', async () => {
    const fake = server({ before: [new Writer().byte(MSG.IGNORE).string('').build()] });
    const transport = new Transport(fake.socket);
    await transport.handshake();
    expect(transport.negotiated!.strictKex).toBe(false);
  });

  it('re-keys when the server asks, under the same host key', async () => {
    const fake = server({ strict: true, rekeyWith: 'same' });
    const transport = new Transport(fake.socket);
    await transport.handshake();
    // The server's KEXINIT arrives inside receive(), which finishes the exchange before returning.
    expect((await transport.receive())[0]).toBe(MSG.REQUEST_FAILURE);
    expect(transport.keyExchanges).toBe(2);
    await fake.running;
  });

  it('refuses a different host key on re-keying', async () => {
    const fake = server({ strict: true, rekeyWith: hostKey() });
    const transport = new Transport(fake.socket);
    await transport.handshake();
    await expect(transport.receive()).rejects.toThrow(/different host key on re-keying/);
  });
});
