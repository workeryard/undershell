import { describe, expect, it } from 'vitest';
import { SshClient } from '../src/client';
import type { HostKey } from '../src/transport/transport';
import { server } from './transport/fake-server';

const connect = (
  fake: ReturnType<typeof server>,
  check: Partial<Parameters<typeof SshClient.connect>[0]>,
) =>
  SshClient.connect({
    socket: fake.socket,
    username: 'u',
    auth: { kind: 'none' },
    timeoutMs: 2000,
    ...check,
  });

describe('the host key policy', () => {
  it('will not connect with no pin and no callback', async () => {
    const fake = server();
    await expect(connect(fake, {})).rejects.toThrow(/will not trust on first use/);
  });

  it('refuses a key other than the one pinned, naming both', async () => {
    const fake = server();
    await expect(connect(fake, { hostKeyFingerprint: 'SHA256:' + 'A'.repeat(43) })).rejects.toThrow(
      new RegExp(
        `is SHA256:${fake.fingerprint.replace(/[+/]/g, '\\$&')}, not the SHA256:A{43} expected`,
      ),
    );
  });

  it('takes a pin written as ssh-keygen prints it, or bare, with or without padding', async () => {
    const fakes = [server(), server(), server()];
    const pins = [
      `SHA256:${fakes[0]!.fingerprint}`,
      fakes[1]!.fingerprint,
      `  sha256:${fakes[2]!.fingerprint}=  `,
    ];
    for (const [index, pin] of pins.entries()) {
      // The pin passes; what fails afterwards is authentication, which the fake server does not offer.
      await expect(connect(fakes[index]!, { hostKeyFingerprint: pin })).rejects.toThrow(
        /refused ssh-userauth/,
      );
    }
  });

  it('asks verifyHostKey, and refuses when it says no', async () => {
    const fake = server();
    const seen: HostKey[] = [];
    await expect(
      connect(fake, { verifyHostKey: (key) => (seen.push(key), false) }),
    ).rejects.toThrow(/refused by verifyHostKey/);
    expect(seen[0]).toMatchObject({
      algorithm: 'ssh-ed25519',
      signatureAlgorithm: 'ssh-ed25519',
      fingerprint: fake.fingerprint,
    });
    expect(seen[0]!.publicKey).toMatch(/^ssh-ed25519 AAAA/);
  });

  it('needs both to agree when given both', async () => {
    const fake = server();
    await expect(
      connect(fake, { hostKeyFingerprint: fake.fingerprint, verifyHostKey: () => false }),
    ).rejects.toThrow(/verifyHostKey/);
  });
});
