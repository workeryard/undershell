/**
 * The probe's cases for finite-field Diffie-Hellman, which is BigInt in the
 * Worker and worth seeing the CPU of, and for keepalives, which need a
 * Worker's timers to run while a session is idle.
 */

import type { Authentication, ConnectOptions, SshClient } from '../src/index';

type Attempt = (name: string, body: () => Promise<string | void>) => void;
type Base = (extra?: Partial<ConnectOptions> & { jump?: never[] }) => Promise<SshClient>;

export function kexCases(
  attempt: Attempt,
  base: Base,
  gex: { host: string; pins: string[] },
  key: Authentication,
): void {
  // OpenSSH 10 offers no finite-field exchange at all, so these go one hop
  // in, to a server that still does.
  const kexes = [
    'diffie-hellman-group-exchange-sha256',
    'diffie-hellman-group16-sha512',
    'diffie-hellman-group14-sha256',
  ] as const;
  for (const kex of kexes) {
    attempt(`tunnel: ${kex}, one hop in (BigInt in the Worker)`, async () => {
      const client = await base();
      try {
        const inner = await client.jump({
          host: gex.host,
          username: 'tester',
          auth: key,
          hostKeyFingerprint: gex.pins,
          algorithms: { kex: [kex] },
        });
        const ok = (await inner.exec('echo ok')).stdout.trim();
        await inner.close();
        if (ok !== 'ok' || inner.negotiated.kex !== kex)
          throw new Error(`${inner.negotiated.kex}: ${ok}`);
        return `${inner.serverVersion}, ${inner.negotiated.kex}`;
      } finally {
        await client.close().catch(() => {});
      }
    });
  }
  attempt('tunnel: keepalives answered through 3 s of silence', async () => {
    const client = await base({ keepalive: { intervalMs: 500, maxMissed: 2 } });
    try {
      await new Promise((resolve) => setTimeout(resolve, 3000));
      const ok = (await client.exec('echo still')).stdout.trim();
      if (ok !== 'still') throw new Error(ok);
      return 'still up after 6 keepalives';
    } finally {
      await client.close();
    }
  });
}
