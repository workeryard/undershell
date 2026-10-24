/** The keepalive case: the server is frozen with docker pause, not closed. */

import { execFileSync } from 'node:child_process';
import { assert, type Case } from './matrix-cases';

export function keepaliveCase(server: string): Case {
  return {
    group: 'keepalive',
    name: 'a frozen server is given up after 2 missed keepalives',
    connect: { keepalive: { intervalMs: 500, maxMissed: 2 } },
    async run(client) {
      const alive = await client.exec('echo up');
      assert(alive.stdout === 'up\n', 'the connection was not up to begin with');
      // Frozen, not closed: the TCP connection stays, nothing answers on it.
      execFileSync('docker', ['pause', `us-${server}`]);
      const started = Date.now();
      try {
        const said = await client.exec('echo never').then(
          () => 'it answered',
          (error: Error) => error.message,
        );
        const waited = Date.now() - started;
        assert(/answered none of 2 keepalives/.test(said), said);
        assert(waited < 5000, `it took ${waited} ms to give up`);
        return `gave up after ${waited} ms`;
      } finally {
        execFileSync('docker', ['unpause', `us-${server}`]);
      }
    },
  };
}
