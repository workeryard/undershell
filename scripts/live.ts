/**
 * The live check: the probe Worker (dev/worker.ts), deployed, runs the client
 * against two kinds of server.
 *
 * - test.rebex.net over a TCP socket from `cloudflare:sockets`: a public
 *   server for exactly this, pinned by what `ssh-keyscan` sees, not by
 *   anything this package computed.
 * - The matrix's OpenSSH in Docker, published through a Cloudflare quick
 *   tunnel (`cloudflared tunnel --url ssh://…`), which the Worker reaches as
 *   `cloudflared access ssh` would, over a WebSocket — and through it, the
 *   Dropbear container as a jump.
 *
 *   make deploy && make live          (PROBE_URL and PROBE_TOKEN from the Makefile)
 *   PROBE_URL=http://localhost:8813 PROBE_TOKEN=… pnpm tsx scripts/live.ts
 *
 * cloudflared is looked for on PATH, then in .cache/cloudflared/.
 */

import { execFileSync, spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileOf, fingerprint, SERVERS, setUp, tearDown, waitFor } from './matrix-docker';

const ROOT = new URL('..', import.meta.url).pathname;
const url = process.env.PROBE_URL;
const token = process.env.PROBE_TOKEN;
if (!url || !token) throw new Error('PROBE_URL and PROBE_TOKEN are needed');

function keyscan(host: string): Record<string, string> {
  const lines = execFileSync(
    'sh',
    ['-c', `ssh-keyscan -t ed25519,ecdsa,rsa ${host} 2>/dev/null | ssh-keygen -lf -`],
    { encoding: 'utf8' },
  );
  const byType: Record<string, string> = {
    ED25519: 'ssh-ed25519',
    ECDSA: 'ecdsa-sha2-nistp256',
    RSA: 'rsa-sha2-256',
  };
  const pins: Record<string, string> = {};
  for (const line of lines.trim().split('\n')) {
    const type = /\((\w+)\)$/.exec(line)?.[1];
    if (type && byType[type]) pins[byType[type]] = line.split(' ')[1]!;
  }
  return pins;
}

function cloudflared(): string {
  const local = join(ROOT, '.cache/cloudflared/cloudflared');
  try {
    execFileSync('cloudflared', ['--version'], { stdio: 'ignore' });
    return 'cloudflared';
  } catch {
    if (existsSync(local)) return local;
    throw new Error('cloudflared is not installed, on PATH or in .cache/cloudflared/');
  }
}

/** A quick tunnel to the bastion's SSH port, and the hostname it was given. */
function quickTunnel(port: number): Promise<{ hostname: string; stop(): void }> {
  const child = spawn(
    cloudflared(),
    ['tunnel', '--no-autoupdate', '--url', `ssh://127.0.0.1:${port}`],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  return new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('the quick tunnel did not come up in 60 s')),
      60_000,
    );
    let registered = false;
    let hostname = '';
    const watch = (chunk: Buffer) => {
      const text = chunk.toString();
      hostname ||= /https:\/\/([a-z0-9-]+\.trycloudflare\.com)/.exec(text)?.[1] ?? '';
      registered ||= /Registered tunnel connection/.test(text);
      if (hostname && registered) {
        clearTimeout(timer);
        resolve({ hostname, stop: () => child.kill() });
      }
    };
    child.stdout.on('data', watch);
    child.stderr.on('data', watch);
    child.on('exit', (code) => reject(new Error(`cloudflared exited with ${code}`)));
  });
}

interface Outcome {
  name: string;
  ok: boolean;
  detail: string;
  ms: number;
}

async function main(): Promise<void> {
  setUp();
  const tunnel = await (async () => {
    for (const server of SERVERS) await waitFor(server);
    return quickTunnel(SERVERS[0]!.port);
  })();
  try {
    const bastion = SERVERS[0]!;
    const dropbear = SERVERS[2]!;
    const pinsOf = (server: typeof bastion) =>
      Object.values(server.hostKeys).map((file) => fingerprint(server, file));
    const plan = {
      tcp: {
        host: 'test.rebex.net',
        port: 22,
        username: 'demo',
        password: 'password',
        pins: keyscan('test.rebex.net'),
      },
      tunnel: {
        hostname: tunnel.hostname,
        pins: pinsOf(bastion),
        key: readFileSync(fileOf('ed25519'), 'utf8'),
        lockedKey: {
          text: readFileSync(fileOf('ed25519+passphrase'), 'utf8'),
          passphrase: 'matrix passphrase',
        },
        jump: { host: dropbear.name, pins: pinsOf(dropbear) },
        gex: { host: SERVERS[1]!.name, pins: pinsOf(SERVERS[1]!) },
      },
    };
    // A quick tunnel's name takes a moment to resolve everywhere.
    await new Promise((resolve) => setTimeout(resolve, 5000));
    const post = async (query = '') => {
      const response = await fetch(`${url}/run${query}`, {
        method: 'POST',
        headers: { 'x-probe-token': token! },
        body: JSON.stringify(plan),
      });
      if (!response.ok)
        throw new Error(`the probe answered ${response.status}: ${await response.text()}`);
      return (await response.json()) as unknown;
    };
    const { cases } = (await post()) as { cases: string[] };
    console.log(`against ${url}, tunnel ${tunnel.hostname}\n`);
    const results: Outcome[] = [];
    for (const name of cases) {
      const result = (await post(`?case=${encodeURIComponent(name)}`)) as Outcome & {
        colo: string | null;
      };
      results.push(result);
      const where = result.colo ? ` [${result.colo}]` : '';
      console.log(
        `${result.ok ? 'pass' : 'FAIL'} ${result.name.padEnd(62)} ${result.detail} (${result.ms} ms)${where}`,
      );
    }
    const failed = results.filter((result) => !result.ok).length;
    console.log(`\n${results.length - failed} passed, ${failed} failed`);
    process.exitCode = failed ? 1 : 0;
  } finally {
    tunnel.stop();
    tearDown();
  }
}

await main();
