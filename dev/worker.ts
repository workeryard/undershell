/**
 * The probe Worker: the client run where it is meant to run, against real
 * servers, so what only the platform does shows. `wrangler dev` runs workerd
 * too, but not the platform's limits: the block on sockets to Cloudflare's
 * own addresses, the subrequest count, CPU time.
 *
 * POST /run with a JSON plan (scripts/live.ts writes one) lists its cases;
 * POST /run?case=<name> with the same plan runs one. Every request
 * needs the x-probe-token header to match the PROBE_TOKEN secret, and
 * without the secret nothing runs at all.
 */

import { connect, openSocket, openTunnel, type SshClient } from '../src/workers/index';
import type { Authentication } from '../src/index';
import { kexCases } from './kex-cases';

interface Env {
  PROBE_TOKEN?: string;
}

interface Plan {
  /** A public server over TCP: test.rebex.net, which lets anyone in as demo. */
  tcp?: {
    host: string;
    port: number;
    username: string;
    password: string;
    pins: Record<string, string>;
  };
  /** The matrix's servers behind a quick tunnel, its keys and their pins. */
  tunnel?: {
    hostname: string;
    pins: string[];
    key: string;
    lockedKey: { text: string; passphrase: string };
    jump: { host: string; pins: string[] };
    /** A server behind the bastion that still offers the group exchange. */
    gex: { host: string; pins: string[] };
  };
}

interface Outcome {
  name: string;
  ok: boolean;
  detail: string;
  ms: number;
}

type Cases = Map<string, () => Promise<string | void>>;

function attempt(cases: Cases, name: string, body: () => Promise<string | void>): void {
  cases.set(name, body);
}

/** One case, with a deadline: a hang is a failure to report, not a request that never ends. */
async function run(name: string, body: () => Promise<string | void>): Promise<Outcome> {
  const started = Date.now();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('no answer within 60 s')), 60_000);
    });
    const detail = (await Promise.race([body(), deadline])) ?? '';
    return { name, ok: true, detail, ms: Date.now() - started };
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return { name, ok: false, detail, ms: Date.now() - started };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

const KEX = ['curve25519-sha256', 'ecdh-sha2-nistp256'] as const;
const CIPHERS = [
  'aes256-gcm@openssh.com',
  'aes128-gcm@openssh.com',
  'aes256-ctr',
  'aes192-ctr',
  'aes128-ctr',
] as const;

function overTcp(plan: NonNullable<Plan['tcp']>, results: Cases): void {
  const base = (extra: Partial<Parameters<typeof connect>[0]> = {}) =>
    connect({
      host: plan.host,
      port: plan.port,
      username: plan.username,
      auth: { kind: 'password', password: plan.password },
      hostKeyFingerprint: Object.values(plan.pins),
      ...extra,
    });
  const use = async (client: SshClient, what: () => Promise<string>) => {
    try {
      return await what();
    } finally {
      await client.close();
    }
  };

  attempt(results, 'tcp: exec and SFTP over cloudflare:sockets', async () => {
    const client = await base();
    return use(client, async () => {
      const listing = await client.exec('ls /');
      const sftp = await client.sftp();
      const readme = await sftp.get('/readme.txt');
      await sftp.end();
      return `${client.serverVersion}; ${client.negotiated.kex}, ${client.negotiated.cipher}; ls: ${listing.stdout.trim().replace(/\n/g, ' ')}; readme ${readme.length} bytes`;
    });
  });
  for (const kex of KEX) {
    for (const cipher of CIPHERS) {
      attempt(results, `tcp: ${kex} ${cipher}`, async () => {
        const client = await base({ algorithms: { kex: [kex], cipher: [cipher] } });
        return use(
          client,
          async () =>
            `${(await client.exec('ls /')).exitStatus === 0 ? 'ok' : 'exec failed'}${client.negotiated.mac ? `, ${client.negotiated.mac}` : ''}`,
        );
      });
    }
  }
  for (const [algorithm, pin] of Object.entries(plan.pins)) {
    attempt(results, `tcp: host key ${algorithm}`, async () => {
      const client = await base({
        algorithms: { hostKey: [algorithm as never] },
        hostKeyFingerprint: pin,
      });
      return use(client, () => Promise.resolve(`SHA256:${client.hostKey.fingerprint}`));
    });
  }
  attempt(results, 'tcp: a wrong fingerprint is refused', async () => {
    const refused = await base({ hostKeyFingerprint: 'SHA256:' + 'A'.repeat(43) }).then(
      async (client) => (await client.close(), false),
      (error: Error) => /expected/.test(error.message),
    );
    if (!refused) throw new Error('it connected');
  });
  const refusal = (host: string, port: number) =>
    openSocket(host, port, 8000).then(
      async (socket) => (await socket.close?.(), 'it connected'),
      (error: Error) => error.message,
    );
  attempt(results, 'tcp: a Cloudflare address on port 22 is refused, with the hint', async () => {
    const said = await refusal('example.com', 22);
    if (!/behind Cloudflare/.test(said)) throw new Error(said);
    return said.slice(0, 160);
  });
  attempt(results, 'tcp: a Cloudflare address on port 443, named as one', async () => {
    const said = await refusal('example.com', 443);
    if (!/Cloudflare's own IP ranges/.test(said)) throw new Error(said);
    return said.slice(0, 160);
  });
  attempt(results, 'tcp: a dead address (TEST-NET-1), for what the platform says', async () => {
    const said = await refusal('192.0.2.1', 22);
    if (said === 'it connected') throw new Error(said);
    return said.slice(0, 160);
  });
}

function overTunnel(plan: NonNullable<Plan['tunnel']>, results: Cases): void {
  const key: Authentication = { kind: 'privateKey', privateKey: plan.key };
  const base = (extra: Partial<Parameters<typeof connect>[0]> = {}) =>
    connect({
      tunnel: { hostname: plan.hostname },
      username: 'tester',
      auth: key,
      hostKeyFingerprint: plan.pins,
      ...extra,
    });

  attempt(results, 'tunnel: 3 MB of exec output over a WebSocket', async () => {
    const client = await base();
    try {
      const result = await client.exec('head -c 3000000 /dev/zero | tr "\\0" a', {
        maxOutputBytes: 4_000_000,
      });
      if (result.stdout.length !== 3_000_000 || result.truncated)
        throw new Error(`got ${result.stdout.length}`);
      return `${client.serverVersion}, ${client.transport.keyExchanges} key exchanges`;
    } finally {
      await client.close();
    }
  });
  attempt(results, 'tunnel: SFTP, 5 MB up and back, streamed', async () => {
    const client = await base();
    try {
      const sftp = await client.sftp();
      const size = 5 * 1024 * 1024;
      const data = new Uint8Array(size).map((_, i) => (i * 7) % 256);
      await sftp.put('/tmp/live.bin', data);
      let back = 0;
      let same = true;
      for await (const chunk of sftp.createReadStream('/tmp/live.bin')) {
        for (let i = 0; i < chunk.length; i++) if (chunk[i] !== data[back + i]) same = false;
        back += chunk.length;
      }
      await sftp.remove('/tmp/live.bin');
      await sftp.end();
      if (back !== size || !same) throw new Error(`came back ${back} bytes, same: ${same}`);
      return `${size} bytes`;
    } finally {
      await client.close();
    }
  });
  attempt(results, 'tunnel: a shell with a pty and a resize', async () => {
    const client = await base();
    try {
      const shell = await client.shell({ pty: { cols: 90, rows: 20 } });
      const writer = shell.stdin.getWriter();
      let seen = '';
      const reading = (async () => {
        for await (const chunk of shell.stdout) seen += new TextDecoder().decode(chunk);
      })();
      await writer.write(new TextEncoder().encode('stty size\n'));
      await new Promise((resolve) => setTimeout(resolve, 500));
      await shell.resize(120, 40);
      await new Promise((resolve) => setTimeout(resolve, 500));
      await writer.write(new TextEncoder().encode('stty size; exit\n'));
      await reading;
      if (!seen.includes('20 90') || !seen.includes('40 120'))
        throw new Error(JSON.stringify(seen.slice(-200)));
      return 'saw 20 90, then 40 120';
    } finally {
      await client.close();
    }
  });
  attempt(results, 'tunnel: a jump from the tunnel to a host behind it', async () => {
    const client = await base({ jump: [] });
    try {
      const inner = await client.jump({
        host: plan.jump.host,
        username: 'tester',
        auth: key,
        hostKeyFingerprint: plan.jump.pins,
      });
      const result = await inner.exec('echo $(uname -n) behind the bastion');
      await inner.close();
      return `${inner.serverVersion}: ${result.stdout.trim()}`;
    } finally {
      await client.close().catch(() => {});
    }
  });
  attempt(results, 'tunnel: a key with a passphrase (bcrypt_pbkdf in the Worker)', async () => {
    const started = Date.now();
    const client = await base({
      auth: {
        kind: 'privateKey',
        privateKey: plan.lockedKey.text,
        passphrase: plan.lockedKey.passphrase,
      },
    });
    await client.close();
    return `${Date.now() - started} ms to unlock, connect and log in`;
  });
  kexCases(attempt.bind(null, results), base, plan.gex, key);
  attempt(results, 'tunnel: keyboard-interactive', async () => {
    const client = await base({
      auth: { kind: 'keyboardInteractive', respond: (c) => c.prompts.map(() => 'tester-password') },
    });
    await client.close();
  });
  attempt(results, 'tunnel: the tunnel itself, as a ByteSocket', async () => {
    const socket = await openTunnel({ hostname: plan.hostname });
    const { value } = await socket.readable.getReader().read();
    await socket.close?.();
    return new TextDecoder().decode(value).split('\r\n')[0]!;
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (!env.PROBE_TOKEN || request.headers.get('x-probe-token') !== env.PROBE_TOKEN) {
      return new Response('not found', { status: 404 });
    }
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/run') {
      return new Response('POST /run', { status: 400 });
    }
    const plan = (await request.json()) as Plan;
    const cases: Cases = new Map();
    if (plan.tcp) overTcp(plan.tcp, cases);
    if (plan.tunnel) overTunnel(plan.tunnel, cases);
    // One case a request: each stays well inside the subrequest limit and the
    // time a request may take, and one hang does not hide the rest.
    const name = new URL(request.url).searchParams.get('case');
    if (!name) return Response.json({ cases: [...cases.keys()] });
    const body = cases.get(name);
    if (!body) return new Response(`no case ${name}`, { status: 404 });
    const colo = (request as { cf?: { colo?: string } }).cf?.colo ?? null;
    return Response.json({ ...(await run(name, body)), colo });
  },
};
