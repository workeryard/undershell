/**
 * The Docker matrix: every algorithm, key type and login method against real
 * servers — OpenSSH as Alpine ships it today, OpenSSH 8.2 from Ubuntu 20.04,
 * and Dropbear — plus a jump through a bastion, 3 MB of output, shells,
 * forwarding and SFTP. Run before every release:
 *
 *   make matrix            (pnpm tsx scripts/matrix.ts [--keep] [--only name])
 *
 * The parts most likely to break — window accounting, the GCM counter,
 * strict KEX — produce no error in a unit test, only a hang or a silent
 * truncation against a real server, which is why this exists.
 *
 * A pairing a server does not offer is reported as n/a, and only when the
 * client's own error says the server lacked it; anything else is a failure.
 */

import { readFileSync } from 'node:fs';
import {
  CIPHERS,
  KEX,
  MACS,
  SshClient,
  type Authentication,
  type ConnectOptions,
} from '../src/index';
import { openNodeSocket } from './node-socket';
import { channelCases, type Case } from './matrix-cases';
import {
  CLIENT_KEYS,
  fileOf,
  fingerprint,
  SERVERS,
  setUp,
  tearDown,
  waitFor,
  type Server,
} from './matrix-docker';

const keep = process.argv.includes('--keep');
const only = process.argv.includes('--only')
  ? process.argv[process.argv.indexOf('--only') + 1]
  : undefined;

const key = (name: string): Authentication => ({
  kind: 'privateKey',
  privateKey: readFileSync(fileOf(name), 'utf8'),
  ...(CLIENT_KEYS.find((k) => k.name === name)?.passphrase && {
    passphrase: CLIENT_KEYS.find((k) => k.name === name)!.passphrase!,
  }),
});

type Result = {
  server: string;
  group: string;
  name: string;
  outcome: 'pass' | 'n/a' | 'FAIL';
  detail: string;
};
const results: Result[] = [];

async function check(
  server: Server,
  group: string,
  name: string,
  body: () => Promise<string | void>,
): Promise<void> {
  const started = performance.now();
  try {
    const detail = await Promise.race([
      body(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('timed out after 60 s')), 60_000),
      ),
    ]);
    results.push({
      server: server.name,
      group,
      name,
      outcome: 'pass',
      detail: `${detail ?? ''} ${(performance.now() - started).toFixed(0)} ms`.trim(),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const missing = /the server offers no/.test(message);
    results.push({
      server: server.name,
      group,
      name,
      outcome: missing ? 'n/a' : 'FAIL',
      detail: message.slice(0, 160),
    });
  }
  const last = results.at(-1)!;
  console.log(
    `${last.outcome.padEnd(4)} ${server.name.padEnd(15)} ${group.padEnd(10)} ${name.padEnd(46)} ${last.detail}`,
  );
}

async function main(): Promise<void> {
  setUp();
  try {
    for (const server of SERVERS) await waitFor(server);
    for (const server of SERVERS) {
      if (only && server.name !== only) continue;
      const pins = Object.fromEntries(
        Object.entries(server.hostKeys).map(([algorithm, file]) => [
          algorithm,
          fingerprint(server, file),
        ]),
      );
      const base = (extra: Partial<ConnectOptions> = {}): Promise<SshClient> =>
        openNodeSocket('127.0.0.1', server.port).then((socket) =>
          SshClient.connect({
            socket,
            username: 'tester',
            auth: key('ed25519'),
            hostKeyFingerprint: Object.values(pins),
            ...extra,
          }),
        );
      const echo = async (client: SshClient) => {
        const result = await client.exec('echo ok');
        await client.close();
        if (result.stdout !== 'ok\n')
          throw new Error(`echo printed ${JSON.stringify(result.stdout)}`);
      };

      for (const kex of KEX) {
        for (const cipher of CIPHERS) {
          const macs = cipher.includes('gcm') ? [undefined] : MACS;
          for (const mac of macs) {
            await check(
              server,
              'algorithms',
              `${kex} ${cipher}${mac ? ` ${mac}` : ''}`,
              async () => {
                const client = await base({
                  algorithms: { kex: [kex], cipher: [cipher], ...(mac && { mac: [mac] }) },
                });
                const strict = client.negotiated.strictKex ? 'strict' : '';
                await echo(client);
                return strict;
              },
            );
          }
        }
      }
      for (const [algorithm, pin] of Object.entries(pins)) {
        await check(server, 'host key', algorithm, async () => {
          const client = await base({
            algorithms: { hostKey: [algorithm as never] },
            hostKeyFingerprint: pin,
          });
          await echo(client);
          return `${pin.slice(0, 19)}…`;
        });
      }
      for (const { name } of CLIENT_KEYS) {
        await check(server, 'client key', name, async () => echo(await base({ auth: key(name) })));
      }
      await check(server, 'login', 'password', async () =>
        echo(await base({ auth: { kind: 'password', password: 'tester-password' } })),
      );
      await check(server, 'login', 'none, then password', async () =>
        echo(
          await base({
            auth: [{ kind: 'none' }, { kind: 'password', password: 'tester-password' }],
          }),
        ),
      );
      if (server.openssh) {
        await check(server, 'login', 'keyboard-interactive', async () => {
          const asked: string[] = [];
          const client = await base({
            auth: {
              kind: 'keyboardInteractive',
              respond: (c) => c.prompts.map((p) => (asked.push(p.text), 'tester-password')),
            },
          });
          await echo(client);
          return `asked ${JSON.stringify(asked)}`;
        });
        await check(server, 'login', 'key then keyboard-interactive (2FA)', async () => {
          const client = await base({
            username: 'twofactor',
            auth: [
              key('ed25519'),
              {
                kind: 'keyboardInteractive',
                respond: (c) => c.prompts.map(() => 'twofactor-password'),
              },
            ],
          });
          await echo(client);
        });
      }
      await check(server, 'login', 'wrong password refused', async () => {
        const refused = await base({ auth: { kind: 'password', password: 'nope' } }).then(
          () => false,
          (error: Error) => /did not accept/.test(error.message),
        );
        if (!refused) throw new Error('a wrong password was not refused as such');
      });
      await check(server, 'host key', 'wrong fingerprint refused', async () => {
        const wrong = 'SHA256:' + 'A'.repeat(43);
        const refused = await base({ hostKeyFingerprint: wrong }).then(
          () => false,
          (error: Error) => /not the SHA256:A+ expected/.test(error.message),
        );
        if (!refused) throw new Error('a wrong fingerprint was not refused');
      });
      await check(server, 'host key', 'verifyHostKey false refused', async () => {
        const refused = await base({ verifyHostKey: () => false }).then(
          () => false,
          (error: Error) => /refused by verifyHostKey/.test(error.message),
        );
        if (!refused) throw new Error('verifyHostKey returning false was not honoured');
      });
      await check(server, 'host key', 'no pin at all refused', async () => {
        const refused = await base({ hostKeyFingerprint: [] }).then(
          () => false,
          (error: Error) => /will not trust on first use/.test(error.message),
        );
        if (!refused) throw new Error('a connection without any host key check went through');
      });

      for (const item of channelCases(server.name, server.openssh) satisfies Case[]) {
        await check(server, item.group, item.name, async () => {
          const client = await base(item.connect);
          try {
            return await item.run(client);
          } finally {
            await client.close();
          }
        });
      }
    }

    // A jump: the latest OpenSSH as bastion, the other two behind it by their network names.
    const bastion = SERVERS[0]!;
    for (const target of SERVERS.slice(1)) {
      if (only && target.name !== only && bastion.name !== only) continue;
      await check(bastion, 'jump', `through ${bastion.name} to ${target.name}`, async () => {
        const pins = Object.values(bastion.hostKeys).map((file) => fingerprint(bastion, file));
        const targetPins = Object.values(target.hostKeys).map((file) => fingerprint(target, file));
        const first = await SshClient.connect({
          socket: await openNodeSocket('127.0.0.1', bastion.port),
          username: 'tester',
          auth: key('ed25519'),
          hostKeyFingerprint: pins,
        });
        const second = await first.jump({
          host: target.name,
          port: 22,
          username: 'tester',
          auth: key('ecdsa-256'),
          hostKeyFingerprint: targetPins,
        });
        // The bastion's pins do not open the target: each hop is checked on its own.
        const crossed = await first
          .jump({
            host: target.name,
            port: 22,
            username: 'tester',
            auth: key('ed25519'),
            hostKeyFingerprint: pins,
          })
          .then(
            () => true,
            () => false,
          );
        const result = await second.exec('head -c 3000000 /dev/zero | tr "\\0" x', {
          maxOutputBytes: 4_000_000,
        });
        await second.close();
        if (crossed) throw new Error("the target accepted the bastion's fingerprint");
        if (result.stdout.length !== 3_000_000 || result.truncated)
          throw new Error(`3 MB came through as ${result.stdout.length}`);
        return `${second.serverVersion}, 3 MB through the hop`;
      });
    }
  } finally {
    if (!keep) tearDown();
  }

  const failed = results.filter((r) => r.outcome === 'FAIL');
  const counts = (outcome: Result['outcome']) =>
    results.filter((r) => r.outcome === outcome).length;
  console.log(
    `\n${counts('pass')} passed, ${counts('n/a')} not offered by the server, ${failed.length} failed`,
  );
  for (const r of failed) console.log(`  FAIL ${r.server} ${r.group} ${r.name}: ${r.detail}`);
  process.exit(failed.length ? 1 : 0);
}

await main();
