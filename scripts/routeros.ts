/**
 * MikroTik RouterOS, as the Cloud Hosted Router image runs it under QEMU:
 * the SSH server many networks are run through, and not OpenSSH. Its shell
 * is RouterOS's console, so it has checks of its own rather than the
 * matrix's Linux commands.
 *
 *   make routeros          (needs Docker and /dev/kvm)
 *
 * The images are not redistributed here; they are downloaded from
 * download.mikrotik.com into .cache/chr/. RouterOS 7 is expected to work.
 * RouterOS 6 offers only finite-field Diffie-Hellman and, by default, SHA-1
 * MACs, none of which this client speaks, so it is expected to be refused,
 * with an error that says what the server offered.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { CIPHERS, SshClient, type ConnectOptions } from '../src/index';
import { openNodeSocket } from './node-socket';

const ROOT = new URL('..', import.meta.url).pathname;
const CACHE = join(ROOT, '.cache/chr');
const VERSIONS = [
  { version: '7.24.5', port: 2321, works: true },
  { version: '6.49.23', port: 2322, works: false },
];

const run = (command: string, args: string[]) =>
  execFileSync(command, args, { encoding: 'utf8' }).trim();
const container = (version: string) => `us-chr-${version}`;

function start(version: string, port: number): void {
  const image = join(CACHE, `chr-${version}.img`);
  if (!existsSync(image)) {
    mkdirSync(CACHE, { recursive: true });
    const zip = join(CACHE, `chr-${version}.img.zip`);
    run('curl', [
      '-fsSL',
      '--retry',
      '3',
      '-o',
      zip,
      `https://download.mikrotik.com/routeros/${version}/chr-${version}.img.zip`,
    ]);
    run('unzip', ['-oq', zip, '-d', CACHE]);
  }
  run('docker', [
    'build',
    '-q',
    '-t',
    'undershell-chr',
    '-f',
    join(ROOT, 'docker/chr.Dockerfile'),
    join(ROOT, 'docker'),
  ]);
  stop(version);
  run('docker', [
    'run',
    '-d',
    '--name',
    container(version),
    '--device',
    '/dev/kvm',
    '-p',
    `127.0.0.1:${port}:22`,
    '-v',
    `${image}:/chr.img:ro`,
    'undershell-chr',
  ]);
}

function stop(version: string): void {
  try {
    run('docker', ['rm', '-f', container(version)]);
  } catch {
    // Not running.
  }
}

/** The host key's fingerprint as ssh-keyscan sees it, once the router has booted. */
async function pin(port: number): Promise<string> {
  for (let attempt = 0; attempt < 90; attempt++) {
    try {
      const line = run('sh', [
        '-c',
        `ssh-keyscan -T 3 -p ${port} 127.0.0.1 2>/dev/null | ssh-keygen -lf - 2>/dev/null`,
      ]);
      if (line) return line.split(' ')[1]!;
    } catch {
      // Still booting.
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  throw new Error(`the router on ${port} did not come up`);
}

let failed = 0;
async function check(name: string, body: () => Promise<string | void>): Promise<void> {
  try {
    console.log(`pass ${name.padEnd(56)} ${(await body()) ?? ''}`);
  } catch (error) {
    failed++;
    console.log(
      `FAIL ${name.padEnd(56)} ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

async function routerOs7(port: number, fingerprint: string): Promise<void> {
  const base = async (extra: Partial<ConnectOptions> = {}) =>
    SshClient.connect({
      socket: await openNodeSocket('127.0.0.1', port),
      username: 'admin',
      // A fresh CHR's admin has no password.
      auth: { kind: 'password', password: '' },
      hostKeyFingerprint: fingerprint,
      ...extra,
    });

  for (const cipher of CIPHERS) {
    await check(`curve25519-sha256 ${cipher}`, async () => {
      const client = await base({ algorithms: { cipher: [cipher] } });
      const ok = (await client.exec(':put ok')).stdout.trim();
      await client.close();
      if (ok !== 'ok') throw new Error(`printed ${ok}`);
      return `${client.serverVersion}, ${client.negotiated.hostKey}${client.negotiated.mac ? `, ${client.negotiated.mac}` : ''}`;
    });
  }
  await check('a RouterOS command, and 800 KB of its output', async () => {
    const client = await base();
    try {
      const resource = await client.exec('/system resource print');
      const version = /version: (\S+)/.exec(resource.stdout)?.[1];
      const loop = await client.exec(
        ':for i from=1 to=20000 do={:put "line $i of output to fill the window"}',
        {
          maxOutputBytes: 4_000_000,
        },
      );
      if (!version || loop.truncated || loop.stdout.split('\n').length < 20_000) {
        throw new Error(`version ${version}, ${loop.stdout.length} bytes`);
      }
      return `RouterOS ${version}, ${loop.stdout.length} bytes`;
    } finally {
      await client.close();
    }
  });
  await check('SFTP: put, list, get, remove', async () => {
    const client = await base();
    const sftp = await client.sftp();
    try {
      await sftp.put('/undershell.txt', new TextEncoder().encode('hello router'));
      const names = (await sftp.list('/')).map((entry) => entry.name);
      const back = new TextDecoder().decode(await sftp.get('/undershell.txt'));
      await sftp.remove('/undershell.txt');
      if (!names.includes('undershell.txt') || back !== 'hello router')
        throw new Error(`${names.join()} / ${back}`);
      return `listed ${names.join(', ')}`;
    } finally {
      await sftp.end();
      await client.close();
    }
  });
  await check("the console in a pty, answering its terminal's questions", async () => {
    const client = await base();
    try {
      const shell = await client.shell({ pty: { cols: 100, rows: 30 } });
      const writer = shell.stdin.getWriter();
      const send = (text: string) => writer.write(new TextEncoder().encode(text));
      let seen = '';
      const reading = (async () => {
        for await (const chunk of shell.stdout) {
          const text = new TextDecoder().decode(chunk);
          seen += text;
          // The console asks where the cursor is and waits for an answer, as
          // a terminal (xterm.js, say) gives; a fresh router then offers its licence
          // and asks for a new password, which Ctrl-C skips.
          if (text.includes('\x1b[6n')) await send('\x1b[30;100R');
          if (/software license\? \[Y\/n\]: $/.test(seen)) await send('n\r');
          if (/new password> $/.test(seen)) await send('\x03');
        }
      })().catch(() => {});
      const until = async (pattern: RegExp) => {
        for (let waited = 0; !pattern.test(seen); waited += 100) {
          if (waited > 15_000)
            throw new Error(`waited for ${pattern}; saw ${JSON.stringify(seen.slice(-200))}`);
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      };
      await until(/\] > $/);
      await shell.resize(140, 40);
      await send('/system identity print\r');
      await until(/name: \S+/);
      await send('/quit\r');
      await Promise.race([reading, new Promise((resolve) => setTimeout(resolve, 5000))]);
      return 'prompt, identity, quit';
    } finally {
      await client.close();
    }
  });
  await check('a wrong fingerprint refused', async () => {
    const refused = await base({ hostKeyFingerprint: 'SHA256:' + 'A'.repeat(43) }).then(
      async (client) => (await client.close(), false),
      () => true,
    );
    if (!refused) throw new Error('it connected');
  });
}

async function main(): Promise<void> {
  for (const { version, port, works } of VERSIONS) {
    console.log(`\nRouterOS ${version}`);
    start(version, port);
    try {
      const fingerprint = await pin(port);
      if (works) {
        await routerOs7(port, fingerprint);
      } else {
        await check('refused, saying what the server offers', async () => {
          const error = await SshClient.connect({
            socket: await openNodeSocket('127.0.0.1', port),
            username: 'admin',
            auth: { kind: 'password', password: '' },
            hostKeyFingerprint: fingerprint,
          }).then(
            async (client) => (await client.close(), null),
            (caught: Error) => caught,
          );
          if (!error || !/offers no key exchange/.test(error.message))
            throw new Error(error?.message ?? 'it connected');
          return error.message.slice(0, 120);
        });
      }
    } finally {
      stop(version);
    }
  }
  console.log(failed ? `\n${failed} failed` : '\nall passed');
  process.exitCode = failed ? 1 : 0;
}

await main();
