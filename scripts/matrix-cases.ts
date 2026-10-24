/** What the matrix does on each connection once it is up: commands, shells, tunnels, files. */

import type { ConnectOptions, SshClient } from '../src/index';
import { keepaliveCase } from './matrix-keepalive';

export interface Case {
  group: string;
  name: string;
  /** Options of its own for the connection, over the matrix's defaults. */
  connect?: Partial<ConnectOptions>;
  run(client: SshClient): Promise<string | void>;
}

const text = (value: string) => new TextEncoder().encode(value);

async function readAll(stream: ReadableStream<Uint8Array>): Promise<string> {
  let out = '';
  const decoder = new TextDecoder();
  for await (const chunk of stream) out += decoder.decode(chunk, { stream: true });
  return out + decoder.decode();
}

async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...hash].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Deterministic, not repeating within a chunk: a misplaced chunk shows in the hash. */
function pattern(length: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(length);
  let state = 0x12345678;
  for (let index = 0; index < length; index++) {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    out[index] = state >>> 24;
  }
  return out;
}

export function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

export function channelCases(server: string, openssh: boolean): Case[] {
  const dir = `/tmp/matrix-${server}`;
  return [
    keepaliveCase(server),
    {
      group: 'exec',
      name: '3 MB of output, untruncated (window accounting)',
      async run(client) {
        const result = await client.exec('head -c 3000000 /dev/zero | tr "\\0" a', {
          maxOutputBytes: 4_000_000,
        });
        assert(
          result.stdout.length === 3_000_000 && !result.truncated,
          `got ${result.stdout.length} bytes, truncated ${result.truncated}`,
        );
        assert(result.exitStatus === 0, `exit ${result.exitStatus}`);
      },
    },
    {
      group: 'rekey',
      name: 'the client re-keys of its own accord (every 256 KiB) through 3 MB',
      connect: { rekeyAfterBytes: 256 * 1024 },
      async run(client) {
        const result = await client.exec('head -c 3000000 /dev/zero | tr "\\0" a', {
          maxOutputBytes: 4_000_000,
        });
        const exchanges = client.transport.keyExchanges;
        assert(result.stdout.length === 3_000_000, `got ${result.stdout.length} bytes`);
        // Up to a window is already on its way when our KEXINIT goes out, so
        // the exchanges come further apart than 256 KiB; more than two is the point.
        assert(exchanges > 2, `only ${exchanges} key exchanges`);
        return `${exchanges} key exchanges`;
      },
    },
    ...(openssh
      ? [
          {
            group: 'rekey',
            name: 'the server re-keys (RekeyLimit 1M) mid-upload and mid-download',
            async run(client: SshClient) {
              const upload = await client.exec('wc -c', { stdin: 'u'.repeat(3_000_000) });
              const download = await client.exec('head -c 3000000 /dev/zero | tr "\\0" a', {
                maxOutputBytes: 4_000_000,
              });
              const exchanges = client.transport.keyExchanges;
              assert(
                upload.stdout.trim() === '3000000',
                `the server counted ${upload.stdout.trim()}`,
              );
              assert(download.stdout.length === 3_000_000, `got ${download.stdout.length} bytes`);
              assert(exchanges > 2, `only ${exchanges} key exchanges`);
              return `${exchanges} key exchanges`;
            },
          },
        ]
      : []),
    {
      group: 'exec',
      name: 'past maxOutputBytes: truncated, and still exits',
      async run(client) {
        const result = await client.exec('head -c 3000000 /dev/zero | tr "\\0" a', {
          maxOutputBytes: 1000,
        });
        assert(
          result.stdout.length === 1000 && result.truncated && result.exitStatus === 0,
          JSON.stringify({ ...result, stdout: result.stdout.length }),
        );
      },
    },
    {
      group: 'exec',
      name: 'stdout, stderr and exit status kept apart',
      async run(client) {
        const result = await client.exec('echo out; echo err >&2; exit 7');
        assert(
          result.stdout === 'out\n' && result.stderr === 'err\n' && result.exitStatus === 7,
          JSON.stringify(result),
        );
      },
    },
    {
      group: 'exec',
      name: 'stdin fed and closed',
      async run(client) {
        const result = await client.exec('wc -c', { stdin: 'x'.repeat(100_000) });
        assert(result.stdout.trim() === '100000', JSON.stringify(result.stdout));
      },
    },
    {
      group: 'exec',
      name: 'five commands at once on one connection',
      async run(client) {
        const results = await Promise.all(
          [1, 2, 3, 4, 5].map((n) => client.exec(`sleep 0.$n; echo ${n}`)),
        );
        assert(
          results.map((r) => r.stdout.trim()).join() === '1,2,3,4,5',
          results.map((r) => r.stdout).join('|'),
        );
      },
    },
    {
      group: 'exec',
      name: 'killed by a signal, reported as one',
      async run(client) {
        const result = await client.exec('kill -TERM $$');
        assert(result.exitSignal === 'TERM' || result.exitStatus === 143, JSON.stringify(result));
        return result.exitSignal ? `exit-signal ${result.exitSignal}` : `exit ${result.exitStatus}`;
      },
    },
    {
      group: 'shell',
      name: 'pty: TERM, size, and window-change',
      async run(client) {
        const shell = await client.shell({ pty: { term: 'xterm-256color', cols: 100, rows: 30 } });
        const writer = shell.stdin.getWriter();
        const output = readAll(shell.stdout);
        await writer.write(text('echo "T=$TERM"; stty size\n'));
        await new Promise((resolve) => setTimeout(resolve, 300));
        await shell.resize(132, 43);
        await new Promise((resolve) => setTimeout(resolve, 300));
        await writer.write(text('stty size; exit\n'));
        const seen = await output;
        const exit = await shell.exit;
        assert(seen.includes('T=xterm-256color'), 'TERM was not passed');
        assert(seen.includes('30 100'), 'the first size was not seen');
        assert(seen.includes('43 132'), 'the resize was not seen');
        assert(exit.code === 0, `the shell exited ${exit.code}`);
      },
    },
    {
      group: 'forward',
      name: 'direct-tcpip to the server itself',
      async run(client) {
        const tunnel = await client.forward('127.0.0.1', 22);
        const reader = tunnel.readable.getReader();
        const { value } = await reader.read();
        await tunnel.close();
        const banner = new TextDecoder().decode(value).split('\r\n')[0]!;
        assert(banner.startsWith('SSH-2.0-'), `the tunnel read ${JSON.stringify(banner)}`);
        return banner;
      },
    },
    {
      group: 'forward',
      name: 'a closed port refused as a channel open failure',
      async run(client) {
        const refused = await client.forward('127.0.0.1', 1).then(
          () => false,
          (error: Error) => error.name === 'ChannelOpenError',
        );
        assert(refused, 'opening a closed port did not fail as a ChannelOpenError');
      },
    },
    {
      group: 'sftp',
      name: 'mkdir, put 5 MB streamed, stat, rename, readdir, get, remove, rmdir',
      async run(client) {
        const sftp = await client.sftp();
        try {
          await client.exec(`rm -rf ${dir}`);
          await sftp.mkdir(dir);
          const data = pattern(5 * 1024 * 1024 + 123);
          // Streamed in uneven pieces, so chunking and offsets are what is tested.
          const source = new ReadableStream<Uint8Array>({
            start(controller) {
              for (let at = 0; at < data.length; at += 77_777)
                controller.enqueue(data.slice(at, at + 77_777));
              controller.close();
            },
          });
          await sftp.put(`${dir}/a.bin`, source);
          const stats = await sftp.stat(`${dir}/a.bin`);
          assert(stats.size === data.length && stats.isFile, `stat said ${JSON.stringify(stats)}`);
          await sftp.rename(`${dir}/a.bin`, `${dir}/b.bin`);
          assert(!(await sftp.exists(`${dir}/a.bin`)), 'the old name is still there');
          const names: string[] = [];
          for await (const entry of sftp.readdir(dir)) names.push(entry.name);
          assert(names.join() === 'b.bin', `readdir gave ${names.join()}`);
          let back = 0;
          const parts: Uint8Array[] = [];
          for await (const chunk of sftp.createReadStream(`${dir}/b.bin`)) {
            parts.push(chunk);
            back += chunk.length;
          }
          const joined = new Uint8Array(back);
          let at = 0;
          for (const part of parts) {
            joined.set(part, at);
            at += part.length;
          }
          assert((await sha256(joined)) === (await sha256(data)), 'the file came back different');
          const remote = (await client.exec(`sha256sum ${dir}/b.bin`)).stdout.split(' ')[0];
          assert(remote === (await sha256(data)), 'the server holds a different file');
          await sftp.remove(`${dir}/b.bin`);
          await sftp.rmdir(dir);
          assert(!(await sftp.exists(dir)), 'the directory is still there');
          return `${data.length} bytes both ways`;
        } finally {
          await sftp.end();
        }
      },
    },
    {
      group: 'sftp',
      name: 'readdir pages through 600 entries',
      async run(client) {
        await client.exec(
          `rm -rf ${dir}-many && mkdir -p ${dir}-many && cd ${dir}-many && i=0; while [ $i -lt 600 ]; do : > f$i; i=$((i+1)); done`,
        );
        const sftp = await client.sftp();
        try {
          const entries = await sftp.list(`${dir}-many`);
          assert(entries.length === 600, `listed ${entries.length}`);
        } finally {
          await sftp.end();
          await client.exec(`rm -rf ${dir}-many`);
        }
      },
    },
    {
      group: 'sftp',
      name: 'a missing file is an SftpError, code 2',
      async run(client) {
        const sftp = await client.sftp();
        try {
          const code = await sftp.stat('/nonexistent/x').then(
            () => -1,
            (error: { code?: number }) => error.code ?? -2,
          );
          assert(code === 2, `stat of a missing file gave ${code}`);
        } finally {
          await sftp.end();
        }
      },
    },
    ...(openssh
      ? [
          {
            group: 'sftp',
            name: 'rename over an existing file with posix-rename',
            async run(client: SshClient) {
              const sftp = await client.sftp();
              try {
                await sftp.put(`/tmp/${server}-x`, text('x'));
                await sftp.put(`/tmp/${server}-y`, text('y'));
                await sftp.rename(`/tmp/${server}-x`, `/tmp/${server}-y`, { overwrite: true });
                const after = new TextDecoder().decode(await sftp.get(`/tmp/${server}-y`));
                assert(after === 'x', `the target holds ${after}`);
                await sftp.remove(`/tmp/${server}-y`);
              } finally {
                await sftp.end();
              }
            },
          },
        ]
      : []),
  ];
}
