/** The matrix's servers in Docker: images, containers, keys, and their fingerprints. */

import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { openNodeSocket } from './node-socket';

const ROOT = new URL('..', import.meta.url).pathname;
const KEYS = join(ROOT, '.cache/matrix/keys');
const NETWORK = 'undershell-matrix';

export interface Server {
  /** The base image, for the distributions built from openssh.Dockerfile. */
  base?: string;
  name: string;
  image: string;
  port: number;
  /** Host key files inside the container, by the algorithm that signs with each. */
  hostKeys: Record<string, string>;
  openssh: boolean;
}

export const SERVERS: Server[] = [
  {
    name: 'openssh-latest',
    image: 'undershell-openssh:latest',
    port: 2311,
    openssh: true,
    hostKeys: opensshKeys(),
  },
  {
    name: 'openssh-8.2',
    image: 'undershell-openssh:ubuntu20',
    port: 2312,
    openssh: true,
    hostKeys: opensshKeys(),
  },
  {
    name: 'dropbear',
    image: 'undershell-dropbear',
    port: 2313,
    openssh: false,
    hostKeys: {
      'ssh-ed25519': '/etc/dropbear/ed25519.pub',
      'ecdsa-sha2-nistp256': '/etc/dropbear/ecdsa.pub',
      'rsa-sha2-256': '/etc/dropbear/rsa.pub',
      'rsa-sha2-512': '/etc/dropbear/rsa.pub',
    },
  },
  // The distributions people run servers on, each with its own build of
  // OpenSSH: Debian old and current, and the RHEL family, CentOS 7's 7.4
  // without strict KEX and Rocky 9 under crypto-policies.
  ...(
    [
      ['openssh-debian12', 'debian:12', 2314],
      ['openssh-debian10', 'debian:10', 2315],
      ['openssh-centos7', 'centos:7', 2316],
      ['openssh-rocky9', 'rockylinux:9', 2317],
    ] as const
  ).map(([name, base, port]) => ({
    name,
    image: `undershell-openssh:${base.replace(':', '-')}`,
    base,
    port,
    openssh: true,
    hostKeys: opensshKeys(),
  })),
];

function opensshKeys(): Record<string, string> {
  return {
    'ssh-ed25519': '/etc/ssh/keys/ed25519.pub',
    'ecdsa-sha2-nistp256': '/etc/ssh/keys/ecdsa256.pub',
    'ecdsa-sha2-nistp384': '/etc/ssh/keys/ecdsa384.pub',
    'ecdsa-sha2-nistp521': '/etc/ssh/keys/ecdsa521.pub',
    'rsa-sha2-256': '/etc/ssh/keys/rsa.pub',
    'rsa-sha2-512': '/etc/ssh/keys/rsa.pub',
  };
}

/** Client keys as ssh-keygen writes them, in each format and cipher it offers. */
export const CLIENT_KEYS: { name: string; args: string[]; passphrase?: string }[] = [
  { name: 'ed25519', args: ['-t', 'ed25519'] },
  { name: 'ed25519+passphrase', args: ['-t', 'ed25519'], passphrase: 'matrix passphrase' },
  { name: 'ecdsa-256', args: ['-t', 'ecdsa', '-b', '256'] },
  { name: 'ecdsa-384', args: ['-t', 'ecdsa', '-b', '384'] },
  { name: 'ecdsa-521', args: ['-t', 'ecdsa', '-b', '521'] },
  { name: 'rsa-3072', args: ['-t', 'rsa', '-b', '3072'] },
  {
    name: 'rsa+passphrase(gcm)',
    args: ['-t', 'rsa', '-b', '2048', '-Z', 'aes256-gcm@openssh.com'],
    passphrase: 'gcm',
  },
  { name: 'rsa PEM (PKCS#1)', args: ['-t', 'rsa', '-b', '2048', '-m', 'PEM'] },
  { name: 'ecdsa-384 PKCS#8', args: ['-t', 'ecdsa', '-b', '384', '-m', 'PKCS8'] },
  { name: 'ecdsa-256 PEM (SEC1)', args: ['-t', 'ecdsa', '-b', '256', '-m', 'PEM'] },
];

const run = (command: string, args: string[]) =>
  execFileSync(command, args, { encoding: 'utf8' }).trim();
const docker = (...args: string[]) => run('docker', args);
export const fileOf = (name: string) => join(KEYS, name.replace(/[^a-z0-9]+/gi, '_'));

export function setUp(): void {
  rmSync(KEYS, { recursive: true, force: true });
  mkdirSync(KEYS, { recursive: true });
  for (const key of CLIENT_KEYS) {
    run('ssh-keygen', [
      '-q',
      ...key.args,
      '-N',
      key.passphrase ?? '',
      '-C',
      key.name,
      '-f',
      fileOf(key.name),
    ]);
  }
  for (const [image, file, extra] of [
    ['undershell-openssh:latest', 'openssh.Dockerfile', []],
    ['undershell-openssh:ubuntu20', 'openssh.Dockerfile', ['--build-arg', 'BASE=ubuntu:20.04']],
    ['undershell-dropbear', 'dropbear.Dockerfile', []],
    ...SERVERS.flatMap((server) =>
      server.base
        ? [[server.image, 'openssh.Dockerfile', ['--build-arg', `BASE=${server.base}`]] as const]
        : [],
    ),
  ] as const) {
    docker(
      'build',
      '-q',
      '-t',
      image,
      '-f',
      join(ROOT, 'docker', file),
      ...extra,
      join(ROOT, 'docker'),
    );
  }
  tearDown();
  docker('network', 'create', NETWORK);
  for (const server of SERVERS) {
    docker(
      'run',
      '-d',
      '--name',
      `us-${server.name}`,
      '--network',
      NETWORK,
      '--network-alias',
      server.name,
      '-p',
      `127.0.0.1:${server.port}:22`,
      '-v',
      `${KEYS}:/keys:ro`,
      server.image,
    );
  }
}

export function tearDown(): void {
  for (const server of SERVERS) {
    try {
      docker('rm', '-f', `us-${server.name}`);
    } catch {
      // Not running.
    }
  }
  try {
    docker('network', 'rm', NETWORK);
  } catch {
    // Not there.
  }
}

/** The fingerprint ssh-keygen gives the host key file, read out of the container. */
export function fingerprint(server: Server, file: string): string {
  const line = docker('exec', `us-${server.name}`, 'cat', file);
  return run('sh', ['-c', `echo '${line}' | ssh-keygen -lf -`]).split(' ')[1]!;
}

export async function waitFor(server: Server): Promise<void> {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const socket = await openNodeSocket('127.0.0.1', server.port);
      const reader = socket.readable.getReader();
      const { value } = await reader.read();
      await socket.close?.();
      if (value && new TextDecoder().decode(value).startsWith('SSH-')) return;
    } catch {
      // Not up yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`${server.name} did not start`);
}
