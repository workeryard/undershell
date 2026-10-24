/**
 * An SSH client over any `ByteSocket`: connect, prove the server is the one
 * expected, prove who you are, then open what you need — commands, shells,
 * SFTP, tunnels — on that one connection.
 */

import { authenticate, type Authentication } from './auth';
import type { Channel } from './connection/channel';
import { Connection, type Keepalive } from './connection/connection';
import { prepare, type Session, type SessionOptions } from './connection/session';
import { Sftp } from './sftp/sftp';
import type { Algorithms } from './transport/algorithms';
import type { ByteSocket } from './transport/buffered';
import { Transport, type HostKey, type Negotiated } from './transport/transport';
import { Writer } from './wire';

/** Bastions a target may sit behind. Each is another handshake, and another host key to pin. */
export const MAX_JUMPS = 3;
const DEFAULT_TIMEOUT = 30_000;

export interface HostKeyCheck {
  /**
   * The host key this server should have, as `ssh-keygen -lf` prints it
   * (the "SHA256:" is optional), or several during a key rotation.
   */
  hostKeyFingerprint?: string | readonly string[];
  /**
   * For callers who keep their own known_hosts: return true to accept the
   * key. With a fingerprint as well, both have to agree.
   */
  verifyHostKey?(key: HostKey): boolean | Promise<boolean>;
}

export interface ConnectOptions extends HostKeyCheck {
  socket: ByteSocket;
  username: string;
  /** One method, or several tried in order until the server is satisfied. */
  auth: Authentication | readonly Authentication[];
  /** Narrower or reordered algorithm lists; see the readme's table. */
  algorithms?: Algorithms;
  /** What the server shows before login, such as /etc/issue.net. */
  onBanner?: (message: string) => void;
  /** For the handshake and authentication together. Default 30 s. */
  timeoutMs?: number;
  /** Re-key after this many bytes either way. Default 1 GiB, as RFC 4344 advises. */
  rekeyAfterBytes?: number;
  /**
   * Ask the server every so often whether it is still there, as ssh's
   * ServerAliveInterval does, and give the connection up after `maxMissed`
   * unanswered asks. Off unless given.
   */
  keepalive?: Keepalive;
}

export interface JumpOptions extends Omit<ConnectOptions, 'socket'> {
  host: string;
  port?: number;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  /** Null when the server closed the channel without reporting one. */
  exitStatus: number | null;
  /** The signal that killed it, when it was killed rather than exited. */
  exitSignal?: string;
  /** True when output passed `maxOutputBytes` and the rest was dropped. */
  truncated: boolean;
}

export interface ExecOptions extends SessionOptions {
  /** Output is held in memory, so it is capped. Default 1 MiB per stream. */
  maxOutputBytes?: number;
  /** Written to the command's stdin, which is then closed. Without it stdin is closed at once. */
  stdin?: string | Uint8Array;
  /** Aborting sends the command SIGKILL and closes its channel. */
  signal?: AbortSignal;
}

function normalizeFingerprint(value: string): string {
  return value
    .trim()
    .replace(/^SHA256:/i, '')
    .replace(/=+$/, '');
}

/** The host key policy for one server: pinned, checked by the caller, or both. Never neither. */
function hostKeyChecker(check: HostKeyCheck): (key: HostKey) => Promise<void> {
  const pinned = [check.hostKeyFingerprint ?? []].flat().map(normalizeFingerprint).filter(Boolean);
  if (pinned.length === 0 && !check.verifyHostKey) {
    throw new Error(
      'no host key fingerprint or verifyHostKey was given, and this client will not trust on first use',
    );
  }
  return async (key) => {
    if (pinned.length && !pinned.includes(key.fingerprint)) {
      const expected = pinned.map((print) => `SHA256:${print}`).join(' or ');
      throw new Error(
        `the ${key.algorithm} host key is SHA256:${key.fingerprint}, not the ${expected} expected`,
      );
    }
    if (check.verifyHostKey && !(await check.verifyHostKey(key))) {
      throw new Error(
        `the ${key.algorithm} host key SHA256:${key.fingerprint} was refused by verifyHostKey`,
      );
    }
  };
}

async function withDeadline<T>(
  work: Promise<T>,
  ms: number,
  what: string,
  onTimeout: () => unknown,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      void onTimeout();
      reject(new Error(`${what} took longer than ${ms} ms`));
    }, ms);
  });
  try {
    return await Promise.race([work, deadline]);
  } finally {
    // A Worker's clearTimeout takes no undefined.
    if (timer !== undefined) clearTimeout(timer);
  }
}

export class SshClient {
  #parent: SshClient | null = null;

  private constructor(
    private readonly connection: Connection,
    private readonly depth: number,
  ) {}

  get transport(): Transport {
    return this.connection.transport;
  }

  get hostKey(): HostKey {
    return this.transport.hostKey!;
  }

  get negotiated(): Negotiated {
    return this.transport.negotiated!;
  }

  get serverVersion(): string {
    return this.transport.serverVersion;
  }

  /** Settles when the connection ends, whether it was closed or it failed. */
  get ended(): Promise<void> {
    return this.connection.ended;
  }

  static connect(options: ConnectOptions): Promise<SshClient> {
    return SshClient.#connect(options, 0);
  }

  static async #connect(options: ConnectOptions, depth: number): Promise<SshClient> {
    let checkHostKey: (key: HostKey) => Promise<void>;
    try {
      checkHostKey = hostKeyChecker(options);
    } catch (error) {
      await options.socket.close?.().catch(() => {});
      throw error;
    }
    const transport = new Transport(options.socket, {
      checkHostKey,
      ...(options.algorithms && { algorithms: options.algorithms }),
      ...(options.rekeyAfterBytes && { rekeyAfterBytes: options.rekeyAfterBytes }),
    });
    try {
      const login = async () => {
        await transport.handshake();
        await authenticate(transport, options.username, [options.auth].flat(), options.onBanner);
      };
      await withDeadline(login(), options.timeoutMs ?? DEFAULT_TIMEOUT, 'connecting', () =>
        transport.close(),
      );
      return new SshClient(new Connection(transport, options.keepalive), depth);
    } catch (error) {
      // A half-open connection is a leaked socket for the rest of the request.
      await transport.close();
      throw error;
    }
  }

  /** Opens a session channel and starts `start` on it. */
  async #session(options: SessionOptions, start: string, data?: Uint8Array): Promise<Session> {
    return prepare(await this.connection.open('session'), options, start, data);
  }

  /** Starts a command and hands back its streams, for output too large to hold or input to feed. */
  spawn(command: string, options: SessionOptions = {}): Promise<Session> {
    return this.#session(options, 'exec', new Writer().string(command).build());
  }

  /** An interactive shell, with a pty unless `pty: false` is asked for. */
  shell(options: SessionOptions = {}): Promise<Session> {
    return this.#session({ ...options, pty: options.pty ?? true }, 'shell');
  }

  /** A subsystem by name, such as `sftp` or `netconf`. */
  subsystem(name: string, options: SessionOptions = {}): Promise<Session> {
    return this.#session(options, 'subsystem', new Writer().string(name).build());
  }

  /** Runs one command and reads it to the end. */
  async exec(command: string, options: ExecOptions = {}): Promise<CommandResult> {
    const limit = options.maxOutputBytes ?? 1024 * 1024;
    options.signal?.throwIfAborted();
    const session = await this.spawn(command, options);
    const abort = () =>
      void session
        .signal('KILL')
        .finally(() => session.close())
        .catch(() => {});
    options.signal?.addEventListener('abort', abort, { once: true });

    const result: CommandResult = { stdout: '', stderr: '', exitStatus: null, truncated: false };
    /** Both streams are read to the end: past the cap they are drained, or the window would stall. */
    const collect = async (stream: ReadableStream<Uint8Array>, into: 'stdout' | 'stderr') => {
      const decoder = new TextDecoder();
      let kept = 0;
      for await (const chunk of stream) {
        const room = limit - kept;
        if (chunk.length > room) result.truncated = true;
        if (room > 0) {
          result[into] += decoder.decode(chunk.subarray(0, room), { stream: true });
          kept += Math.min(room, chunk.length);
        }
      }
      result[into] += decoder.decode();
    };

    try {
      const writer = session.stdin.getWriter();
      const feeding = (async () => {
        if (options.stdin !== undefined) {
          const input =
            typeof options.stdin === 'string'
              ? new TextEncoder().encode(options.stdin)
              : options.stdin;
          await writer.write(input);
        }
        // A command that reads stdin should see the end rather than wait for one.
        await writer.close();
      })().catch(() => {});
      await Promise.all([
        collect(session.stdout, 'stdout'),
        collect(session.stderr, 'stderr'),
        feeding,
      ]);
      const exit = await session.exit;
      options.signal?.throwIfAborted();
      result.exitStatus = exit.code;
      if (exit.signal) result.exitSignal = exit.signal;
      await session.close();
      return result;
    } finally {
      options.signal?.removeEventListener('abort', abort);
    }
  }

  /**
   * A TCP connection from the server to `host:port` (RFC 4254 §7.2), as a
   * `ByteSocket`: for a port forward, or to carry the next SSH connection.
   */
  forward(host: string, port: number, origin = { host: '127.0.0.1', port: 0 }): Promise<Channel> {
    return this.connection.open(
      'direct-tcpip',
      new Writer().string(host).uint32(port).string(origin.host).uint32(origin.port).build(),
    );
  }

  /**
   * Connects to a host this server can reach, through it. The new client is
   * checked and authenticated on its own terms — its own host key, its own
   * credentials — and closing it closes the hop it rides on as well.
   */
  async jump(options: JumpOptions): Promise<SshClient> {
    if (this.depth >= MAX_JUMPS)
      throw new Error(`a target may sit behind at most ${MAX_JUMPS} jump hosts`);
    const { host, port = 22, ...rest } = options;
    const tunnel = await this.forward(host, port);
    const client = await SshClient.#connect({ ...rest, socket: tunnel }, this.depth + 1);
    client.#parent = this;
    return client;
  }

  /** Starts an SFTP session on its own channel. Close it with `end()`. */
  async sftp(): Promise<Sftp> {
    return Sftp.start(await this.subsystem('sftp'));
  }

  /** Closes this connection, and any jump hosts it was reached through. */
  async close(): Promise<void> {
    await this.connection.close();
    await this.#parent?.close();
  }
}

/**
 * A server's host key, read the way `ssh-keyscan` reads it: connect, exchange
 * keys, take what it presented, hang up. No credential is involved — the host
 * key is what a server shows everyone before anyone proves anything.
 */
export async function readHostKey(
  socket: ByteSocket,
  options: { algorithms?: Algorithms } = {},
): Promise<{ hostKey: HostKey; serverVersion: string; negotiated: Negotiated }> {
  const transport = new Transport(
    socket,
    options.algorithms ? { algorithms: options.algorithms } : {},
  );
  try {
    await transport.handshake();
    return {
      hostKey: transport.hostKey!,
      serverVersion: transport.serverVersion,
      negotiated: transport.negotiated!,
    };
  } finally {
    await transport.close();
  }
}
