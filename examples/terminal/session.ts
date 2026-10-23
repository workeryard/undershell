/**
 * One terminal session: a Durable Object holding a browser's WebSocket on
 * one side and an SSH shell on the other, for as long as both stay open.
 *
 * A Durable Object rather than the Worker itself because of CPU: a Worker's
 * whole WebSocket is one request with one CPU budget, while a Durable
 * Object's budget starts again with every message that arrives, and in a
 * terminal every keystroke is one.
 *
 * The wire, browser to here: the first message is JSON with the token and
 * the terminal's size; after it, binary messages are keystrokes and text
 * messages are JSON resizes. Here to browser: binary is the shell's output,
 * text is JSON status ({ status } or { error }).
 */

import { DurableObject } from 'cloudflare:workers';
import { connect, type SshClient, type Session } from '../../src/workers/index';

export interface Env {
  TERMINAL: DurableObjectNamespace<TerminalSession>;
  /** Shared with whoever may open a terminal; compared in constant time. */
  TERMINAL_TOKEN: string;
  /** The one server this terminal reaches. Never chosen by the browser. */
  SSH_HOST?: string;
  SSH_PORT?: string;
  /** Or a Cloudflare Tunnel hostname, reached as `cloudflared access ssh` would. */
  SSH_TUNNEL?: string;
  SSH_USER: string;
  SSH_KEY: string;
  /** The host key fingerprint, as `ssh-keygen -lf` prints it. */
  SSH_HOST_KEY: string;
  /** Minutes without a keystroke before the session is closed. Default 15. */
  IDLE_MINUTES?: string;
}

const encoder = new TextEncoder();

async function sameToken(given: string, expected: string): Promise<boolean> {
  if (!expected) return false;
  // Hashed first, so the comparison is of equal lengths whatever was sent.
  const [a, b] = await Promise.all(
    [given, expected].map(
      async (text) => new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(text))),
    ),
  );
  const subtle = crypto.subtle as SubtleCrypto & {
    timingSafeEqual?(a: ArrayBufferView, b: ArrayBufferView): boolean;
  };
  return subtle.timingSafeEqual
    ? subtle.timingSafeEqual(a, b)
    : a.every((byte, index) => byte === b[index]);
}

export class TerminalSession extends DurableObject<Env> {
  #client: SshClient | null = null;
  #shell: Session | null = null;
  #stdin: WritableStreamDefaultWriter<Uint8Array> | null = null;
  #idle: ReturnType<typeof setTimeout> | undefined;

  override fetch(request: Request): Response {
    if (request.headers.get('upgrade') !== 'websocket')
      return new Response('expected a WebSocket', { status: 426 });
    const { 0: browser, 1: socket } = new WebSocketPair();
    // Accepted, not hibernated: the SSH connection is open I/O, which keeps
    // this object in memory anyway.
    socket.accept();
    // On a recent compatibility date binary messages arrive as Blobs, and a
    // Uint8Array made from a Blob is empty: every keystroke would be lost.
    socket.binaryType = 'arraybuffer';
    this.#serve(socket);
    return new Response(null, { status: 101, webSocket: browser });
  }

  #serve(socket: WebSocket): void {
    const status = (body: Record<string, string>) => {
      try {
        socket.send(JSON.stringify(body));
      } catch {
        // The browser has gone.
      }
    };
    const end = async (reason?: string) => {
      if (this.#idle !== undefined) clearTimeout(this.#idle);
      if (reason) status({ error: reason });
      await this.#client?.close().catch(() => {});
      this.#client = null;
      try {
        socket.close(1000, 'bye');
      } catch {
        // Already closed.
      }
    };
    const idleMinutes = Number(this.env.IDLE_MINUTES ?? 15);
    const touch = () => {
      if (this.#idle !== undefined) clearTimeout(this.#idle);
      this.#idle = setTimeout(
        () => void end(`closed after ${idleMinutes} minutes without input`),
        idleMinutes * 60_000,
      );
    };

    let started = false;
    socket.addEventListener('message', (event) => {
      touch();
      if (!started) {
        started = true;
        void this.#start(socket, String(event.data), status).catch((error: unknown) =>
          end(error instanceof Error ? error.message : String(error)),
        );
        return;
      }
      if (typeof event.data === 'string') {
        const { resize } = JSON.parse(event.data) as { resize?: [number, number] };
        if (resize) void this.#shell?.resize(resize[0], resize[1]).catch(() => {});
      } else void this.#stdin?.write(new Uint8Array(event.data as ArrayBuffer)).catch(() => {});
    });
    socket.addEventListener('close', () => void end());
    socket.addEventListener('error', () => void end());
  }

  async #start(
    socket: WebSocket,
    hello: string,
    status: (body: Record<string, string>) => void,
  ): Promise<void> {
    const { token, cols, rows } = JSON.parse(hello) as {
      token?: string;
      cols?: number;
      rows?: number;
    };
    if (!(await sameToken(token ?? '', this.env.TERMINAL_TOKEN)))
      throw new Error('the token is not right');

    const env = this.env;
    status({ status: `connecting to ${env.SSH_TUNNEL ?? env.SSH_HOST}` });
    this.#client = await connect({
      ...(env.SSH_TUNNEL
        ? { tunnel: { hostname: env.SSH_TUNNEL } }
        : { host: env.SSH_HOST!, port: Number(env.SSH_PORT ?? 22) }),
      username: env.SSH_USER,
      auth: { kind: 'privateKey', privateKey: env.SSH_KEY },
      hostKeyFingerprint: env.SSH_HOST_KEY,
    });
    this.#shell = await this.#client.shell({
      pty: {
        term: 'xterm-256color',
        cols: clamp(cols, 20, 500, 80),
        rows: clamp(rows, 5, 200, 24),
      },
    });
    this.#stdin = this.#shell.stdin.getWriter();
    status({ status: 'connected' });

    const send = (chunk: Uint8Array) => socket.send(chunk);
    await Promise.all([
      this.#shell.stdout.pipeTo(new WritableStream({ write: send })),
      // With a pty stderr is merged into stdout; read it anyway so it never stalls the window.
      this.#shell.stderr.pipeTo(new WritableStream({ write: send })),
    ]).catch(() => {});
    const exit = await this.#shell.exit;
    status({ status: `the shell exited${exit.code === null ? '' : ` with status ${exit.code}`}` });
    await this.#client.close().catch(() => {});
    socket.close(1000, 'exited');
  }
}

function clamp(value: unknown, low: number, high: number, fallback: number): number {
  const number = Math.floor(Number(value));
  return Number.isFinite(number) ? Math.min(high, Math.max(low, number)) : fallback;
}
