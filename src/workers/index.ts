/**
 * The Cloudflare Workers adapter: the one place that names the runtime.
 *
 * Everything else under `src/` takes a `ByteSocket` and knows nothing of
 * where it came from. Here the two ways a Worker reaches a server are filled
 * in: a TCP socket from `cloudflare:sockets`, and a WebSocket to a server
 * published through Cloudflare Tunnel.
 */

import { connect as tcp } from 'cloudflare:sockets';
import { webSocketStream, type WebSocketLike } from '../carriers/websocket';
import { SshClient, type ConnectOptions, type JumpOptions } from '../client';
import type { ByteSocket } from '../transport/buffered';

/** Opens a TCP connection, settled once it is up. */
export async function openSocket(hostname: string, port = 22): Promise<ByteSocket> {
  const socket = tcp({ hostname, port });
  try {
    await socket.opened;
  } catch (error) {
    const said = error instanceof Error ? error.message : String(error);
    // Production refuses Cloudflare's own address ranges with this, and only
    // the "HTTP-based service" part tells it apart from a dead address.
    if (/HTTP-based service/i.test(said)) {
      throw new Error(
        `could not connect to ${hostname}:${port}: a Worker may not open TCP connections to Cloudflare's ` +
          'own IP ranges. A server behind Cloudflare is reached through Cloudflare Tunnel instead (`tunnel`).',
        { cause: error },
      );
    }
    throw new Error(`could not connect to ${hostname}:${port}: ${said}`, { cause: error });
  }
  return { readable: socket.readable, writable: socket.writable, close: () => socket.close() };
}

export interface TunnelOptions {
  /** The hostname the tunnel publishes the SSH service at, as `cloudflared access ssh --hostname` takes it. */
  hostname: string;
  /** A Zero Trust service token, sent as CF-Access-Client-Id and CF-Access-Client-Secret. */
  serviceToken?: { clientId: string; clientSecret: string };
  /** An Access JWT, as `cloudflared access login` keeps it, sent as Cf-Access-Token. */
  accessToken?: string;
  /** For a tunnel in bastion mode: the host:port behind it, sent as Cf-Access-Jump-Destination. */
  destination?: string;
  /** Anything else to send with the upgrade. */
  headers?: Record<string, string>;
}

/**
 * Opens the WebSocket that `cloudflared access ssh` would, to a server
 * behind Cloudflare Tunnel. Over `fetch()`, so it also reaches hostnames a
 * socket from `cloudflare:sockets` may not.
 */
export async function openTunnel(options: TunnelOptions): Promise<ByteSocket> {
  const headers = new Headers(options.headers);
  headers.set('Upgrade', 'websocket');
  if (options.serviceToken) {
    headers.set('CF-Access-Client-Id', options.serviceToken.clientId);
    headers.set('CF-Access-Client-Secret', options.serviceToken.clientSecret);
  }
  if (options.accessToken) headers.set('Cf-Access-Token', options.accessToken);
  if (options.destination) headers.set('Cf-Access-Jump-Destination', options.destination);

  const response = await fetch(`https://${options.hostname}/`, { headers });
  const socket = (
    response as Response & { webSocket?: (WebSocketLike & { accept(): void }) | null }
  ).webSocket;
  if (response.status !== 101 || !socket) {
    const hint =
      response.status === 302 || response.status === 403
        ? '; Cloudflare Access wants a service token or an access token'
        : '';
    await response.body?.cancel();
    throw new Error(
      `the tunnel at ${options.hostname} answered ${response.status} instead of a WebSocket${hint}`,
    );
  }
  socket.accept();
  return webSocketStream(socket);
}

export interface WorkersConnectOptions extends Omit<ConnectOptions, 'socket'> {
  /** Where to connect over TCP. Not needed with `tunnel`. */
  host?: string;
  port?: number;
  /** Reach the first hop through Cloudflare Tunnel instead of TCP. */
  tunnel?: TunnelOptions;
  /**
   * Bastions to go through, nearest first, each with its own host key and
   * credentials. The target's options are the top-level ones.
   */
  jump?: readonly JumpOptions[];
}

/** Connects, through any jump hosts given, and authenticates at every hop. */
export async function connect(options: WorkersConnectOptions): Promise<SshClient> {
  const { host, port = 22, tunnel, jump = [], ...target } = options;
  const final: JumpOptions = { ...target, host: host ?? '', port };
  const [first = final, ...rest] = [...jump, final];
  if (!tunnel && !first.host) throw new Error('connect needs a host, or a tunnel');
  const socket = tunnel ? await openTunnel(tunnel) : await openSocket(first.host, first.port ?? 22);
  let client = await SshClient.connect({ ...first, socket });
  try {
    for (const hop of rest) client = await client.jump(hop);
  } catch (error) {
    await client.close();
    throw error;
  }
  return client;
}

export * from '../index';
