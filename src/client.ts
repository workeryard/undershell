/**
 * Authentication (RFC 4252) and running one command (RFC 4254) on top of the
 * transport: what an automation step actually does — connect, prove who you
 * are, run something, read what it printed, hang up.
 *
 * There is no pty and no shell here. Those exist for a person at a terminal;
 * a workflow wants one command and its exit status, and asking for a pty would
 * mix stderr into stdout and invite programs to print colour codes.
 */

import { subtle } from "./crypto";
import { Sftp } from "./sftp";
import { parseOpenSshPrivateKey } from "./openssh-key";
import { MSG, Transport, type ByteSocket, type HostKey, type Negotiated } from "./transport";
import { Reader, Writer } from "./wire";

const SERVICE = "ssh-connection";
const ED25519 = "ssh-ed25519";
const WINDOW_SIZE = 2 * 1024 * 1024;
const MAX_PACKET = 32 * 1024;

export type Authentication =
  { kind: "privateKey"; privateKey: string; passphrase?: string } | { kind: "password"; password: string };

export interface ConnectOptions {
  socket: ByteSocket;
  username: string;
  auth: Authentication;
  /**
   * The host key this credential expects, as `ssh-keygen -lf` prints it (the
   * "SHA256:" is optional). Refusing to guess is the point: to an unattended
   * run, an unknown host is a failure, not a prompt.
   */
  hostKeyFingerprint: string;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  /** Null when the server closed the channel without reporting one. */
  exitStatus: number | null;
  /** The signal that killed it, when it was killed rather than exited. */
  exitSignal?: string;
  /** True when output hit `maxOutputBytes` and the rest was dropped. */
  truncated: boolean;
}

export interface ExecOptions {
  /** Output is held in memory, so it is capped. Default 1 MiB per stream. */
  maxOutputBytes?: number;
}

function normalizeFingerprint(value: string): string {
  return value
    .trim()
    .replace(/^SHA256:/i, "")
    .replace(/=+$/, "");
}

export class SshClient {
  #nextChannel = 0;

  private constructor(readonly transport: Transport) {}

  get hostKey(): HostKey | null {
    return this.transport.hostKey;
  }

  get negotiated(): Negotiated | null {
    return this.transport.negotiated;
  }

  get serverVersion(): string {
    return this.transport.serverVersion;
  }

  static async connect(options: ConnectOptions): Promise<SshClient> {
    const transport = new Transport(options.socket);
    try {
      await transport.exchangeVersions();
      await transport.keyExchange();

      const expected = normalizeFingerprint(options.hostKeyFingerprint);
      if (!expected) throw new Error("no host key fingerprint was given, and this client will not trust on first use");
      const seen = transport.hostKey!.fingerprint;
      if (seen !== expected) {
        throw new Error(`the host key is SHA256:${seen}, not the SHA256:${expected} this credential expects`);
      }

      const client = new SshClient(transport);
      await client.#authenticate(options.username, options.auth);
      return client;
    } catch (error) {
      // A half-open connection is a leaked socket for the rest of the step.
      await transport.close();
      throw error;
    }
  }

  async #authenticate(username: string, auth: Authentication): Promise<void> {
    await this.transport.send(new Writer().byte(MSG.SERVICE_REQUEST).string("ssh-userauth").build());
    const accepted = await this.transport.receive();
    if (accepted[0] !== MSG.SERVICE_ACCEPT) throw new Error(`the server refused ssh-userauth (message ${accepted[0]})`);

    if (auth.kind === "password") {
      await this.transport.send(
        new Writer()
          .byte(MSG.USERAUTH_REQUEST)
          .string(username)
          .string(SERVICE)
          .string("password")
          .bool(false)
          .string(auth.password)
          .build(),
      );
    } else {
      const key = await parseOpenSshPrivateKey(auth.privateKey, auth.passphrase);
      // The signature covers the session id as well as the request, so a
      // captured request cannot be replayed onto another connection.
      const request = new Writer()
        .byte(MSG.USERAUTH_REQUEST)
        .string(username)
        .string(SERVICE)
        .string("publickey")
        .bool(true)
        .string(ED25519)
        .string(key.publicKeyBlob)
        .build();
      const signed = new Writer().string(this.transport.sessionId).raw(request).build();
      const signature = new Uint8Array(await subtle.sign({ name: "Ed25519" }, key.signingKey, signed));
      await this.transport.send(
        new Writer().raw(request).string(new Writer().string(ED25519).string(signature).build()).build(),
      );
    }

    for (;;) {
      const reply = await this.transport.receive();
      // The first byte of every payload is the message type.
      const type = reply[0];
      if (type === MSG.USERAUTH_BANNER) continue;
      if (type === MSG.USERAUTH_SUCCESS) return;
      if (type === MSG.USERAUTH_FAILURE) {
        const reader = new Reader(reply.subarray(1));
        const methods = reader.nameList().join(", ");
        const what = auth.kind === "password" ? "password" : "key";
        throw new Error(`the server rejected the ${what} for "${username}"; it will accept ${methods}`);
      }
      throw new Error(`unexpected message ${type} while authenticating`);
    }
  }

  /** Starts an SFTP session on its own channel. Close it with `end()`. */
  sftp(): Promise<Sftp> {
    return Sftp.open(this.transport);
  }

  /** Runs one command and reads it to the end. */
  async exec(command: string, options: ExecOptions = {}): Promise<CommandResult> {
    const limit = options.maxOutputBytes ?? 1024 * 1024;
    const channel = this.#nextChannel++;

    await this.transport.send(
      new Writer()
        .byte(MSG.CHANNEL_OPEN)
        .string("session")
        .uint32(channel)
        .uint32(WINDOW_SIZE)
        .uint32(MAX_PACKET)
        .build(),
    );

    let peerChannel = 0;
    for (;;) {
      const reply = await this.transport.receive();
      const type = reply[0];
      if (type === MSG.CHANNEL_OPEN_CONFIRMATION) {
        const reader = new Reader(reply.subarray(1));
        reader.uint32();
        peerChannel = reader.uint32();
        break;
      }
      if (type === MSG.CHANNEL_OPEN_FAILURE) {
        const reader = new Reader(reply.subarray(1));
        reader.uint32();
        throw new Error(`the server would not open a session (reason ${reader.uint32()}): ${reader.text()}`);
      }
      throw new Error(`unexpected message ${type} while opening a channel`);
    }

    await this.transport.send(
      new Writer().byte(MSG.CHANNEL_REQUEST).uint32(peerChannel).string("exec").bool(true).string(command).build(),
    );
    // Nothing is being sent on stdin, and a command that reads it should see
    // the end rather than wait for one.
    await this.transport.send(new Writer().byte(MSG.CHANNEL_EOF).uint32(peerChannel).build());

    const decoder = new TextDecoder();
    const result: CommandResult = { stdout: "", stderr: "", exitStatus: null, truncated: false };
    let window = WINDOW_SIZE;
    let closed = false;
    let weClosed = false;

    /** Both kinds of output spend the same window; forgetting one stalls the server. */
    const consume = async (bytes: Uint8Array, stream: "stdout" | "stderr") => {
      const room = limit - result[stream].length;
      if (room <= 0) result.truncated = true;
      else {
        const text = decoder.decode(bytes.subarray(0, Math.min(bytes.length, room)), { stream: true });
        result[stream] += text;
        if (bytes.length > room) result.truncated = true;
      }
      window -= bytes.length;
      if (window < WINDOW_SIZE / 2) {
        const top = WINDOW_SIZE - window;
        window = WINDOW_SIZE;
        await this.transport.send(new Writer().byte(MSG.CHANNEL_WINDOW_ADJUST).uint32(peerChannel).uint32(top).build());
      }
    };

    while (!closed) {
      const message = await this.transport.receive();
      const type = message[0];
      const reader = new Reader(message.subarray(1));
      switch (type) {
        case MSG.CHANNEL_DATA:
          reader.uint32();
          await consume(reader.string(), "stdout");
          break;
        case MSG.CHANNEL_EXTENDED_DATA:
          reader.uint32();
          reader.uint32(); // 1 is stderr; there is nothing else defined
          await consume(reader.string(), "stderr");
          break;
        case MSG.CHANNEL_REQUEST: {
          reader.uint32();
          const request = reader.text();
          const wantReply = reader.bool();
          if (request === "exit-status") result.exitStatus = reader.uint32();
          if (request === "exit-signal") result.exitSignal = reader.text();
          if (wantReply) await this.transport.send(new Writer().byte(MSG.CHANNEL_SUCCESS).uint32(peerChannel).build());
          break;
        }
        case MSG.CHANNEL_CLOSE:
          // A close is answered with a close, or the server waits for one.
          if (!weClosed) {
            weClosed = true;
            await this.transport.send(new Writer().byte(MSG.CHANNEL_CLOSE).uint32(peerChannel).build());
          }
          closed = true;
          break;
        case MSG.CHANNEL_EOF:
        case MSG.CHANNEL_SUCCESS:
        case MSG.CHANNEL_FAILURE:
        case MSG.CHANNEL_WINDOW_ADJUST:
          break;
        default:
          throw new Error(`unexpected message ${type} while reading the command's output`);
      }
    }

    return result;
  }

  close(): Promise<void> {
    return this.transport.close();
  }
}

/**
 * A server's host key, read the way `ssh-keyscan` reads it: connect, exchange
 * keys, take what it presented, hang up. No credential is involved — the host
 * key is what a server shows everyone before anyone proves anything.
 */
export async function readHostKey(socket: ByteSocket): Promise<{ hostKey: HostKey; serverVersion: string }> {
  const transport = new Transport(socket);
  try {
    await transport.exchangeVersions();
    await transport.keyExchange();
    return { hostKey: transport.hostKey!, serverVersion: transport.serverVersion };
  } finally {
    await transport.close();
  }
}
