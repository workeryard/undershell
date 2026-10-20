/**
 * A session channel (RFC 4254 §6) running a command, a shell or a
 * subsystem, with the requests that shape it: a pseudo-terminal, its size,
 * environment variables, and signals.
 */

import { Writer } from '../wire';
import type { Channel, ExitStatus } from './channel';

export interface PtyOptions {
  /** The TERM the remote programs see. Default `xterm-256color`. */
  term?: string;
  /** Characters. Default 80 × 24. */
  cols?: number;
  rows?: number;
  /** Pixels, where a terminal knows them; 0 otherwise. */
  width?: number;
  height?: number;
  /** Terminal modes by RFC 4254 §8 opcode, such as `{ 53: 0 }` to turn ECHO off. */
  modes?: Record<number, number>;
}

export interface SessionOptions {
  /** A pseudo-terminal: what a person at a terminal needs, and what merges stderr into stdout. */
  pty?: PtyOptions | boolean;
  /** Variables to set, which sshd accepts only for names its AcceptEnv lists. */
  env?: Record<string, string>;
}

export function ptyRequest(options: PtyOptions): Uint8Array {
  const modes = new Writer();
  for (const [opcode, value] of Object.entries(options.modes ?? {}))
    modes.byte(Number(opcode)).uint32(value);
  modes.byte(0); // TTY_OP_END
  return new Writer()
    .string(options.term ?? 'xterm-256color')
    .uint32(options.cols ?? 80)
    .uint32(options.rows ?? 24)
    .uint32(options.width ?? 0)
    .uint32(options.height ?? 0)
    .string(modes.build())
    .build();
}

export class Session {
  constructor(readonly channel: Channel) {}

  /** What the remote side writes; with a pty, stderr arrives here too. */
  get stdout(): ReadableStream<Uint8Array> {
    return this.channel.readable;
  }

  /**
   * What it writes to stderr. It shares the window with stdout: read it, or
   * cancel it, or a command that writes a lot of it will stall.
   */
  get stderr(): ReadableStream<Uint8Array> {
    return this.channel.stderr;
  }

  /** What it reads. Closing this sends EOF, which is how a command reading stdin finishes. */
  get stdin(): WritableStream<Uint8Array> {
    return this.channel.writable;
  }

  /** How it ended, once the channel has closed. */
  get exit(): Promise<ExitStatus> {
    return this.channel.closed;
  }

  /** Tells the remote terminal its new size (RFC 4254 §6.7). */
  async resize(cols: number, rows: number, width = 0, height = 0): Promise<void> {
    await this.channel.request(
      'window-change',
      false,
      new Writer().uint32(cols).uint32(rows).uint32(width).uint32(height).build(),
    );
  }

  /** Sends a signal by name without "SIG", such as `INT` or `TERM`. OpenSSH honours it since 7.9. */
  async signal(name: string): Promise<void> {
    await this.channel.request(
      'signal',
      false,
      new Writer().string(name.replace(/^SIG/, '')).build(),
    );
  }

  close(): Promise<void> {
    return this.channel.close();
  }
}

/** Sets up a session channel for `start`: env, then the pty, then the start request itself. */
export async function prepare(
  channel: Channel,
  options: SessionOptions,
  start: string,
  data?: Uint8Array,
): Promise<Session> {
  try {
    for (const [name, value] of Object.entries(options.env ?? {})) {
      // No reply asked: a refused variable should not fail the command.
      await channel.request('env', false, new Writer().string(name).string(value).build());
    }
    if (options.pty) {
      const pty = options.pty === true ? {} : options.pty;
      if (!(await channel.request('pty-req', true, ptyRequest(pty))))
        throw new Error('the server refused a pseudo-terminal');
    }
    if (!(await channel.request(start, true, data))) {
      throw new Error(
        start === 'subsystem'
          ? 'the server refused the subsystem'
          : `the server refused the ${start} request`,
      );
    }
    return new Session(channel);
  } catch (error) {
    await channel.close().catch(() => {});
    throw error;
  }
}
