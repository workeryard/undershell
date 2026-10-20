/**
 * The SSH transport layer (RFC 4253): the version exchange, the binary packet
 * protocol, key exchange and re-exchange, and the host key's proof.
 *
 * One connection is driven by one reader — first the handshake, then
 * authentication, then the connection's pump — so a key exchange the server
 * starts is run to completion inside `receive()` before the caller sees the
 * next message. Sends come from anywhere, and are queued: two overlapping
 * sends would each read the same GCM invocation counter while the other
 * awaited WebCrypto, and a nonce used twice hands an attacker the keystream.
 */

import { fingerprintOf, openSshPublicKey, verifySignature } from '../keys/public-key';
import { equalBytes, Reader, Writer, type Bytes } from '../wire';
import {
  preference,
  type Algorithms,
  type CipherName,
  type KexName,
  type MacName,
  type Preference,
} from './algorithms';
import { Buffered, type ByteSocket } from './buffered';
import { PLAIN, type Opener, type Sealer } from './cipher';
import { deriveCiphers, exchangeHash, kexinit, negotiate } from './exchange';
import { agreement } from './kex';
import { disconnected, MSG, serverSignatureAlgorithms, toError } from './messages';

export const CLIENT_VERSION = 'SSH-2.0-undershell_0.1';

/** RFC 4253 §4.2 allows a server 8 KiB of banner before its version line. */
const MAX_BANNER = 8 * 1024;
/** RFC 4344 §3: re-key well before a block cipher's counter or nonce wears thin. */
const REKEY_BYTES = 2 ** 30;
const REKEY_PACKETS = 2 ** 28;

export interface HostKey {
  /** The key's type, as its blob names it: ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa. */
  algorithm: string;
  /** The signature algorithm the server proved it with, such as rsa-sha2-512. */
  signatureAlgorithm: string;
  /** The blob the server sent, which is what the fingerprint is taken over. */
  blob: Bytes;
  /** Base64 SHA-256, as `ssh-keygen -lf` prints it, without the "SHA256:". */
  fingerprint: string;
  /** `type base64`, as a known_hosts line holds it after the host names. */
  publicKey: string;
}

export interface Negotiated {
  kex: KexName;
  hostKey: string;
  cipher: CipherName;
  /** Null for an AES-GCM cipher, which authenticates packets itself. */
  mac: MacName | null;
  strictKex: boolean;
}

export interface TransportOptions {
  algorithms?: Algorithms;
  /**
   * Called once, on the first exchange, with the key the server has just
   * proved it holds. Throwing refuses the connection before anything is
   * sent under its keys. A re-exchange must present the same key.
   */
  checkHostKey?(key: HostKey): Promise<void>;
  /** Re-key after this many bytes either way. Default 1 GiB; lower only to test re-keying. */
  rekeyAfterBytes?: number;
}

interface Exchange {
  ours: Bytes;
  done: Promise<void>;
  settle(error?: unknown): void;
}

export class Transport {
  #out: Sealer = PLAIN;
  #in: Opener = PLAIN;
  #sequenceIn = 0;
  #sequenceOut = 0;
  #bytesIn = 0;
  #bytesOut = 0;
  #packetsIn = 0;
  #packetsOut = 0;
  #strictKex = false;
  #sending: Promise<void> = Promise.resolve();
  #exchange: Exchange | null = null;
  #failed: unknown = null;
  #closing: Promise<void> | null = null;
  readonly #reader: Buffered;
  readonly #writer: WritableStreamDefaultWriter<Uint8Array>;
  readonly #socket: ByteSocket;
  readonly #preference: Preference;
  readonly #options: TransportOptions;
  readonly #rekeyBytes: number;

  sessionId: Bytes = new Uint8Array(0);
  hostKey: HostKey | null = null;
  serverVersion = '';
  negotiated: Negotiated | null = null;
  /** Key exchanges completed, the first included: more than one means it has re-keyed. */
  keyExchanges = 0;
  /** What the server said it verifies (RFC 8308 server-sig-algs), or null if it did not say. */
  serverSignatureAlgorithms: string[] | null = null;

  constructor(socket: ByteSocket, options: TransportOptions = {}) {
    this.#socket = socket;
    this.#options = options;
    this.#preference = preference(options.algorithms);
    this.#rekeyBytes = options.rekeyAfterBytes ?? REKEY_BYTES;
    this.#reader = new Buffered(socket.readable);
    this.#writer = socket.writable.getWriter();
  }

  /** The version exchange and the first key exchange. */
  async handshake(): Promise<void> {
    await this.exchangeVersions();
    this.#begin();
    for (;;) {
      const payload = await this.#readPacket();
      const type = payload[0];
      if (type === MSG.KEXINIT) return this.#run(payload);
      if (type === MSG.DISCONNECT) throw disconnected(payload);
      // Strict KEX forbids anything before KEXINIT, which #run checks by
      // the sequence number; a server without it may send these.
      if (type === MSG.IGNORE || type === MSG.DEBUG) continue;
      throw new Error(`expected KEXINIT, got message ${type}`);
    }
  }

  /** Both sides announce themselves in plain text before anything else. */
  async exchangeVersions(): Promise<string> {
    await this.#writer.write(new TextEncoder().encode(`${CLIENT_VERSION}\r\n`));
    let spent = 0;
    for (;;) {
      const line = await this.#reader.line(MAX_BANNER);
      // Anything before the version line is a banner the server chose to print.
      if (line.startsWith('SSH-')) {
        if (!line.startsWith('SSH-2.0-') && !line.startsWith('SSH-1.99-')) {
          throw new Error(`the server speaks ${line}, and this client only speaks 2.0`);
        }
        this.serverVersion = line;
        return line;
      }
      spent += line.length + 1;
      if (spent > MAX_BANNER)
        throw new Error('the server sent more banner than RFC 4253 allows before its version');
    }
  }

  /** Sends a payload, after any key exchange under way has finished. */
  async send(payload: Bytes): Promise<void> {
    while (this.#exchange) await this.#exchange.done;
    return this.#enqueue(payload);
  }

  #enqueue(payload: Bytes, after?: () => void): Promise<void> {
    const next = this.#sending.then(async () => {
      if (this.#failed) throw toError(this.#failed);
      const packet = await this.#out.seal(payload, this.#sequenceOut);
      this.#sequenceOut = (this.#sequenceOut + 1) >>> 0;
      this.#bytesOut += packet.length;
      this.#packetsOut++;
      await this.#writer.write(packet);
      after?.();
      if (this.#bytesOut > this.#rekeyBytes || this.#packetsOut > REKEY_PACKETS) this.#begin();
    });
    // Keep the chain alive after a failure so later sends report their own error.
    this.#sending = next.catch(() => {});
    return next;
  }

  async #readPacket(): Promise<Bytes> {
    const payload = await this.#in.open(this.#reader, this.#sequenceIn);
    this.#sequenceIn = (this.#sequenceIn + 1) >>> 0;
    this.#bytesIn += payload.length;
    this.#packetsIn++;
    if (payload.length === 0) throw new Error('an empty packet');
    return payload;
  }

  /**
   * The next message a caller needs to act on. Housekeeping is dealt with
   * here: debug chatter dropped, the server's global requests declined, its
   * extensions noted, and a key exchange run to completion.
   */
  async receive(): Promise<Bytes> {
    for (;;) {
      if (!this.#exchange && (this.#bytesIn > this.#rekeyBytes || this.#packetsIn > REKEY_PACKETS))
        this.#begin();
      const payload = await this.#readPacket();
      const type = payload[0];
      if (type === MSG.DISCONNECT) throw disconnected(payload);
      if (type === MSG.IGNORE || type === MSG.DEBUG || type === MSG.UNIMPLEMENTED) continue;
      if (type === MSG.EXT_INFO) {
        this.serverSignatureAlgorithms =
          serverSignatureAlgorithms(payload) ?? this.serverSignatureAlgorithms;
        continue;
      }
      if (type === MSG.GLOBAL_REQUEST) {
        const reader = new Reader(payload.subarray(1));
        reader.skipString();
        // Leaving want_reply unanswered stalls servers that ask, such as
        // OpenSSH's keepalives. Not awaited: a send may wait on a key
        // exchange that only this reader can finish.
        if (reader.bool()) void this.send(new Uint8Array([MSG.REQUEST_FAILURE])).catch(() => {});
        continue;
      }
      if (type === MSG.KEXINIT) {
        await this.#run(payload);
        continue;
      }
      return payload;
    }
  }

  /** Sends our KEXINIT, once, and holds every other send until the exchange is over. */
  #begin(): void {
    if (this.#exchange) return;
    let settle!: (error?: unknown) => void;
    const done = new Promise<void>((resolve, reject) => {
      settle = (error) => (error === undefined ? resolve() : reject(toError(error)));
    });
    done.catch(() => {});
    const ours = kexinit(this.#preference, this.sessionId.length === 0);
    this.#exchange = { ours, done, settle };
    void this.#enqueue(ours).catch(() => {});
  }

  /** A key exchange message, where a strict first exchange allows nothing else. */
  async #expect(type: number, strict: boolean): Promise<Bytes> {
    for (;;) {
      const payload = await this.#readPacket();
      if (payload[0] === type) return payload;
      if (payload[0] === MSG.DISCONNECT) throw disconnected(payload);
      const noise =
        payload[0] === MSG.IGNORE || payload[0] === MSG.DEBUG || payload[0] === MSG.UNIMPLEMENTED;
      if (noise && !strict) continue;
      throw new Error(
        `message ${payload[0]} arrived during the key exchange, where ${type} was due`,
      );
    }
  }

  /** The rest of a key exchange, from the server's KEXINIT on. */
  async #run(theirs: Bytes): Promise<void> {
    this.#begin();
    const exchange = this.#exchange!;
    try {
      await this.#negotiateAndSwitch(exchange.ours, theirs);
      this.#bytesIn = this.#bytesOut = this.#packetsIn = this.#packetsOut = 0;
      this.#exchange = null;
      this.keyExchanges++;
      exchange.settle();
    } catch (error) {
      this.#failed = error;
      this.#exchange = null;
      exchange.settle(error);
      throw error;
    }
  }

  async #negotiateAndSwitch(ours: Bytes, theirs: Bytes): Promise<void> {
    const first = this.sessionId.length === 0;
    const chosen = negotiate(this.#preference, theirs);
    // Strict KEX (the Terrapin fix) binds only if both sides asked for it,
    // and only on the first exchange: afterwards it is already in force.
    if (first) this.#strictKex = chosen.strictOffered;
    const strict = first && this.#strictKex;
    if (strict && this.#sequenceIn !== 1)
      throw new Error('strict KEX: the server sent something before KEXINIT');

    const ecdh = await agreement(chosen.kex);
    void this.#enqueue(
      new Writer().byte(MSG.KEX_ECDH_INIT).string(ecdh.clientPublic).build(),
    ).catch(() => {});
    if (chosen.dropGuess) await this.#readPacket();

    const reply = new Reader((await this.#expect(MSG.KEX_ECDH_REPLY, strict)).subarray(1));
    const hostKeyBlob = reply.string();
    const serverPublic = reply.string();
    const signature = reply.string();
    const secret = new Writer().mpint(await ecdh.secret(serverPublic)).build();
    const hash = await exchangeHash(ecdh.hash, {
      clientVersion: CLIENT_VERSION,
      serverVersion: this.serverVersion,
      ours,
      theirs,
      hostKeyBlob,
      clientPublic: ecdh.clientPublic,
      serverPublic,
      secret,
    });
    if (!(await verifySignature(chosen.hostKey, hostKeyBlob, signature, hash))) {
      throw new Error("the server's signature over the exchange hash does not check out");
    }
    await this.#acceptHostKey(chosen.hostKey, hostKeyBlob);
    if (first) this.sessionId = hash;
    const { outgoing, incoming } = await deriveCiphers(
      ecdh.hash,
      secret,
      hash,
      this.sessionId,
      chosen,
    );

    // Strict KEX restarts the numbering on every NEWKEYS, which is what stops
    // a prefix of injected packets from being deleted unnoticed.
    void this.#enqueue(new Uint8Array([MSG.NEWKEYS]), () => {
      this.#out = outgoing;
      if (this.#strictKex) this.#sequenceOut = 0;
    }).catch(() => {});
    await this.#expect(MSG.NEWKEYS, strict);
    this.#in = incoming;
    if (this.#strictKex) this.#sequenceIn = 0;
    const { kex, hostKey, cipher, mac } = chosen;
    this.negotiated = {
      kex,
      hostKey,
      cipher: cipher.out,
      mac: mac.out,
      strictKex: this.#strictKex,
    };
  }

  async #acceptHostKey(signatureAlgorithm: string, blob: Bytes): Promise<void> {
    if (this.hostKey) {
      if (!equalBytes(this.hostKey.blob, blob))
        throw new Error('the server presented a different host key on re-keying');
      return;
    }
    const key: HostKey = {
      algorithm: new Reader(blob).text(),
      signatureAlgorithm,
      blob,
      fingerprint: await fingerprintOf(blob),
      publicKey: openSshPublicKey(blob),
    };
    await this.#options.checkHostKey?.(key);
    this.hostKey = key;
  }

  /** Says goodbye if the connection is up, then hangs up. Safe to call twice. */
  close(): Promise<void> {
    this.#closing ??= this.#close();
    return this.#closing;
  }

  async #close(): Promise<void> {
    if (!this.#failed && this.negotiated) {
      // Reason 11, "by application": a clean goodbye, so the server logs no error.
      const goodbye = new Writer().byte(MSG.DISCONNECT).uint32(11).string('').string('').build();
      await this.#enqueue(goodbye).catch(() => {});
    }
    this.#failed ??= new Error('the connection is closed');
    this.#reader.cancel();
    await this.#writer.close().catch(() => {});
    await this.#socket.close?.().catch(() => {});
  }
}
