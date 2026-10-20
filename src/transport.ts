/**
 * The SSH transport layer (RFC 4253): version exchange, the binary packet
 * protocol, key exchange, and one authenticated cipher.
 *
 * Deliberately narrow. `curve25519-sha256` with `aes256-gcm@openssh.com` is
 * offered and nothing else, because every algorithm added is another way to be
 * subtly wrong, and every server since OpenSSH 6.2 speaks both. Host keys are
 * the one place breadth is worth it — a server you do not administer may have
 * only an RSA key — so ed25519 and rsa-sha2-256/512 are all verified.
 *
 * ChaCha20-Poly1305, which OpenSSH would otherwise prefer, is absent from
 * WebCrypto; not offering it makes the server pick AES-GCM.
 */

import { subtle } from "./crypto";
import { concat, Reader, Writer, type Bytes } from "./wire";

export const MSG = {
  DISCONNECT: 1,
  IGNORE: 2,
  UNIMPLEMENTED: 3,
  DEBUG: 4,
  SERVICE_REQUEST: 5,
  SERVICE_ACCEPT: 6,
  EXT_INFO: 7,
  KEXINIT: 20,
  NEWKEYS: 21,
  KEX_ECDH_INIT: 30,
  KEX_ECDH_REPLY: 31,
  USERAUTH_REQUEST: 50,
  USERAUTH_FAILURE: 51,
  USERAUTH_SUCCESS: 52,
  USERAUTH_BANNER: 53,
  GLOBAL_REQUEST: 80,
  REQUEST_SUCCESS: 81,
  REQUEST_FAILURE: 82,
  CHANNEL_OPEN: 90,
  CHANNEL_OPEN_CONFIRMATION: 91,
  CHANNEL_OPEN_FAILURE: 92,
  CHANNEL_WINDOW_ADJUST: 93,
  CHANNEL_DATA: 94,
  CHANNEL_EXTENDED_DATA: 95,
  CHANNEL_EOF: 96,
  CHANNEL_CLOSE: 97,
  CHANNEL_REQUEST: 98,
  CHANNEL_SUCCESS: 99,
  CHANNEL_FAILURE: 100,
} as const;

/**
 * All this needs from a runtime: two byte streams and a way to hang up.
 * `cloudflare:sockets` provides one, underfetch's proxy tunnel provides one,
 * and so does a pair of in-memory streams in a test.
 */
export interface ByteSocket {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  close?(): Promise<void>;
}

export const CLIENT_VERSION = "SSH-2.0-flowker_0.1";

const KEX = "curve25519-sha256";
const KEX_STRICT = "kex-strict-c-v00@openssh.com";
const KEX_STRICT_SERVER = "kex-strict-s-v00@openssh.com";
const HOST_KEYS = ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"];
const CIPHER = "aes256-gcm@openssh.com";

/** RFC 4253 §4.2 allows a server 8 KiB of banner before its version line. */
const MAX_BANNER = 8 * 1024;
const MAX_PACKET = 1024 * 1024;

class Buffered {
  #buffer: Bytes = new Uint8Array(0);
  #ended = false;
  readonly #reader: ReadableStreamDefaultReader<Uint8Array>;

  constructor(stream: ReadableStream<Uint8Array>) {
    this.#reader = stream.getReader();
  }

  async #pull(): Promise<boolean> {
    if (this.#ended) return false;
    const { value, done } = await this.#reader.read();
    if (done) {
      this.#ended = true;
      return false;
    }
    if (value?.length) this.#buffer = concat([this.#buffer, value]);
    return true;
  }

  async exactly(length: number): Promise<Bytes> {
    while (this.#buffer.length < length) {
      if (!(await this.#pull()))
        throw new Error(`the connection ended after ${this.#buffer.length} of ${length} bytes`);
    }
    const taken = this.#buffer.slice(0, length);
    this.#buffer = this.#buffer.subarray(length);
    return taken;
  }

  /** One CRLF-terminated line, refusing to buffer a hostile server's flood. */
  async line(limit: number): Promise<string> {
    for (;;) {
      const at = this.#buffer.indexOf(10);
      if (at !== -1) {
        const line = this.#buffer.subarray(0, at);
        this.#buffer = this.#buffer.subarray(at + 1);
        return new TextDecoder().decode(line).replace(/\r$/, "");
      }
      if (this.#buffer.length > limit) throw new Error(`the server sent ${this.#buffer.length} bytes without a line`);
      if (!(await this.#pull())) throw new Error("the connection ended before a line arrived");
    }
  }

  cancel(): void {
    void this.#reader.cancel().catch(() => {});
  }
}

function sha256(...parts: Uint8Array[]): Promise<Bytes> {
  return subtle.digest("SHA-256", concat(parts)).then((hash) => new Uint8Array(hash));
}

/** Padding so the encrypted part lands on a block boundary, at least 4 bytes of it. */
export function paddingFor(payloadLength: number, blockSize: number, countLengthField: boolean): number {
  const base = (countLengthField ? 4 : 0) + 1 + payloadLength;
  let padding = blockSize - (base % blockSize);
  if (padding < 4) padding += blockSize;
  return padding;
}

interface Direction {
  key: CryptoKey;
  /** 4 fixed bytes then an 8-byte counter, bumped once per packet. */
  iv: Bytes;
}

/**
 * The GCM invocation counter, as a big-endian integer over the last 8 bytes.
 * Exported because reusing one is not a bug you want to find in production:
 * it is what the send queue exists to prevent.
 */
export function bumpCounter(iv: Bytes): void {
  for (let index = 11; index >= 4; index--) {
    if (++iv[index]! <= 0xff) break;
    iv[index] = 0;
  }
}

export interface HostKey {
  /** The blob the server sent, which is what the fingerprint is taken over. */
  blob: Bytes;
  algorithm: string;
  /** Base64 SHA-256, as `ssh-keygen -lf` prints it, without the "SHA256:". */
  fingerprint: string;
}

export interface Negotiated {
  kex: string;
  hostKey: string;
  cipher: string;
  strictKex: boolean;
}

export class Transport {
  #incoming: Direction | null = null;
  #outgoing: Direction | null = null;
  #sequenceIn = 0;
  #sequenceOut = 0;
  #strictKex = false;
  /**
   * Every send is chained onto the last. Two overlapping sends would each read
   * the same invocation counter while the other awaited WebCrypto, and a GCM
   * nonce used twice hands an attacker the keystream.
   */
  #sending: Promise<void> = Promise.resolve();
  readonly #reader: Buffered;
  readonly #writer: WritableStreamDefaultWriter<Uint8Array>;
  readonly #socket: ByteSocket;

  sessionId: Bytes = new Uint8Array(0);
  hostKey: HostKey | null = null;
  serverVersion = "";
  negotiated: Negotiated | null = null;

  constructor(socket: ByteSocket) {
    this.#socket = socket;
    this.#reader = new Buffered(socket.readable);
    this.#writer = socket.writable.getWriter();
  }

  send(payload: Bytes): Promise<void> {
    const next = this.#sending.then(() => this.#sendNow(payload));
    // Keep the chain alive after a failure so later sends report their own error.
    this.#sending = next.catch(() => {});
    return next;
  }

  async #sendNow(payload: Bytes): Promise<void> {
    const out = this.#outgoing;
    if (!out) {
      const padding = paddingFor(payload.length, 8, true);
      const packet = new Writer()
        .uint32(1 + payload.length + padding)
        .byte(padding)
        .raw(payload)
        .raw(new Uint8Array(padding))
        .build();
      this.#sequenceOut++;
      return this.#writer.write(packet);
    }

    // AES-GCM: the length goes out in the clear and is authenticated as
    // associated data; everything after it is one sealed block.
    const padding = paddingFor(payload.length, 16, false);
    const lengthBytes = new Writer().uint32(1 + payload.length + padding).build();
    const plain = concat([new Uint8Array([padding]), payload, crypto.getRandomValues(new Uint8Array(padding))]);
    const sealed = new Uint8Array(
      await subtle.encrypt({ name: "AES-GCM", iv: out.iv, additionalData: lengthBytes }, out.key, plain),
    );
    bumpCounter(out.iv);
    this.#sequenceOut++;
    return this.#writer.write(concat([lengthBytes, sealed]));
  }

  /**
   * The next packet a caller needs to act on. Housekeeping is dealt with here:
   * a server's global requests are answered, its debug chatter dropped, and a
   * mid-session key exchange run to completion before the caller sees anything.
   */
  async receive(): Promise<Bytes> {
    for (;;) {
      const payload = await this.#receiveOne();
      const type = payload[0];

      if (type === MSG.DISCONNECT) {
        const reader = new Reader(payload.subarray(1));
        throw new Error(`the server disconnected (reason ${reader.uint32()}): ${reader.text()}`);
      }
      if (type === MSG.IGNORE || type === MSG.DEBUG || type === MSG.UNIMPLEMENTED || type === MSG.EXT_INFO) {
        // Under strict KEX these are forbidden during the exchange itself,
        // which #receiveOne enforces; outside it they are noise.
        continue;
      }
      if (type === MSG.GLOBAL_REQUEST) {
        const reader = new Reader(payload.subarray(1));
        reader.skipString();
        // Leaving want_reply unanswered stalls servers that ask, such as
        // OpenSSH offering its host keys right after authentication.
        if (reader.bool()) await this.send(new Uint8Array([MSG.REQUEST_FAILURE]));
        continue;
      }
      if (type === MSG.KEXINIT) {
        await this.keyExchange(payload);
        continue;
      }
      return payload;
    }
  }

  async #receiveOne(): Promise<Bytes> {
    const incoming = this.#incoming;
    if (!incoming) {
      const header = await this.#reader.exactly(4);
      const length = new DataView(header.buffer, header.byteOffset, 4).getUint32(0);
      if (length < 8 || length > MAX_PACKET) throw new Error(`a packet of ${length} bytes is out of range`);
      const rest = await this.#reader.exactly(length);
      this.#sequenceIn++;
      return rest.subarray(1, rest.length - rest[0]!);
    }

    const lengthBytes = await this.#reader.exactly(4);
    const length = new DataView(lengthBytes.buffer, lengthBytes.byteOffset, 4).getUint32(0);
    if (length < 16 || length > MAX_PACKET || length % 16 !== 0) {
      throw new Error(`a packet of ${length} bytes is out of range`);
    }
    const sealed = await this.#reader.exactly(length + 16);
    const plain = new Uint8Array(
      await subtle.decrypt({ name: "AES-GCM", iv: incoming.iv, additionalData: lengthBytes }, incoming.key, sealed),
    );
    bumpCounter(incoming.iv);
    this.#sequenceIn++;
    return plain.subarray(1, plain.length - plain[0]!);
  }

  /** Both sides announce themselves in plain text before anything else. */
  async exchangeVersions(): Promise<string> {
    await this.#writer.write(new TextEncoder().encode(`${CLIENT_VERSION}\r\n`));
    let spent = 0;
    for (;;) {
      const line = await this.#reader.line(MAX_BANNER);
      // Anything before the version line is a banner the server chose to print.
      if (line.startsWith("SSH-")) {
        if (!line.startsWith("SSH-2.0-")) throw new Error(`the server speaks ${line}, and this client only speaks 2.0`);
        this.serverVersion = line;
        return line;
      }
      spent += line.length + 1;
      if (spent > MAX_BANNER) throw new Error("the server sent more banner than RFC 4253 allows before its version");
    }
  }

  #kexinitPayload(): Bytes {
    return new Writer()
      .byte(MSG.KEXINIT)
      .raw(crypto.getRandomValues(new Uint8Array(16)))
      .nameList([KEX, KEX_STRICT])
      .nameList(HOST_KEYS)
      .nameList([CIPHER])
      .nameList([CIPHER])
      .nameList(["hmac-sha2-256"])
      .nameList(["hmac-sha2-256"])
      .nameList(["none"])
      .nameList(["none"])
      .nameList([])
      .nameList([])
      .bool(false)
      .uint32(0)
      .build();
  }

  /**
   * Key exchange, start to finish. `theirs` is passed in when the server asked
   * for a re-exchange mid-session and its KEXINIT has already been read.
   */
  async keyExchange(theirs?: Bytes): Promise<void> {
    const ours = this.#kexinitPayload();
    const first = this.sessionId.length === 0;
    await this.send(ours);

    const peer = theirs ?? (await this.#receiveOne());
    if (peer[0] !== MSG.KEXINIT) throw new Error(`expected KEXINIT, got message ${peer[0]}`);

    const reader = new Reader(peer.subarray(17)); // the message byte and a 16-byte cookie
    const offered = {
      kex: reader.nameList(),
      hostKey: reader.nameList(),
      cipherToServer: reader.nameList(),
      cipherToClient: reader.nameList(),
    };
    if (!offered.kex.includes(KEX)) {
      throw new Error(`the server offers no key exchange this client speaks; it has ${offered.kex.join(", ")}`);
    }
    for (const [what, list] of [
      ["cipher to the server", offered.cipherToServer],
      ["cipher to the client", offered.cipherToClient],
    ] as const) {
      if (!list.includes(CIPHER)) {
        throw new Error(`the server offers no ${what} this client speaks; it has ${list.join(", ")}`);
      }
    }
    const hostKeyAlgorithm = HOST_KEYS.find((algorithm) => offered.hostKey.includes(algorithm));
    if (!hostKeyAlgorithm) {
      throw new Error(`the server has no host key this client can check; it offers ${offered.hostKey.join(", ")}`);
    }

    // Strict KEX (the Terrapin fix) only binds if both sides asked for it, and
    // only on the first exchange: afterwards it is already in force.
    if (first) this.#strictKex = offered.kex.includes(KEX_STRICT_SERVER);
    this.negotiated = { kex: KEX, hostKey: hostKeyAlgorithm, cipher: CIPHER, strictKex: this.#strictKex };

    const pair = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
    const clientPublic = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
    await this.send(new Writer().byte(MSG.KEX_ECDH_INIT).string(clientPublic).build());

    const replyPayload = await this.#receiveOne();
    if (replyPayload[0] !== MSG.KEX_ECDH_REPLY) throw new Error(`expected KEX_ECDH_REPLY, got ${replyPayload[0]}`);
    const reply = new Reader(replyPayload.subarray(1));
    const hostKeyBlob = reply.string();
    const serverPublic = reply.string();
    const signature = reply.string();
    if (serverPublic.length !== 32) throw new Error(`the server's ephemeral key is ${serverPublic.length} bytes`);

    const theirEphemeral = await subtle.importKey("raw", serverPublic, { name: "X25519" }, false, []);
    const shared = new Uint8Array(
      await subtle.deriveBits({ name: "X25519", public: theirEphemeral }, pair.privateKey, 256),
    );

    // The exchange hash covers everything both sides have said so far. If one
    // byte of our view differs from the server's, the signature check fails.
    const sharedAsMpint = new Writer().mpint(shared).build();
    const hash = await sha256(
      new Writer()
        .string(CLIENT_VERSION)
        .string(this.serverVersion)
        .string(ours)
        .string(peer)
        .string(hostKeyBlob)
        .string(clientPublic)
        .string(serverPublic)
        .raw(sharedAsMpint)
        .build(),
    );

    await this.#verifyHostKey(hostKeyAlgorithm, hostKeyBlob, signature, hash);
    if (first) this.sessionId = hash;

    await this.send(new Uint8Array([MSG.NEWKEYS]));
    const newKeys = await this.#receiveOne();
    if (newKeys[0] !== MSG.NEWKEYS) throw new Error(`expected NEWKEYS, got ${newKeys[0]}`);

    const derive = async (letter: string, length: number) => {
      let material: Bytes = await sha256(sharedAsMpint, hash, new TextEncoder().encode(letter), this.sessionId);
      while (material.length < length) material = concat([material, await sha256(sharedAsMpint, hash, material)]);
      return material.subarray(0, length);
    };
    const [ivOut, ivIn, keyOut, keyIn] = await Promise.all([
      derive("A", 12),
      derive("B", 12),
      derive("C", 32),
      derive("D", 32),
    ]);
    const aes = (raw: Bytes, usage: string) => subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [usage]);

    this.#outgoing = { key: await aes(keyOut!, "encrypt"), iv: new Uint8Array(ivOut!) };
    this.#incoming = { key: await aes(keyIn!, "decrypt"), iv: new Uint8Array(ivIn!) };
    // Strict KEX restarts the numbering, which is what stops a prefix of
    // injected packets from being deleted without either side noticing.
    if (this.#strictKex) {
      this.#sequenceIn = 0;
      this.#sequenceOut = 0;
    }
  }

  async #verifyHostKey(algorithm: string, blob: Bytes, signature: Bytes, hash: Bytes): Promise<void> {
    const key = new Reader(blob);
    const blobType = key.text();
    const signed = new Reader(signature);
    const signatureType = signed.text();
    if (signatureType !== algorithm) {
      throw new Error(`the host key signature is a ${signatureType}, not the ${algorithm} that was agreed`);
    }
    const bytes = signed.string();

    let publicKey: CryptoKey;
    let verifyAlgorithm: unknown;
    if (algorithm === "ssh-ed25519") {
      if (blobType !== "ssh-ed25519") throw new Error(`the host key is a ${blobType}, not the ed25519 agreed`);
      publicKey = await subtle.importKey("raw", key.string(), { name: "Ed25519" }, false, ["verify"]);
      verifyAlgorithm = { name: "Ed25519" };
    } else {
      // rsa-sha2-256/512 sign with an "ssh-rsa" blob: the algorithm names the
      // hash, not the key.
      if (blobType !== "ssh-rsa") throw new Error(`the host key is a ${blobType}, not the RSA agreed`);
      const exponent = key.string();
      const modulus = key.string();
      const hashName = algorithm === "rsa-sha2-512" ? "SHA-512" : "SHA-256";
      publicKey = await subtle.importKey(
        "jwk",
        { kty: "RSA", n: base64Url(modulus), e: base64Url(exponent), alg: hashName === "SHA-512" ? "RS512" : "RS256" },
        { name: "RSASSA-PKCS1-v1_5", hash: hashName },
        false,
        ["verify"],
      );
      verifyAlgorithm = { name: "RSASSA-PKCS1-v1_5" };
    }

    if (!(await subtle.verify(verifyAlgorithm, publicKey, bytes, hash))) {
      throw new Error("the server's signature over the exchange hash does not check out");
    }

    const digest = new Uint8Array(await subtle.digest("SHA-256", blob));
    this.hostKey = { blob, algorithm: blobType, fingerprint: base64(digest).replace(/=+$/, "") };
  }

  async close(): Promise<void> {
    this.#reader.cancel();
    await this.#writer.close().catch(() => {});
    await this.#socket.close?.().catch(() => {});
  }
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** An SSH mpint is signed, so a leading zero has to come off before base64url. */
function base64Url(bytes: Uint8Array): string {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  return base64(bytes.subarray(start)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
