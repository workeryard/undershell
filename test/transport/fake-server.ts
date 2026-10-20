import { createHash, createPublicKey, diffieHellman, generateKeyPairSync, sign } from 'node:crypto';
import { Buffered } from '../../src/transport/buffered';
import { packetCipher, PLAIN, type Opener, type Sealer } from '../../src/transport/cipher';
import { MSG } from '../../src/transport/messages';
import { Writer, Reader, type Bytes } from '../../src/wire';

/**
 * A server in memory, enough of one to run key exchanges against the
 * client's state machine: curve25519-sha256, an Ed25519 host key, and
 * aes256-gcm afterwards. Its cryptography is Node's; the packet layer is the
 * package's own, which test/transport/cipher.test.ts checks separately.
 */
interface Options {
  strict?: boolean;
  /** Sent before the server's KEXINIT. */
  before?: Bytes[];
  /** Re-key after the first exchange, with this host key, or the same one. */
  rekeyWith?: ReturnType<typeof hostKey> | 'same';
}

export function hostKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = Buffer.from(publicKey.export({ format: 'jwk' }).x!, 'base64url');
  const blob = new Writer().string('ssh-ed25519').string(raw).build();
  return { privateKey, blob };
}

export function server(options: Options = {}) {
  // Buffered both ways, as a socket is: each side writes without waiting for the other to read.
  const roomy = { highWaterMark: 1 << 20, size: (chunk: Uint8Array) => chunk.length };
  const toServer = new TransformStream<Uint8Array, Uint8Array>({}, roomy, roomy);
  const toClient = new TransformStream<Uint8Array, Uint8Array>({}, roomy, roomy);
  const input = new Buffered(toServer.readable);
  const output = toClient.writable.getWriter();
  const received: number[] = [];
  let sealer: Sealer = PLAIN;
  let opener: Opener = PLAIN;
  let seqIn = 0;
  let seqOut = 0;
  let sessionId: Bytes | null = null;
  let clientVersion = '';
  const send = async (payload: Bytes) => output.write(await sealer.seal(payload, seqOut++));
  const read = async () => {
    const payload = await opener.open(input, seqIn++);
    received.push(payload[0]!);
    return payload;
  };

  const exchange = async (key: ReturnType<typeof hostKey>, theirs?: Bytes) => {
    const kex = ['curve25519-sha256', ...(options.strict ? ['kex-strict-s-v00@openssh.com'] : [])];
    const ours = new Writer()
      .byte(MSG.KEXINIT)
      .raw(new Uint8Array(16))
      .nameList(kex)
      .nameList(['ssh-ed25519'])
      .nameList(['aes256-gcm@openssh.com'])
      .nameList(['aes256-gcm@openssh.com'])
      .nameList(['hmac-sha2-256'])
      .nameList(['hmac-sha2-256'])
      .nameList(['none'])
      .nameList(['none'])
      .nameList([])
      .nameList([])
      .bool(false)
      .uint32(0)
      .build();
    await send(ours);
    const clientInit = theirs ?? (await read());
    const init = new Reader((await read()).subarray(1));
    const clientPublic = init.string();
    const ephemeral = generateKeyPairSync('x25519');
    const serverPublic = Buffer.from(ephemeral.publicKey.export({ format: 'jwk' }).x!, 'base64url');
    const theirs25519 = createPublicKey({
      key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(clientPublic).toString('base64url') },
      format: 'jwk',
    });
    const secret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: theirs25519 });
    const k = new Writer().mpint(secret).build();
    const hash = createHash('sha256')
      .update(
        new Writer()
          .string(clientVersion)
          .string('SSH-2.0-Fake')
          .string(clientInit)
          .string(ours)
          .string(key.blob)
          .string(clientPublic)
          .string(serverPublic)
          .raw(k)
          .build(),
      )
      .digest();
    sessionId ??= new Uint8Array(hash);
    const signature = new Writer()
      .string('ssh-ed25519')
      .string(sign(null, hash, key.privateKey))
      .build();
    await send(
      new Writer()
        .byte(MSG.KEX_ECDH_REPLY)
        .string(key.blob)
        .string(serverPublic)
        .string(signature)
        .build(),
    );
    await send(new Uint8Array([MSG.NEWKEYS]));
    if (options.strict) seqOut = 0;
    const derive = (letter: string, length: number) => {
      let out = createHash('sha256')
        .update(k)
        .update(hash)
        .update(letter)
        .update(sessionId!)
        .digest();
      while (out.length < length)
        out = Buffer.concat([
          out,
          createHash('sha256').update(k).update(hash).update(out).digest(),
        ]);
      return new Uint8Array(out.subarray(0, length));
    };
    sealer = await packetCipher(
      'aes256-gcm@openssh.com',
      'hmac-sha2-256',
      { iv: derive('B', 12), key: derive('D', 32), macKey: new Uint8Array(0) },
      'encrypt',
    );
    const nextOpener = await packetCipher(
      'aes256-gcm@openssh.com',
      'hmac-sha2-256',
      { iv: derive('A', 12), key: derive('C', 32), macKey: new Uint8Array(0) },
      'decrypt',
    );
    const newKeys = await read();
    if (newKeys[0] !== MSG.NEWKEYS) throw new Error(`expected NEWKEYS, got ${newKeys[0]}`);
    opener = nextOpener;
    if (options.strict) seqIn = 0;
  };

  const first = hostKey();
  const running = (async () => {
    await output.write(new TextEncoder().encode('SSH-2.0-Fake\r\n'));
    clientVersion = await input.line(1024);
    for (const packet of options.before ?? []) await send(packet);
    await exchange(first);
    if (options.rekeyWith) await exchange(options.rekeyWith === 'same' ? first : options.rekeyWith);
    // Something receive() hands back, once any re-key is over.
    await send(new Uint8Array([MSG.REQUEST_FAILURE]));
  })();
  running.catch(() => {});
  const fingerprint = createHash('sha256').update(first.blob).digest('base64').replace(/=+$/, '');
  return {
    socket: { readable: toClient.readable, writable: toServer.writable },
    received,
    running,
    fingerprint,
  };
}
