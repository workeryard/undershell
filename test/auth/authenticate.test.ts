import { describe, expect, it } from 'vitest';
import { authenticate, AuthenticationError, type Challenge } from '../../src/auth';
import { parsePrivateKey } from '../../src/keys/pem';
import { MSG } from '../../src/transport/messages';
import type { Transport } from '../../src/transport/transport';
import { readFileSync } from 'node:fs';
import { Reader, Writer, type Bytes } from '../../src/wire';

/** A transport that answers user authentication from a script. */
function scripted(
  answer: (request: Reader, method: string) => Bytes[],
  serverSigAlgs: string[] | null = null,
) {
  const queue: Bytes[] = [];
  const methods: string[] = [];
  const transport = {
    sessionId: new Uint8Array(32),
    serverSignatureAlgorithms: serverSigAlgs,
    send(payload: Bytes): Promise<void> {
      const reader = new Reader(payload.subarray(1));
      if (payload[0] === MSG.SERVICE_REQUEST) queue.push(new Uint8Array([MSG.SERVICE_ACCEPT]));
      if (payload[0] === MSG.USERAUTH_REQUEST) {
        reader.text();
        reader.text();
        const method = reader.text();
        methods.push(method);
        queue.push(...answer(reader, method));
      }
      if (payload[0] === MSG.USERAUTH_INFO_RESPONSE) queue.push(...answer(reader, 'response'));
      return Promise.resolve();
    },
    receive(): Promise<Bytes> {
      const next = queue.shift();
      return next ? Promise.resolve(next) : Promise.reject(new Error('the script ran out'));
    },
  };
  return { transport: transport as unknown as Transport, methods };
}

const success = () => new Uint8Array([MSG.USERAUTH_SUCCESS]);
const failure = (methods: string[], partial = false) =>
  new Writer().byte(MSG.USERAUTH_FAILURE).nameList(methods).bool(partial).build();
function infoRequest(name: string, prompts: [string, boolean][]): Bytes {
  const writer = new Writer()
    .byte(MSG.USERAUTH_INFO_REQUEST)
    .string(name)
    .string('')
    .string('')
    .uint32(prompts.length);
  for (const [text, echo] of prompts) writer.string(text).bool(echo);
  return writer.build();
}

describe('keyboard-interactive', () => {
  it('asks the callback each round, and sends its answers', async () => {
    const answers: string[][] = [];
    let round = 0;
    const { transport } = scripted((reader, method) => {
      if (method === 'keyboard-interactive') return [infoRequest('', [['Password: ', false]])];
      const count = reader.uint32();
      answers.push(Array.from({ length: count }, () => reader.text()));
      round++;
      if (round === 1) return [infoRequest('2FA', [['Verification code: ', true]])];
      // OpenSSH's closing round, with nothing to ask.
      if (round === 2) return [infoRequest('', [])];
      return [success()];
    });
    const seen: Challenge[] = [];
    await authenticate(transport, 'u', [
      {
        kind: 'keyboardInteractive',
        respond: (c) => (seen.push(c), c.prompts.map((p) => (p.echo ? '123456' : 'secret'))),
      },
    ]);
    expect(seen.map((c) => c.prompts[0]!.text)).toEqual(['Password: ', 'Verification code: ']);
    expect(answers).toEqual([['secret'], ['123456'], []]);
  });

  it('refuses a callback that answers the wrong number of prompts', async () => {
    const { transport } = scripted(() => [
      infoRequest('', [
        ['a', true],
        ['b', true],
      ]),
    ]);
    await expect(
      authenticate(transport, 'u', [{ kind: 'keyboardInteractive', respond: () => ['one'] }]),
    ).rejects.toThrow(/1 answers were given to 2 prompts/);
  });
});

describe('several methods', () => {
  it('goes on to the second factor after a partial success', async () => {
    const { transport, methods } = scripted((_, method) => {
      if (method === 'password') return [failure(['keyboard-interactive'], true)];
      if (method === 'keyboard-interactive') return [infoRequest('', [['Code: ', true]])];
      return [success()];
    });
    await authenticate(transport, 'u', [
      { kind: 'password', password: 'p' },
      { kind: 'keyboardInteractive', respond: () => ['1'] },
    ]);
    expect(methods).toEqual(['password', 'keyboard-interactive']);
  });

  it('skips a method the server has said it will not take', async () => {
    const { transport, methods } = scripted((_, method) =>
      method === 'none' ? [failure(['keyboard-interactive'])] : [success()],
    );
    await authenticate(transport, 'u', [
      { kind: 'none' },
      { kind: 'password', password: 'p' },
      { kind: 'keyboardInteractive', respond: () => [] },
    ]);
    expect(methods).toEqual(['none', 'keyboard-interactive']);
  });

  it('says what the server would still accept when nothing worked', async () => {
    const { transport } = scripted(() => [failure(['publickey'])]);
    const error = await authenticate(transport, 'u', [{ kind: 'password', password: 'p' }]).catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(AuthenticationError);
    expect((error as AuthenticationError).methods).toEqual(['publickey']);
    expect((error as AuthenticationError).message).toMatch(/it will accept publickey/);
  });

  it('passes banners on', async () => {
    const banners: string[] = [];
    const { transport } = scripted(() => [
      new Writer().byte(MSG.USERAUTH_BANNER).string('Authorized use only').string('').build(),
      success(),
    ]);
    await authenticate(transport, 'u', [{ kind: 'none' }], (message) => banners.push(message));
    expect(banners).toEqual(['Authorized use only']);
  });
});

describe('an RSA key', () => {
  const rsa = readFileSync(new URL('../fixtures/keys/rsa', import.meta.url), 'utf8');

  it('signs with what server-sig-algs lists', async () => {
    const signed: string[] = [];
    const { transport } = scripted(
      (reader) => {
        reader.bool();
        signed.push(reader.text());
        return [success()];
      },
      ['ssh-ed25519', 'rsa-sha2-256'],
    );
    await authenticate(transport, 'u', [
      { kind: 'privateKey', privateKey: await parsePrivateKey(rsa) },
    ]);
    expect(signed).toEqual(['rsa-sha2-256']);
  });

  it('tries SHA-512 and then SHA-256 when the server lists nothing', async () => {
    const signed: string[] = [];
    const { transport } = scripted((reader) => {
      reader.bool();
      signed.push(reader.text());
      return signed.length === 1 ? [failure(['publickey'])] : [success()];
    });
    await authenticate(transport, 'u', [{ kind: 'privateKey', privateKey: rsa }]);
    expect(signed).toEqual(['rsa-sha2-512', 'rsa-sha2-256']);
  });
});
