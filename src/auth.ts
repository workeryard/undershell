/**
 * User authentication (RFC 4252), with keyboard-interactive (RFC 4256).
 *
 * Methods are tried in the order given until the server says success. A
 * server that wants two of them — a key and then a one-time code — answers
 * the first with "partial success", and the next one given is tried then.
 */

import { parsePrivateKey } from './keys/pem';
import type { PrivateKey } from './keys/private-key';
import { MSG } from './transport/messages';
import type { Transport } from './transport/transport';
import { Reader, Writer } from './wire';

const SERVICE = 'ssh-connection';
/** Rounds of keyboard-interactive prompts before a server is assumed to loop. */
const MAX_ROUNDS = 16;

export interface Prompt {
  text: string;
  /** Whether the answer may be shown as it is typed; false for a password. */
  echo: boolean;
}

export interface Challenge {
  name: string;
  instruction: string;
  prompts: Prompt[];
}

export type Authentication =
  | { kind: 'none' }
  | { kind: 'password'; password: string }
  | {
      kind: 'privateKey';
      /** The key file's text, or a key already read with `parsePrivateKey`. */
      privateKey: string | PrivateKey;
      passphrase?: string;
    }
  | {
      kind: 'keyboardInteractive';
      /** One answer per prompt, in order. Called once per round the server asks. */
      respond(challenge: Challenge): string[] | Promise<string[]>;
    };

export class AuthenticationError extends Error {
  override name = 'AuthenticationError';
  constructor(
    message: string,
    /** What the server said it would still accept. */
    readonly methods: string[],
  ) {
    super(message);
  }
}

type Outcome = { ok: true } | { ok: false; methods: string[]; partial: boolean };

function failure(payload: Uint8Array<ArrayBuffer>): Outcome {
  const reader = new Reader(payload.subarray(1));
  return { ok: false, methods: reader.nameList(), partial: reader.bool() };
}

const METHOD = {
  none: 'none',
  password: 'password',
  privateKey: 'publickey',
  keyboardInteractive: 'keyboard-interactive',
} as const;

export async function authenticate(
  transport: Transport,
  username: string,
  methods: readonly Authentication[],
  onBanner?: (message: string) => void,
): Promise<void> {
  if (methods.length === 0) throw new Error('no authentication method was given');
  await transport.send(new Writer().byte(MSG.SERVICE_REQUEST).string('ssh-userauth').build());
  const accepted = await transport.receive();
  if (accepted[0] !== MSG.SERVICE_ACCEPT)
    throw new Error(`the server refused ssh-userauth (message ${accepted[0]})`);

  const request = (method: string) =>
    new Writer().byte(MSG.USERAUTH_REQUEST).string(username).string(SERVICE).string(method);

  /** The server's answer, banners passed on and 60 handed to `sixty`. */
  const answer = async (
    sixty?: (payload: Uint8Array<ArrayBuffer>) => Promise<void>,
  ): Promise<Outcome> => {
    for (;;) {
      const reply = await transport.receive();
      const type = reply[0];
      if (type === MSG.USERAUTH_BANNER) {
        onBanner?.(new Reader(reply.subarray(1)).text());
        continue;
      }
      if (type === MSG.USERAUTH_SUCCESS) return { ok: true };
      if (type === MSG.USERAUTH_FAILURE) return failure(reply);
      if (type === MSG.USERAUTH_INFO_REQUEST && sixty) {
        await sixty(reply);
        continue;
      }
      throw new Error(`unexpected message ${type} while authenticating`);
    }
  };

  const attempt = async (auth: Authentication): Promise<Outcome> => {
    switch (auth.kind) {
      case 'none':
        await transport.send(request('none').build());
        return answer();
      case 'password':
        await transport.send(request('password').bool(false).string(auth.password).build());
        return answer(() => {
          throw new AuthenticationError(
            `the server wants the password for "${username}" changed first`,
            [],
          );
        });
      case 'privateKey':
        return publicKey(transport, request, answer, auth);
      case 'keyboardInteractive': {
        await transport.send(request('keyboard-interactive').string('').string('').build());
        let rounds = 0;
        return answer(async (payload) => {
          if (++rounds > MAX_ROUNDS)
            throw new Error(
              `the server asked ${MAX_ROUNDS} rounds of questions and was still asking`,
            );
          const reader = new Reader(payload.subarray(1));
          const challenge: Challenge = {
            name: reader.text(),
            instruction: reader.text(),
            prompts: [],
          };
          reader.skipString(); // language tag, deprecated
          const count = reader.uint32();
          for (let index = 0; index < count; index++)
            challenge.prompts.push({ text: reader.text(), echo: reader.bool() });
          // OpenSSH ends with a round of no prompts; there is nothing to ask the caller.
          const answers = count === 0 ? [] : await auth.respond(challenge);
          if (answers.length !== count)
            throw new Error(`${answers.length} answers were given to ${count} prompts`);
          const response = new Writer().byte(MSG.USERAUTH_INFO_RESPONSE).uint32(count);
          for (const text of answers) response.string(text);
          await transport.send(response.build());
        });
      }
    }
  };

  let allowed: string[] = [];
  let partial = false;
  for (const auth of methods) {
    // After the server has named what it accepts, a method it did not name is skipped.
    if (allowed.length && auth.kind !== 'none' && !allowed.includes(METHOD[auth.kind])) continue;
    const outcome = await attempt(auth);
    if (outcome.ok) return;
    allowed = outcome.methods;
    partial ||= outcome.partial;
  }
  const tried = methods.map((auth) => METHOD[auth.kind]).join(', ');
  throw new AuthenticationError(
    `the server did not accept ${tried} for "${username}"${partial ? ' (some only in part)' : ''}; ` +
      `it will accept ${allowed.join(', ') || 'nothing more'}`,
    allowed,
  );
}

async function publicKey(
  transport: Transport,
  request: (method: string) => Writer,
  answer: () => Promise<Outcome>,
  auth: Extract<Authentication, { kind: 'privateKey' }>,
): Promise<Outcome> {
  const key =
    typeof auth.privateKey === 'string'
      ? await parsePrivateKey(auth.privateKey, auth.passphrase)
      : auth.privateKey;
  // An RSA key can sign as rsa-sha2-512 or -256; the server says which it
  // checks, if it says (RFC 8308). If it does not, both are tried.
  const said = transport.serverSignatureAlgorithms;
  const algorithms = said ? key.algorithms.filter((name) => said.includes(name)) : key.algorithms;
  if (algorithms.length === 0) {
    throw new AuthenticationError(
      `the server verifies none of ${key.algorithms.join(', ')}; it lists ${said!.join(', ')}`,
      [],
    );
  }

  let outcome: Outcome = { ok: false, methods: [], partial: false };
  for (const algorithm of algorithms) {
    const body = request('publickey')
      .bool(true)
      .string(algorithm)
      .string(key.publicKeyBlob)
      .build();
    // The signature covers the session id as well as the request, so a
    // captured request cannot be replayed onto another connection.
    const signed = new Writer().string(transport.sessionId).raw(body).build();
    await transport.send(
      new Writer()
        .raw(body)
        .string(await key.sign(algorithm, signed))
        .build(),
    );
    outcome = await answer();
    if (outcome.ok || !outcome.methods.includes('publickey')) return outcome;
  }
  return outcome;
}
