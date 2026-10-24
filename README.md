# undershell

An SSH client for Cloudflare Workers: commands, shells, SFTP, port forwards
and jump hosts, over a TCP socket or Cloudflare Tunnel, with WebCrypto as
its only cryptography and no dependencies.

```ts
import { connect } from '@workeryard/undershell/workers';

const client = await connect({
  host: 'build.example.com',
  username: 'deploy',
  auth: { kind: 'privateKey', privateKey: env.DEPLOY_KEY },
  hostKeyFingerprint: 'SHA256:d7Te2DHmvBNSWJNBWik2KbDTjmWtYHe2bvXTMM9lVg4',
});

const { stdout, exitStatus } = await client.exec(
  'systemctl restart app && systemctl is-active app',
);
await client.close();
```

## Status

**Experimental, 0.2.0.** What it does is tested — 187 unit tests, a matrix of
947 cases against six builds of OpenSSH from 7.4 to 10.3 and Dropbear in
Docker, MikroTik RouterOS 7 and 6, and 29 live cases from a deployed Worker
before the release — but it has not yet
carried anyone's production traffic, and:

- **The API may change** between minor versions until 1.0.0. The changes
  are written down in [CHANGELOG.md](CHANGELOG.md).
- **The protocol is implemented here**, about 3,300 lines of it, with no
  security review of its own. The cryptographic primitives are the
  runtime's WebCrypto; how they are put together into SSH is this package's.

It began as the SSH client inside Flowker, which ran one command per
connection; see the changelog for what 0.1.0 added.

Pin an exact version, and read the changelog before moving it.

## Who it is for

- Workers that run something on a server: a deploy step, a health check, a
  backup, a command a workflow or a chat bot was asked to run.
- Workers that move files over SFTP without holding them in memory: a
  report to a partner's drop box, a log pulled into R2.
- Browser terminals whose backend is a Worker: a shell with a pty, resized
  as the window is.
- Servers on a private network, reached through a bastion, or through
  Cloudflare Tunnel with a Zero Trust service token.

## What it is not for

- **A way around a server's authentication.** It logs in with credentials
  the server accepts, and only after the server has proved it holds the
  host key you expected. There is no accept-any mode.
- **ChaCha20-Poly1305**, which WebCrypto does not have. Every server
  that offers it also offers AES-GCM or AES-CTR, which are used instead.
- **Agent forwarding, X11, or remote forwarding** (`ssh -R`). The server's
  attempts to open such channels are refused. Local forwarding is here.
- **A server.** It is a client only.
- **SHA-1 where it is broken**: no `ssh-rsa` signatures, no
  `diffie-hellman-group1-sha1` or `-group14-sha1`. OpenSSH has refused
  `ssh-rsa` signatures by default since 8.8. `hmac-sha1` is offered, last,
  for servers that have nothing better: SHA-1's collisions do not carry over
  to HMAC, and OpenSSH still offers it by default.

## Install

```
npm install @workeryard/undershell
```

The package ships its TypeScript source, so it is read by a bundler:
Wrangler, Vite, esbuild or tsx, or `tsc` with `"moduleResolution": "Bundler"`,
as a Worker project has it. A project that compiles with `NodeNext`, or runs
plain `node`, cannot import it yet. It needs Node 22 or later, or workerd.

`@workeryard/undershell` is runtime-agnostic: it takes a `ByteSocket` —
two byte streams and a `close()` — from wherever you have one.
`@workeryard/undershell/workers` adds the two ways a Worker gets one, and
re-exports everything else.

## Using it

### Connecting

```ts
import { connect } from '@workeryard/undershell/workers';

const client = await connect({
  host: '198.51.100.20',
  port: 22,
  username: 'deploy',
  auth: { kind: 'privateKey', privateKey: env.KEY, passphrase: env.KEY_PASSPHRASE },
  hostKeyFingerprint: 'SHA256:…',
  timeoutMs: 30_000, // to open the socket; then again for the handshake and login
  keepalive: { intervalMs: 30_000, maxMissed: 3 }, // optional, as ssh's ServerAliveInterval
});
```

With `keepalive`, the client asks the server every `intervalMs` whether it
is still there (`keepalive@openssh.com`, which any server answers, if only
to refuse it) and gives the connection up after `maxMissed` asks go
unanswered, rather than leaving a frozen server or a dead NAT mapping to
hang the session until TCP notices. Anything heard from the server counts
as an answer. It is off unless given.

Anything that gives two byte streams works with the core instead,
[underfetch](https://github.com/workeryard/underfetch)'s proxy tunnel for one:

```ts
import { SshClient } from '@workeryard/undershell';

const client = await SshClient.connect({ socket, username, auth, hostKeyFingerprint });
```

### The host key

Every connection is checked against what you expect, before anything is
sent under its keys. Give a fingerprint, as `ssh-keygen -lf` or
`ssh-keyscan host | ssh-keygen -lf -` prints it, or several while a key is
being rotated:

```ts
hostKeyFingerprint: ['SHA256:old…', 'SHA256:new…'],
```

or check it yourself, against a known_hosts you keep:

```ts
verifyHostKey: async (key) => {
  // key.algorithm, key.fingerprint, key.publicKey ("ssh-ed25519 AAAA…"), key.blob
  return (await env.KNOWN_HOSTS.get(host)) === key.publicKey;
},
```

With both, both have to agree. With neither, `connect` refuses to start.
A re-key that presents a different host key ends the connection.

A server usually has several host keys, and the one checked is the one the
key exchange settles on: ed25519 first, then ECDSA, then RSA. Pin that one,
pin all of them, or narrow the choice with
`algorithms: { hostKey: ['rsa-sha2-512'] }`.

`readHostKey(socket)` reads a server's key the way `ssh-keyscan` does, for
showing someone a fingerprint to confirm.

### Logging in

`auth` is one method, or several tried in order. A server that wants two —
a key and then a one-time code — answers the first with partial success,
and the next is tried:

```ts
auth: [
  { kind: 'privateKey', privateKey: env.KEY },
  {
    kind: 'keyboardInteractive',
    // Once per round the server asks; one answer per prompt.
    respond: ({ name, instruction, prompts }) => prompts.map((prompt) => totp(env.SEED)),
  },
],
```

| `kind`                | What it sends                                                               |
| --------------------- | --------------------------------------------------------------------------- |
| `privateKey`          | A signature from ed25519, RSA (rsa-sha2-512/256) or ECDSA P-256/384/521     |
| `password`            | The password                                                                |
| `keyboardInteractive` | Your `respond`'s answers, RFC 4256: passwords through PAM, OTP, 2FA prompts |
| `none`                | Only the username, for servers that allow it or to learn what they accept   |

A failure is an `AuthenticationError` whose `methods` say what the server
would still accept. `onBanner` receives what a server shows before login.

Keys are read from OpenSSH's own format (`ssh-keygen`'s default, with or
without a passphrase, AES-CTR or AES-GCM), PKCS#1 `RSA PRIVATE KEY`,
SEC1 `EC PRIVATE KEY` and unencrypted PKCS#8 `PRIVATE KEY`.
`parsePrivateKey` reads one once, to reuse across connections.
An encrypted PEM is refused with the command that converts it.

A passphrase costs CPU: bcrypt_pbkdf at `ssh-keygen`'s 16 rounds is about
170 ms of it in Node 22 and took about 300 ms in a deployed Worker
(2026-10-24), far past a 10 ms plan's limit. There, keep the key
unencrypted in a secret instead, or read it once with `parsePrivateKey`.

### Commands

```ts
const result = await client.exec('make deploy', {
  stdin: 'yes\n',
  maxOutputBytes: 4 * 1024 * 1024, // per stream; past it, output is drained and truncated: true
  signal: AbortSignal.timeout(60_000), // SIGKILL and close on abort
  env: { RELEASE: '42' }, // only names the server's AcceptEnv lists
});
// { stdout, stderr, exitStatus, exitSignal?, truncated }
```

For output too large to hold, or input to feed as it comes, `spawn` gives
the streams:

```ts
const session = await client.spawn('pg_dump app');
await session.stdout.pipeTo(r2Upload.writable);
await session.stderr.cancel(); // read it or cancel it: the two share one window
const { code, signal } = await session.exit;
```

Several commands, shells and SFTP sessions can be open on one connection at
once.

### Shells

```ts
const shell = await client.shell({ pty: { term: 'xterm-256color', cols: 120, rows: 40 } });
shell.stdout.pipeTo(toBrowser);
fromBrowser.pipeTo(shell.stdin);
await shell.resize(160, 48);
await shell.signal('INT');
```

### SFTP

```ts
const sftp = await client.sftp();

await sftp.put('/srv/in/report.csv', r2Object.body); // a stream, or bytes
const stream = sftp.createReadStream('/var/log/app.log', { start: 0 });
await stream.pipeTo(destination);

for await (const entry of sftp.readdir('/srv/in')) {
  // A page at a time, however large the directory.
  console.log(entry.name, entry.size, entry.directory);
}

await sftp.mkdir('/srv/out', { permissions: 0o750 });
await sftp.rename('/srv/in/report.csv', '/srv/out/report.csv', { overwrite: true });
const stats = await sftp.stat('/srv/out/report.csv');
await sftp.remove('/srv/out/report.csv');
await sftp.rmdir('/srv/out');
await sftp.end();
```

Transfers keep 16 requests of 32 KiB in flight, so they move at the speed
the round trip allows while holding at most half a megabyte, never the file.
`get` and `list` collect into memory (`get` refuses past 64 MiB). Errors are
`SftpError`s with the server's `code`: 2 no such file, 3 permission denied.
`overwrite: true` needs `posix-rename@openssh.com`, which OpenSSH offers.

### Port forwarding and jump hosts

`forward(host, port)` opens a TCP connection from the server, as `ssh -L`
does, and hands it back as a `ByteSocket`:

```ts
const database = await client.forward('10.0.0.5', 5432);
// database.readable, database.writable, database.close()
```

That is also how a host behind a bastion is reached. Every hop has its own
host key and credentials, checked on its own:

```ts
const target = await connect({
  host: '10.0.0.7',
  username: 'app',
  auth: { kind: 'privateKey', privateKey: env.APP_KEY },
  hostKeyFingerprint: 'SHA256:…target…',
  jump: [
    {
      host: 'bastion.example.com',
      username: 'jump',
      auth: { kind: 'privateKey', privateKey: env.JUMP_KEY },
      hostKeyFingerprint: 'SHA256:…bastion…',
    },
  ],
});
await target.close(); // closes the bastion connection too
```

or `await bastion.jump({ host, port, username, auth, hostKeyFingerprint })`.
A target may sit behind at most three bastions.

### Cloudflare Tunnel

A server published with `cloudflared tunnel` and an `ssh://` ingress is
reached the way `cloudflared access ssh` reaches it, over a WebSocket:

```ts
const client = await connect({
  tunnel: {
    hostname: 'ssh.example.com',
    // For an application behind Cloudflare Access:
    serviceToken: { clientId: env.CF_ACCESS_CLIENT_ID, clientSecret: env.CF_ACCESS_CLIENT_SECRET },
  },
  username: 'deploy',
  auth: { kind: 'privateKey', privateKey: env.KEY },
  hostKeyFingerprint: 'SHA256:…',
});
```

`accessToken` sends a user's Access JWT instead, `destination` addresses a
tunnel in bastion mode, and `headers` adds anything else. The host key is
checked as on any other connection: the tunnel carries bytes, and proves
nothing about the server.

`openTunnel(options)` returns the tunnel alone, as a `ByteSocket`.
`webSocketStream(ws)` makes one from any open WebSocket, in Node 22 or a
browser too.

### Reaching servers from a Worker

A deployed Worker may not open a TCP connection to Cloudflare's own address
ranges, so a host whose DNS record is proxied by Cloudflare cannot be
reached on port 22. On port 22 the platform says only "proxy request
failed, cannot connect to the specified address", which it also says for
an address that is simply down, so `openSocket` adds a hint rather than a
verdict. Cloudflare Tunnel is the way to such a host. `wrangler dev` does not
enforce the block.

Every `connect()` to a socket counts as a subrequest of the request that
opened it.

### A terminal in the browser

[`examples/terminal`](examples/terminal) puts xterm.js on a page and the
shell in a Durable Object, one per tab: keystrokes go to `shell.stdin`,
output comes back from `shell.stdout`, and xterm.js's resize becomes
`shell.resize()`. It is checked in Chromium, typing, resizing, `top` and
3 MB of output included, and its README has what a session cost when
measured on a deployed Worker: 17 ms of CPU to connect and log in, about
20 ms per megabyte of output.

Keep the server, the user and the key in the Worker's configuration, not in
what the browser sends, or the page is an open SSH proxy. In the Durable
Object set the server-side WebSocket's `binaryType` to `'arraybuffer'`: on a
recent compatibility date binary messages arrive as Blobs, and a
`Uint8Array` made from a Blob is empty.

## Servers it has been run against

Every one of these, before 0.2.0, through the checks under
[Proving it](#proving-it):

| Server                                               | Result                                                                    |
| ---------------------------------------------------- | ------------------------------------------------------------------------- |
| OpenSSH 10.3 (Alpine)                                | everything                                                                |
| OpenSSH 9.9 (Rocky Linux 9, crypto-policies DEFAULT) | everything                                                                |
| OpenSSH 9.2 (Debian 12)                              | everything                                                                |
| OpenSSH 8.2 (Ubuntu 20.04)                           | everything                                                                |
| OpenSSH 7.9 (Debian 10)                              | everything                                                                |
| OpenSSH 7.4 (CentOS 7)                               | everything, without strict KEX, which it predates                         |
| Dropbear 2026.91 (Alpine)                            | everything it offers: curve25519 or ECDH, AES-CTR with hmac-sha2-256      |
| MikroTik RouterOS 7.24.5 (CHR)                       | commands, SFTP and the console; curve25519, AES-GCM or -CTR, rsa-sha2-256 |
| test.rebex.net (Rebex SSH 8)                         | commands and SFTP, from a deployed Worker                                 |
| MikroTik RouterOS 6.49.23 (CHR)                      | commands and SFTP, strong-crypto off and on; group exchange, hmac-sha1    |

OpenSSH 7.4 lists only `rsa-sha2-256,rsa-sha2-512` in server-sig-algs and
accepts ed25519 and ECDSA keys all the same, so that list decides between
RSA's hashes and nothing else.

RouterOS 6 offers no elliptic curve and, even with strong-crypto, no MAC
but hmac-sha1 and hmac-md5, so it is reached with
diffie-hellman-group-exchange-sha256, AES-CTR and hmac-sha1. The CHR image
showed a new RSA host key on every connection, so it cannot be pinned by
fingerprint; a router doing that can only be checked with `verifyHostKey`
and a policy of your own, or by fixing the router.

RouterOS's console asks the terminal where its cursor is (`ESC [6n`) and
waits for the answer; a terminal emulator such as xterm.js gives it, a
script reading `stdout` has to. For scripts, `exec` with a RouterOS command
needs none of that.

## Algorithms

Offered in this order; the first the server also has is used. Each name can
be narrowed or reordered with `algorithms: { kex, hostKey, cipher, mac }`.

|               |                                                                                                                                                                                                |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Key exchange  | curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, diffie-hellman-group-exchange-sha256 (2048–4096-bit groups), diffie-hellman-group16-sha512, diffie-hellman-group14-sha256 |
| Host keys     | ssh-ed25519, ecdsa-sha2-nistp256, -nistp384, -nistp521, rsa-sha2-512, rsa-sha2-256 (RSA of 1024 bits or more)                                                                                  |
| Ciphers       | aes256-gcm@openssh.com, aes128-gcm@openssh.com, aes256-ctr, aes192-ctr, aes128-ctr                                                                                                             |
| MACs, for CTR | hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com, hmac-sha2-256, hmac-sha2-512, hmac-sha1-etm@openssh.com, hmac-sha1                                                               |
| Client keys   | ssh-ed25519, rsa-sha2-512, rsa-sha2-256, ecdsa-sha2-nistp256, -nistp384, -nistp521                                                                                                             |
| Extensions    | strict KEX (kex-strict-c-v00@openssh.com, the Terrapin fix) when the server offers it; ext-info-c for server-sig-algs                                                                          |
| Compression   | none                                                                                                                                                                                           |

Not offered: chacha20-poly1305@openssh.com (WebCrypto has no ChaCha20),
the sntrup761 and ML-KEM hybrids (no WebCrypto primitive yet; workerd had
no ML-KEM on 2026-10-24), the SHA-1 key exchanges and signatures, and CBC.

The finite-field exchanges are BigInt arithmetic, as WebCrypto has none,
and cost more: two modular exponentiations of about 3, 6 and 9 ms each in
Node for 2048-, 3072- and 4096-bit groups, and about 30 ms of CPU for a
whole 4096-bit exchange in a deployed Worker, against about 5 ms for
curve25519 (2026-10-24). They come after the curves, so only a server
without a curve, such as RouterOS 6, gets them; OpenSSH 10 no longer offers
them at all.

Re-keying is started by either side: by the server whenever it likes, and by
the client after 1 GiB either way (`rekeyAfterBytes`).

## Proving it

```
make check            # typecheck, lint, the unit tests
make matrix           # Docker: six OpenSSH builds, Dropbear, a bastion
make routeros         # MikroTik RouterOS 7 and 6, under QEMU (needs /dev/kvm)
make live             # the probe Worker, deployed, against real servers
make consumer-check   # the packed package, typechecked as an installing Worker would
```

The unit tests check the packet ciphers against a second implementation on
Node's OpenSSL, every key format against keys `ssh-keygen` and `openssl`
wrote, Ed25519 against RFC 8032's vector, mpints against RFC 4251's,
bcrypt_pbkdf against the OpenBSD port on npm, and the key exchange's state
machine against a server in memory: a host key refused before NEWKEYS,
strict KEX violations, a changed key on re-keying.

What a unit test cannot catch — a stalled window, a counter off by one —
shows only as a hang or a truncation against a real server, so the matrix
runs every key exchange and cipher pairing, every host and client key type,
password, keyboard-interactive and key-then-code logins, 3 MB of output,
re-keying from both sides mid-transfer, keepalives against a server frozen
with `docker pause`, a pty shell and its resize, port forwarding, 5 MB
through SFTP both ways, and jumps through a bastion to each of the others.
For 0.2.0 it was 947 passed, none failed, and 173 not offered by the
server: Dropbear has no GCM, no encrypt-then-MAC, no hmac-sha2-512, no
aes192-ctr, no rsa-sha2-512 and of the finite-field exchanges only group14,
and OpenSSH 10.3 has none of them.

`wrangler dev` does not enforce the platform's limits, so the probe Worker
in `dev/` is deployed and run against test.rebex.net over a TCP socket, and
against the matrix's servers through a Cloudflare quick tunnel, the
finite-field exchanges and keepalives included: for 0.2.0, 29 passed, none
failed.

RouterOS is checked on its own (`make routeros`), since its shell is not a
Unix one: commands, 800 KB of output, SFTP, and its console in a pty on
7.24.5; commands and SFTP on 6.49.23, with strong-crypto off and then on.

## Working on it

`make` lists the targets. `src/workers/` is the only place that names a
runtime; lint keeps everything else on `ByteSocket` and WebCrypto.

A release is a version tag: `.github/workflows/release.yml` checks the tagged
commit, stages it on npm with provenance, and opens the GitHub release; it
goes live once a maintainer approves it on npmjs.com. The matrix and the live
check need Docker and a Cloudflare account, so they run before the tag, not
in the workflow.

Why something was put in or left out is in
[docs/decisions.md](docs/decisions.md).

## Licence

MIT — see [LICENSE](LICENSE).
