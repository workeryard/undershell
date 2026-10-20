# Decisions

What was put in, what was left out, and why, so that a choice that looks
like an omission can be told from one that was made. Each entry says what
it rests on: a measurement, a server's behaviour, a specification, or the
platform's documentation. Newest first within each section.

## Taken

**server-sig-algs chooses RSA's hash and nothing else** (2026-10-21).
OpenSSH 7.4, as CentOS 7 ships it, lists only `rsa-sha2-256,rsa-sha2-512`
there and still accepts ed25519 and ECDSA keys. Filtering a key's
algorithms by the list refused every such key before it was offered; the
CentOS 7 run of the matrix showed it. OpenSSH's own client uses the list
the same narrow way.

**A hint, not a verdict, when a Worker's socket is refused** (2026-10-20).
On port 443 production refuses Cloudflare's own addresses with "…HTTP-based
service", which names the cause. On port 22 it says only "proxy request
failed, cannot connect to the specified address", and the probe Worker got
the same words for TEST-NET-1, an address nothing answers on. So that
message says the host may be behind Cloudflare and that Tunnel reaches it,
and claims no more.

**A bounded wait for a socket to open** (2026-10-20). A port that drops
packets never answers, and `opened` never settled: the live check hung on
one until the request ran out. 10 s unless `timeoutMs` says otherwise.

**One case per request in the probe Worker** (2026-10-20). All of them in
one request ran past five minutes under `wrangler dev` and would spend the
subrequest count in production; one at a time, a hang is one failure.

**Cloudflare Tunnel as `cloudflared access ssh` reaches it** (2026-10-20):
a WebSocket to `https://<hostname>/`, the TCP bytes in binary messages,
`Cf-Access-Token` for a user's token, `Cf-Access-Jump-Destination` for
bastion mode, and Access's own service-token headers. Read in cloudflared's
`carrier` package, and run from a deployed Worker through a quick tunnel.

**Our own bcrypt_pbkdf** (2026-10-20). The npm package Flowker used is
CommonJS on tweetnacl, which reaches for `require('crypto')`; a library
shipped as TypeScript for Workers should not need a bundler's help with
that. Blowfish's tables are π's hexadecimal digits, worked out by
`scripts/blowfish-constants.ts` rather than pasted, and the derivation is
checked byte for byte against the npm package, which stays a development
dependency.

**One reader, many channels** (2026-10-20). Flowker's client read the
connection from whichever call was waiting, which allowed one channel at a
time. A pump now hands each message to its channel, and a channel gives
its window back as the reader takes data, not as data arrives, so a slow
reader holds the server to one window of memory. The pump never waits on
a send: a send can be held by a key exchange that only the pump can finish.

**Host keys pinned or checked, never accepted** (2026-10-20). Flowker
required a fingerprint; a `verifyHostKey` callback is added for callers
with their own known_hosts, and with neither `connect` refuses to start.
Trust on first use is for a person at a prompt, and a Worker has none.

**Strict KEX whenever offered** (2026-10-20), as Flowker had it: the
Terrapin fix, with sequence numbers reset on every NEWKEYS and nothing but
key exchange messages allowed during the first one.

## Left out

**RouterOS 6** (2026-10-21). It offers finite-field Diffie-Hellman only,
and by default only SHA-1 and MD5 MACs. With `strong-crypto` it would need
diffie-hellman-group-exchange-sha256, which WebCrypto has no primitive for;
it could be done with BigInt. Not in 0.1.0; RouterOS 7 works.

**ChaCha20-Poly1305** (2026-10-20). WebCrypto has neither ChaCha20 nor
Poly1305, and a JavaScript implementation would be the one cipher here not
done by the runtime. Every server seen offers AES as well.

**SHA-1: `ssh-rsa` signatures, `hmac-sha1`, the group1 and group14-sha1
exchanges** (2026-10-20). OpenSSH 8.8 stopped accepting `ssh-rsa`
signatures by default; the SHA-1 MAC and exchanges it still offers, but
always beside SHA-2 ones, on every server in the matrix. Only RouterOS 6
offered nothing else, and it is refused with an error listing what it
offered.

**The sntrup761 and ML-KEM hybrid key exchanges** (2026-10-20). OpenSSH
10 prefers mlkem768x25519-sha256, and RouterOS 7 offers it; WebCrypto has
no ML-KEM in Node or workerd yet. curve25519-sha256 is taken instead, which
every server in the matrix also offers.

**Agent forwarding, X11, remote forwarding** (2026-10-20). Each is the
server opening a channel to the client, and each is refused. Local
forwarding is enough for a jump host and for reaching a database.

**Encrypted PEM keys** (2026-10-20). OpenSSL's traditional encryption
derives its key with MD5, and PKCS#8's PBES2 needs a parser of its own.
`ssh-keygen -p` rewrites either as an OpenSSH file, which is read with its
passphrase.

## Found along the way

- RouterOS's console asks the terminal for the cursor position
  (`ESC [6n`) and waits; a fresh router then asks about its licence and
  for a new password.
- CentOS 7's sshd looks every client up in DNS and tries GSSAPI first,
  each a timeout away in a container; the matrix turns both off.
- An sshd older than 8.7 refuses its whole config over
  `KbdInteractiveAuthentication`, which it does not know.
