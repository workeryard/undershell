# Changelog

Notable changes, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
[Semantic Versioning](https://semver.org/) — until 1.0.0, a minor version may
change the API.

## 0.1.0 — 2026-10-21

The first release, from the SSH client Flowker carried in `packages/ssh`.
That client ran one command or one SFTP session per connection, with
curve25519-sha256, aes256-gcm@openssh.com and ed25519 client keys.

### Connections

- One connection carries many channels at once: commands, shells, SFTP
  sessions and forwarded ports, each under its own flow control. Room is
  given back to the server as the reader takes data, so a slow reader slows
  the server instead of filling memory.
- Over any `ByteSocket`; `./workers` adds TCP from `cloudflare:sockets`,
  with a connect timeout and a hint when the address may be Cloudflare's, and
  Cloudflare Tunnel over a WebSocket, with Zero Trust service tokens, an
  Access token or a bastion-mode destination.
- Jump hosts through `direct-tcpip`, each hop with its own host key and
  credentials, up to three bastions.

### Algorithms

- Key exchange: curve25519-sha256 (and its @libssh.org name) and
  ecdh-sha2-nistp256.
- Ciphers: AES-256 and AES-128 GCM; AES-256, -192 and -128 CTR with
  HMAC-SHA2-256 or -512, encrypt-then-MAC or not.
- Host keys: ed25519, ECDSA on P-256, P-384 and P-521, and rsa-sha2-512/256.
- Re-keying started by the server or by the client (after 1 GiB, or
  `rekeyAfterBytes`), refusing a changed host key; strict KEX whenever the
  server offers it.

### Host keys

- Pinned by fingerprint, several during a rotation, or checked by
  `verifyHostKey`, or both. With neither, `connect` refuses to start.

### Authentication

- Several methods tried in order, so a key and then a one-time code covers
  2FA; `AuthenticationError` says what the server would still accept.
- Client keys: ed25519, RSA and ECDSA, from OpenSSH files (with a
  passphrase, AES-CTR or AES-GCM), PKCS#1, SEC1 and unencrypted PKCS#8.
- keyboard-interactive (RFC 4256), answered by a callback; `none`; banners.

### Sessions

- `exec` with stdin, an output cap that drains rather than stalls, an
  `AbortSignal` and environment variables; `spawn` for the streams.
- `shell` with a pty, `resize` (window-change) and `signal`.
- `forward` for local port forwarding, as a `ByteSocket`.

### SFTP

- Streaming reads and writes, several requests in flight, never the whole
  file in memory; `get` and `put` on top of them.
- `stat`, `lstat`, `mkdir`, `rmdir`, `remove`, `rename` (with
  posix-rename@openssh.com to replace), `realpath`, and `readdir` a page at
  a time.

### Servers

- Run against OpenSSH 10.3, 9.9 (Rocky 9), 9.2 (Debian 12), 8.2 (Ubuntu
  20.04), 7.9 (Debian 10) and 7.4 (CentOS 7), Dropbear, MikroTik RouterOS 7
  and test.rebex.net. RouterOS 6, which offers only finite-field
  Diffie-Hellman and SHA-1 MACs, is refused with an error naming what it
  offers.
- server-sig-algs decides only between RSA's hashes: OpenSSH 7.4 leaves
  ed25519 and ECDSA out of it and accepts them anyway.

### Inside

- No runtime dependencies: bcrypt_pbkdf, which passphrase-protected keys
  need, is implemented here, with Blowfish's constants worked out from π.
