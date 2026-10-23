# A terminal in the browser

xterm.js on a page, undershell in a Durable Object, one SSH shell per tab.

```
xterm.js  ⇄  WebSocket  ⇄  Worker  →  TerminalSession (Durable Object)  ⇄  undershell  ⇄  sshd
```

- `worker.ts` serves the page and hands each WebSocket to a fresh
  `TerminalSession`, refusing any other origin.
- `session.ts` checks the token, connects, opens a shell with a pty, and
  pipes: keystrokes in as binary messages, resizes as JSON, output back as
  binary. It closes after 15 minutes without input (`IDLE_MINUTES`).
- `page.ts` is the page: xterm.js 6 and its fit addon from jsDelivr, pinned
  and checked by SRI hashes.

The server, its user and its host key are configuration, never something
the browser chooses: a page that let it would be an open SSH proxy. The
private key and the token are secrets.

## Running it

```sh
cd examples/terminal
cp /dev/null .dev.vars && chmod 600 .dev.vars
# TERMINAL_TOKEN, SSH_KEY (the private key, quoted, newlines kept),
# SSH_HOST, SSH_PORT, SSH_USER, SSH_HOST_KEY: see wrangler.jsonc and session.ts
npx wrangler dev --port 8820
```

To deploy: set `vars` in `wrangler.jsonc`, then `npx wrangler secret put
TERMINAL_TOKEN` and `npx wrangler secret put SSH_KEY < key`, then `npx
wrangler deploy`. For a server behind Cloudflare Tunnel set `SSH_TUNNEL` to
its hostname instead of `SSH_HOST`.

It imports the repository's `src/`; in a project of your own, import
`@workeryard/undershell/workers`.

## Checking it

`check.ts` drives the page in Chromium as a person would: another origin
refused, a wrong token refused, the shell opened, typing, `TERM` and the
size set, a resize reaching the pty, `top` drawn and quit, 3 MB printed to
the screen whole, and `exit`.

```sh
TERMINAL_URL=http://localhost:8820 TERMINAL_TOKEN=… CHROME=/path/to/chrome \
  pnpm tsx examples/terminal/check.ts
```

On 2026-10-24 it passed 8 of 8 under `wrangler dev` and deployed.

## What a session costs

`measure.ts` runs each kind of work as its own session against a deployed
copy and reads the CPU Cloudflare reports from `wrangler tail`. Measured on
2026-10-24, two runs, against OpenSSH 10.3 through a Cloudflare Tunnel:

| One whole session           | CPU        | Wall      |
| --------------------------- | ---------- | --------- |
| connect, log in, exit       | 17 ms      | 1.1–1.3 s |
| 200 keystrokes, 20 commands | 148–172 ms | 5.4–5.6 s |
| 3 MB printed                | 131–145 ms | 1.3–2.1 s |
| 30 MB printed               | 563–599 ms | 6.6–6.7 s |

About 20 ms of CPU per megabyte of output and under a millisecond per
keystroke. Against the limits Cloudflare documents (Workers limits page,
updated 2026-10-12; Durable Objects limits, updated 2026-06-01):

- **Duration** has no limit while the browser stays connected. A runtime
  update or a deploy gives open connections up to 20 minutes, then may end
  them: run `tmux` on the server so a session survives a reconnect.
- **CPU** is 30 s by default on Workers Paid, raised here to 5 minutes, and
  a Durable Object's budget starts again with each WebSocket message. Even
  a single burst of output would need gigabytes to reach it. The Free plan's
  10 ms is less than the handshake alone.
- **Billing**: a Durable Object holding an open SSH connection cannot
  hibernate, so it is billed for as long as the session is open. The idle
  limit is what keeps a forgotten tab from costing anything.
