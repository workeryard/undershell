#!/usr/bin/env bash
# Typechecks the package as a project that installs it sees it: packed into a
# tarball, installed into a throwaway Worker project, imported and compiled
# against @cloudflare/workers-types. A link or this repository's own
# typecheck cannot show what goes wrong only inside node_modules; underfetch
# 0.1.0 shipped a typecheck that failed exactly there.
#
#   make consumer-check
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
types="$root/.cache/workers-types/node_modules/@cloudflare/workers-types"
[ -d "$types" ] || { echo "run make typecheck-workers once first, to fetch the Workers types"; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tarball="$(cd "$root" && npm pack --silent --pack-destination "$work")"

mkdir -p "$work/app/src" "$work/app/node_modules/@cloudflare"
cd "$work/app"
echo '{ "name": "consumer", "private": true, "type": "module" }' > package.json
pnpm add --silent "$work/$tarball" >/dev/null
ln -s "$types" node_modules/@cloudflare/workers-types

# What callers write: a command, a shell, SFTP, a jump, a tunnel.
cat > src/index.ts <<'TS'
import { connect, openTunnel, type WorkersConnectOptions } from '@workeryard/undershell/workers';
import { SshClient, parsePrivateKey, webSocketStream, type HostKey } from '@workeryard/undershell';

interface Env {
  SSH_KEY: string;
}

export default {
  async fetch(_request: Request, env: Env): Promise<Response> {
    const options: WorkersConnectOptions = {
      host: 'example.com',
      username: 'deploy',
      auth: [
        { kind: 'privateKey', privateKey: await parsePrivateKey(env.SSH_KEY) },
        { kind: 'keyboardInteractive', respond: (challenge) => challenge.prompts.map(() => '123456') },
      ],
      hostKeyFingerprint: 'SHA256:abc',
      verifyHostKey: (key: HostKey) => key.algorithm === 'ssh-ed25519',
      jump: [{ host: 'bastion', username: 'jump', auth: { kind: 'password', password: 'x' }, hostKeyFingerprint: 'SHA256:def' }],
    };
    const client: SshClient = await connect(options);
    const result = await client.exec('uptime');
    const shell = await client.shell({ pty: { cols: 80, rows: 24 } });
    await shell.resize(100, 30);
    const sftp = await client.sftp();
    await sftp.put('/tmp/x', sftp.createReadStream('/etc/hostname'));
    for await (const entry of sftp.readdir('/tmp')) void entry.name;
    await sftp.end();
    await client.close();
    const tunnel = await openTunnel({ hostname: 'ssh.example.com', serviceToken: { clientId: 'a', clientSecret: 'b' } });
    void tunnel;
    void webSocketStream;
    return Response.json({ stdout: result.stdout, exit: result.exitStatus });
  },
};
TS

config() {
  cat <<JSON
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "lib": ["ES2023"],
    "types": ["@cloudflare/workers-types"],
    "strict": true,
    "skipLibCheck": true,
    "noEmit": true
  },
  "include": ["src"]
}
JSON
}
config > tsconfig.json

"$root/node_modules/.bin/tsc" -p tsconfig.json
echo "consumer typecheck passes for $tarball"
