/**
 * A terminal in the browser: xterm.js on the page, undershell in a Durable
 * Object, one SSH shell per WebSocket. See README.md beside this file.
 *
 * In a project of your own, import from '@workeryard/undershell/workers';
 * this example imports the repository's source so it runs from a checkout.
 */

import { page } from './page';
import type { Env } from './session';

export { TerminalSession } from './session';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/') {
      return new Response(page, {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'content-security-policy':
            "default-src 'none'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
            "style-src 'unsafe-inline' https://cdn.jsdelivr.net; connect-src 'self'; font-src 'self'; " +
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
        },
      });
    }
    if (url.pathname === '/session') {
      if (request.headers.get('upgrade') !== 'websocket')
        return new Response('expected a WebSocket', { status: 426 });
      // Only this page may open a session; the token is still checked inside.
      const origin = request.headers.get('origin');
      if (origin !== url.origin) return new Response('forbidden', { status: 403 });
      // A fresh object per session: nothing is shared between two terminals.
      return env.TERMINAL.get(env.TERMINAL.newUniqueId()).fetch(request);
    }
    return new Response('not found', { status: 404 });
  },
} satisfies ExportedHandler<Env>;
