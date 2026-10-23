/**
 * The page: xterm.js, pinned and checked by SRI hashes, filling the window;
 * a token asked for once, kept for the tab only.
 */

export const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>terminal</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/css/xterm.css"
  integrity="sha384-n2n7twoohnW+d3myBKaUgl7DSiwidw6MkQy9oesGzkPpMjejKRR3XlnD+5yCdtBD" crossorigin="anonymous">
<style>
  html, body { margin: 0; height: 100%; background: #0d1117; color: #e6edf3; font: 14px ui-monospace, Menlo, Consolas, monospace; }
  #terminal { position: fixed; inset: 8px; }
  form { position: fixed; inset: 0; display: grid; place-items: center; background: #0d1117; }
  form[hidden] { display: none; }
  form div { display: grid; gap: 10px; width: min(360px, 90vw); }
  input, button { font: inherit; color: inherit; background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 8px 10px; }
  button { cursor: pointer; } button:hover { border-color: #8b949e; }
  label { color: #8b949e; }
</style>
</head>
<body>
<div id="terminal"></div>
<form id="login">
  <div>
    <label for="token">Token</label>
    <input id="token" type="password" autocomplete="off" required autofocus>
    <button>Open a terminal</button>
  </div>
</form>
<script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@6.0.0/lib/xterm.js"
  integrity="sha384-f/1U6Z9wM4D71a5eRXEZnyOTMOvjqxr2XLwh+Go1OvIl3L3tOcvUrzudnhbECwl4" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.11.0/lib/addon-fit.js"
  integrity="sha384-txoiwu4RR2GD3qySbaj+BbzibkLbSJRcfqGYMu6z1EqHil4A2dyBiBW5dlacG6OR" crossorigin="anonymous"></script>
<script>
'use strict';
const form = document.getElementById('login');
const tokenInput = document.getElementById('token');
const term = new Terminal({
  cursorBlink: true,
  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
  fontSize: 14,
  theme: { background: '#0d1117', foreground: '#e6edf3', cursor: '#3fb950' },
});
const fit = new FitAddon.FitAddon();
term.loadAddon(fit);
term.open(document.getElementById('terminal'));
fit.fit();

function readToken() {
  try { return sessionStorage.getItem('token') || ''; } catch { return ''; }
}
function keepToken(token) {
  try { sessionStorage.setItem('token', token); } catch {}
}

function open(token) {
  form.hidden = true;
  const ws = new WebSocket(location.origin.replace(/^http/, 'ws') + '/session');
  ws.binaryType = 'arraybuffer';
  const encoder = new TextEncoder();
  ws.onopen = () => {
    ws.send(JSON.stringify({ token, cols: term.cols, rows: term.rows }));
    term.focus();
  };
  ws.onmessage = (event) => {
    if (typeof event.data !== 'string') return term.write(new Uint8Array(event.data));
    const message = JSON.parse(event.data);
    if (message.error) {
      term.write('\\r\\n\\x1b[31m' + message.error + '\\x1b[0m\\r\\n');
      if (/token/.test(message.error)) { keepToken(''); form.hidden = false; tokenInput.focus(); }
    } else if (message.status) term.write('\\x1b[2m' + message.status + '\\x1b[0m\\r\\n');
  };
  ws.onclose = () => term.write('\\r\\n\\x1b[2m[disconnected; reload to start again]\\x1b[0m\\r\\n');
  const keys = term.onData((data) => { if (ws.readyState === 1) ws.send(encoder.encode(data)); });
  const size = term.onResize(({ cols, rows }) => { if (ws.readyState === 1) ws.send(JSON.stringify({ resize: [cols, rows] })); });
  ws.addEventListener('close', () => { keys.dispose(); size.dispose(); });
}

addEventListener('resize', () => fit.fit());
form.addEventListener('submit', (event) => {
  event.preventDefault();
  keepToken(tokenInput.value);
  open(tokenInput.value);
});
const saved = readToken();
if (saved) open(saved);
</script>
</body>
</html>
`;
