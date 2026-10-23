/**
 * Drives the terminal page in a real Chromium, the way a person would:
 * types into xterm.js, reads what it draws, resizes the window, runs a
 * full-screen program, and is refused with a wrong token.
 *
 *   TERMINAL_URL=http://localhost:8820 TERMINAL_TOKEN=… CHROME=/path/to/chrome \
 *     pnpm tsx examples/terminal/check.ts
 */

import { get as httpGet } from 'node:http';
import { get as httpsGet } from 'node:https';
import puppeteer, { type Page } from 'puppeteer-core';

const url = process.env.TERMINAL_URL ?? 'http://localhost:8820';
const token = process.env.TERMINAL_TOKEN;
const chrome = process.env.CHROME;
if (!token || !chrome) throw new Error('TERMINAL_TOKEN and CHROME are needed');

let failed = 0;
async function check(name: string, body: () => Promise<string | void>): Promise<void> {
  const started = Date.now();
  try {
    const detail = (await body()) ?? '';
    console.log(`pass ${name.padEnd(48)} ${detail} (${Date.now() - started} ms)`);
  } catch (error) {
    failed++;
    console.log(
      `FAIL ${name.padEnd(48)} ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** What xterm.js has drawn, row by row, as text. */
const screen = (page: Page) =>
  page.evaluate(() =>
    [...document.querySelectorAll('.xterm-rows > div')]
      .map((row) => row.textContent ?? '')
      .join('\n'),
  );

async function until(page: Page, pattern: RegExp, ms = 20_000): Promise<string> {
  const deadline = Date.now() + ms;
  for (;;) {
    const text = await screen(page);
    if (pattern.test(text)) return text;
    if (Date.now() > deadline)
      throw new Error(
        `waited for ${pattern}; the screen ends ${JSON.stringify(text.trim().slice(-160))}`,
      );
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
}

const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: true,
  args: ['--no-sandbox'],
});
try {
  const page = await browser.newPage();
  await page.setViewport({ width: 1000, height: 600 });

  await check('another origin cannot open a session', async () => {
    // node:http, as fetch refuses an Upgrade header of its own.
    const target = new URL('/session', url);
    const get = target.protocol === 'https:' ? httpsGet : httpGet;
    const status = await new Promise<number>((resolve, reject) => {
      const request = get(
        target,
        {
          headers: {
            connection: 'upgrade',
            upgrade: 'websocket',
            origin: 'https://example.com',
            'sec-websocket-version': '13',
            'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
          },
        },
        (response) => {
          response.resume();
          resolve(response.statusCode ?? 0);
        },
      );
      request.on('upgrade', () => resolve(101));
      request.on('error', reject);
    });
    if (status !== 403) throw new Error(`answered ${status}`);
    return '403';
  });

  await check('a wrong token is refused', async () => {
    await page.goto(url);
    await page.type('#token', 'not-the-token');
    await page.click('button');
    await until(page, /the token is not right/);
    await page.waitForSelector('#login:not([hidden])');
  });

  await check('the right token opens a shell', async () => {
    await page.evaluate(() => sessionStorage.clear());
    await page.goto(url);
    await page.type('#token', token);
    await page.click('button');
    await until(page, /connected/);
    await until(page, /[$#] *$/m);
    return 'prompt drawn';
  });

  await check('typing reaches the shell, TERM and size are set', async () => {
    await page.keyboard.type('echo "T=$TERM"; stty size\n');
    const text = await until(page, /T=xterm-256color[\s\S]*\n\s*\d+ \d+/);
    return text.match(/\n\s*(\d+ \d+)\s*\n/)?.[1] ?? '';
  });

  await check('resizing the window resizes the pty', async () => {
    await page.setViewport({ width: 700, height: 420 });
    await new Promise((resolve) => setTimeout(resolve, 500));
    const cols = await page.evaluate(() =>
      Math.floor(document.querySelector('.xterm-screen')!.getBoundingClientRect().width),
    );
    await page.keyboard.type('echo "resized $(stty size)"\n');
    const text = await until(page, /^resized \d+ \d+\s*$/m);
    const [rows, columns] = text
      .match(/^resized (\d+) (\d+)\s*$/m)!
      .slice(1)
      .map(Number);
    if (!rows || !columns || columns > 100)
      throw new Error(`stty says ${rows} ${columns} after shrinking to ${cols}px`);
    return `${rows} rows × ${columns} cols`;
  });

  await check('a full-screen program draws and quits', async () => {
    await page.keyboard.type('top\n');
    await until(page, /Mem:|MiB Mem|load average/);
    await page.keyboard.type('q');
    await page.keyboard.type('echo top-quit\n');
    await until(page, /top-quit\s*\n/);
  });

  await check('3 MB printed to the screen arrives whole', async () => {
    // 30,000 lines of 100 characters, through the pty, the WebSocket and xterm.js.
    await page.keyboard.type(
      "clear; head -c 3000000 /dev/zero | tr '\\0' a | fold -w 100 | nl -ba | tail -c 3000000 | cat; echo done-3mb\n",
    );
    await until(page, /^done-3mb\s*$/m, 120_000);
    const last = await page.evaluate(() => {
      const rows = [...document.querySelectorAll('.xterm-rows > div')].map(
        (row) => row.textContent ?? '',
      );
      return rows.filter((row) => /^\s*\d+\s+a+/.test(row)).at(-1) ?? '';
    });
    return `last numbered line on screen: ${last.trim().split(/\s+/)[0] ?? '?'}`;
  });

  await check('exit closes the session', async () => {
    await page.keyboard.type('exit\n');
    await until(page, /exited|disconnected/);
  });
} finally {
  await browser.close();
}
console.log(failed ? `\n${failed} failed` : '\nall passed');
process.exitCode = failed ? 1 : 0;
