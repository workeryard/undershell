/**
 * How much CPU a terminal session costs the Durable Object, by kind of
 * work: run each scenario as its own session through a real Chromium, and
 * read the cpuTime Cloudflare reports for it from `wrangler tail`.
 *
 *   (cd examples/terminal && npx wrangler tail --format json > tail.jsonl) &
 *   TERMINAL_URL=… TERMINAL_TOKEN=… CHROME=… pnpm tsx examples/terminal/measure.ts tail.jsonl
 *
 * Sessions run one after another, so the n-th TerminalSession event is the
 * n-th scenario.
 */

import { readFileSync } from 'node:fs';
import puppeteer, { type Page } from 'puppeteer-core';

const url = process.env.TERMINAL_URL!;
const token = process.env.TERMINAL_TOKEN!;
const tailFile = process.argv[2];
if (!url || !token || !process.env.CHROME || !tailFile)
  throw new Error('TERMINAL_URL, TERMINAL_TOKEN, CHROME and a tail file are needed');

const screen = (page: Page) =>
  page.evaluate(() =>
    [...document.querySelectorAll('.xterm-rows > div')]
      .map((row) => row.textContent ?? '')
      .join('\n'),
  );
async function until(page: Page, pattern: RegExp, ms = 180_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!pattern.test(await screen(page))) {
    if (Date.now() > deadline) {
      throw new Error(
        `waited for ${pattern}; the screen ends ${JSON.stringify((await screen(page)).trim().slice(-200))}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}
const print = (megabytes: number) =>
  `clear; head -c ${megabytes * 1_000_000} /dev/zero | tr '\\0' a | fold -w 100; echo; echo printed-${megabytes}\n`;

const SCENARIOS: { name: string; run(page: Page): Promise<void> }[] = [
  { name: 'connect, log in, exit', run: async () => {} },
  {
    name: '200 keystrokes, a command at a time',
    run: async (page) => {
      for (let index = 0; index < 20; index++) {
        await page.keyboard.type(`echo line-${String(index).padStart(3, '0')}\n`, { delay: 15 });
      }
      await until(page, /^line-019\s*$/m);
    },
  },
  {
    name: '3 MB printed',
    run: async (page) => (await page.keyboard.type(print(3)), until(page, /^printed-3\s*$/m)),
  },
  {
    name: '30 MB printed',
    run: async (page) => (await page.keyboard.type(print(30)), until(page, /^printed-30\s*$/m)),
  },
];

const browser = await puppeteer.launch({
  executablePath: process.env.CHROME,
  headless: true,
  args: ['--no-sandbox'],
});
const walls: number[] = [];
try {
  for (const scenario of SCENARIOS) {
    const page = await browser.newPage();
    await page.setViewport({ width: 1000, height: 600 });
    await page.goto(url);
    await page.evaluate((value) => sessionStorage.setItem('token', value), token);
    const started = Date.now();
    await page.goto(url);
    await until(page, /[$#] *$/m);
    await scenario.run(page);
    await page.keyboard.type('exit\n');
    await until(page, /exited|disconnected/);
    walls.push(Date.now() - started);
    await page.close();
    // Let the session's event reach the tail before the next one starts.
    await new Promise((resolve) => setTimeout(resolve, 4000));
  }
} finally {
  await browser.close();
}

await new Promise((resolve) => setTimeout(resolve, 15_000));
const events: { cpuTime: number; wallTime: number; entrypoint?: string; eventTimestamp: number }[] =
  [];
let buffer = '';
for (const line of readFileSync(tailFile, 'utf8').split('\n')) {
  buffer += line + '\n';
  try {
    events.push(JSON.parse(buffer) as (typeof events)[number]);
    buffer = '';
  } catch {
    // A JSON object over several lines; keep reading.
  }
}
const sessions = events
  .filter((event) => event.entrypoint === 'TerminalSession')
  .sort((a, b) => a.eventTimestamp - b.eventTimestamp);
SCENARIOS.forEach((scenario, index) => {
  const event = sessions[index];
  console.log(
    `${scenario.name.padEnd(38)} cpu ${String(event?.cpuTime ?? '?').padStart(5)} ms   wall ${String(event?.wallTime ?? '?').padStart(6)} ms   (browser saw ${walls[index]} ms)`,
  );
});
