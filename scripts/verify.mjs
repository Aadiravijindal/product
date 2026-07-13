#!/usr/bin/env node
/**
 * Recrypt one-command verification.
 *
 *   npm run verify            # boots a production server, runs every check, tears down
 *   npm run verify -- --base http://localhost:3000   # run against an already-running server
 *
 * Exit code 0 = everything passed, 1 = at least one failure. Zero npm
 * dependencies — uses only Node's built-in fetch and child_process.
 */

import { spawn } from 'node:child_process';
import { runChecks } from './lib/checks.mjs';

const args = process.argv.slice(2);
const baseFlag = args.indexOf('--base');
const externalBase = baseFlag !== -1 ? args[baseFlag + 1] : null;
const PORT = process.env.VERIFY_PORT || 3999;
const base = externalBase || `http://localhost:${PORT}`;

const c = {
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};

async function waitForHealth(url, timeoutMs = 45_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await fetch(url + '/api/health');
      if (r.ok) return true;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  return false;
}

let server = null;
function startServer() {
  console.log(c.dim(`booting production server on port ${PORT} …`));
  server = spawn('npm', ['run', 'start', '--', '-p', String(PORT)], {
    stdio: ['ignore', 'ignore', 'inherit'],
    env: { ...process.env, PORT: String(PORT) },
  });
  server.on('exit', (code) => {
    if (code && code !== 0 && !shuttingDown) {
      console.error(c.red(`\nserver exited early (code ${code}). Did you run "npm run build" first?`));
      process.exit(1);
    }
  });
}

let shuttingDown = false;
function stopServer() {
  shuttingDown = true;
  if (server && !server.killed) server.kill('SIGTERM');
}
process.on('exit', stopServer);
process.on('SIGINT', () => { stopServer(); process.exit(130); });

(async () => {
  console.log(c.bold('\n  Recrypt verification\n'));

  if (!externalBase) {
    startServer();
    const up = await waitForHealth(base);
    if (!up) {
      console.error(c.red('server did not become healthy in time.'));
      console.error(c.dim('run "npm run build" first, then "npm run verify".'));
      process.exit(1);
    }
  } else {
    const up = await waitForHealth(base, 5000);
    if (!up) {
      console.error(c.red(`no server responding at ${base}. Start it, or drop --base to auto-boot.`));
      process.exit(1);
    }
  }

  const health = await (await fetch(base + '/api/health')).json();
  console.log(
    c.dim(`  target ${base} · ${health.detectionPatterns} detection patterns · live analysis: `) +
      (health.liveAnalysis ? c.green('ON (Claude API)') : c.dim('OFF (built-in engine)')) +
      '\n'
  );

  const t = await runChecks(base, {
    section: (name) => console.log(c.cyan(`  ── ${name}`)),
  });

  for (const r of t.results) {
    if (r.passed) console.log('     ' + c.green('✓') + ' ' + c.dim(r.name));
    else console.log('     ' + c.red('✗ ' + r.name) + (r.extra ? c.red('  — ' + r.extra) : ''));
  }

  const line = `${t.passed} passed, ${t.failed} failed`;
  console.log('\n  ' + (t.failed === 0 ? c.green(c.bold('✔ ' + line)) : c.red(c.bold('✗ ' + line))) + '\n');

  if (health.liveAnalysis) {
    console.log(c.dim('  note: live analysis is ON — the checks above exercised the real Claude two-agent pipeline.\n'));
  } else {
    console.log(c.dim('  note: live analysis is OFF — set ANTHROPIC_API_KEY to verify the live pipeline too.\n'));
  }

  stopServer();
  process.exit(t.failed === 0 ? 0 : 1);
})().catch((err) => {
  console.error(c.red('\nverification crashed: ' + (err?.message || err)));
  stopServer();
  process.exit(2);
});
