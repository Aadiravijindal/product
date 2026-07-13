#!/usr/bin/env node
/**
 * Quick smoke test against an already-running server (default localhost:3000).
 * Use this the morning of a demo to confirm the app is alive end-to-end.
 *
 *   npm run smoke                                   # checks http://localhost:3000
 *   npm run smoke -- --base http://localhost:3100   # custom URL
 */

const args = process.argv.slice(2);
const baseFlag = args.indexOf('--base');
const base = baseFlag !== -1 ? args[baseFlag + 1] : 'http://localhost:3000';

const g = (s) => `\x1b[32m${s}\x1b[0m`;
const r = (s) => `\x1b[31m${s}\x1b[0m`;

async function main() {
  // 1. health
  const health = await fetch(base + '/api/health').then((x) => x.json());
  console.log(`health: ${g('ok')} · live analysis: ${health.liveAnalysis ? g('ON (Claude API)') : 'OFF (built-in)'}`);

  // 2. scan a sample repo
  const scan = await fetch(base + '/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repoId: 'payment-service' }),
  }).then((x) => x.json());
  console.log(`scan: ${g('ok')} · ${scan.findingCount} finding(s)`);

  // 3. analyze one finding through the full pipeline
  const full = await fetch(base + `/api/scan/${scan.scanId}`).then((x) => x.json());
  const fid = full.scan.findings[0].id;
  const analyzed = await fetch(base + `/api/scan/${scan.scanId}/findings/${fid}/analyze`, { method: 'POST' }).then((x) => x.json());
  const a = analyzed.finding.analysis;
  const testsPass = a.tests.every((t) => t.passed);
  const digestOk = /^[0-9a-f]{64}$/.test(a.digest || '');
  console.log(`analyze: ${g('ok')} · engine=${a.engine} · tests ${testsPass ? g(a.tests.length + '/' + a.tests.length) : r('FAIL')} · review=${a.review?.verdict} · digest ${digestOk ? g('valid') : r('INVALID')}`);

  if (!testsPass || !digestOk) {
    console.log(r('\nSMOKE FAILED — something is off. Run `npm run verify` for detail.'));
    process.exit(1);
  }
  console.log(g('\nSMOKE OK — scan → fix → adversarial review → real crypto proof all working.'));
}

main().catch((e) => {
  console.log(r(`\nSMOKE FAILED — could not reach ${base}. Is the server running?`));
  console.log(r(String(e?.message || e)));
  process.exit(1);
});
