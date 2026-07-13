/**
 * Recrypt verification checks — the source of truth for "does it work".
 *
 * Zero dependencies (Node 18+ global fetch only). Exercises the full product
 * surface against a running server and returns a structured result. Used by
 * `npm run verify` (boots its own server) and `npm run smoke`.
 */

export function createRunner() {
  const results = [];
  return {
    results,
    ok(cond, name, extra = '') {
      results.push({ name, passed: Boolean(cond), extra: cond ? '' : extra });
    },
    get passed() {
      return results.filter((r) => r.passed).length;
    },
    get failed() {
      return results.filter((r) => !r.passed).length;
    },
  };
}

async function post(base, path, body) {
  const r = await fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: r.status, data: await r.json().catch(() => null) };
}
async function postRaw(base, path, raw) {
  const r = await fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: raw,
  });
  return { status: r.status, data: await r.json().catch(() => null) };
}
async function get(base, path) {
  const r = await fetch(base + path);
  return { status: r.status, data: await r.json().catch(() => null) };
}
async function scanAndGet(base, body) {
  const s = await post(base, '/api/scan', body);
  if (s.status !== 200) return { scan: null, res: s };
  const g = await get(base, `/api/scan/${s.data.scanId}`);
  return { scan: g.data?.scan, res: s };
}

/**
 * Run the full check battery against `base` (e.g. http://localhost:3999).
 * Returns the runner with .passed / .failed / .results.
 */
export async function runChecks(base, { section = () => {} } = {}) {
  const t = createRunner();

  section('health & metadata');
  {
    const { status, data } = await get(base, '/api/health');
    t.ok(status === 200 && data.status === 'ok', 'health endpoint returns ok');
    t.ok(data && data.detectionPatterns > 15, 'health reports detection-pattern count');
    t.ok(data && typeof data.liveAnalysis === 'boolean', 'health reports live-analysis availability');

    const repos = await get(base, '/api/repos');
    t.ok(repos.status === 200 && repos.data.repos.length === 3, 'lists 3 sample repos');
  }

  section('scanning — deterministic sample-repo contract');
  const expectations = {
    'payment-service': [{ file: 'payments/signer.py', risk: 'Critical', confidence: 94, usage: 'signing' }],
    'auth-service': [
      { file: 'src/main/java/com/acme/auth/AuthService.java', risk: 'High', confidence: 91, usage: 'signing' },
      { file: 'src/main/java/com/acme/auth/TlsConfig.java', risk: 'High', confidence: 61, usage: 'key_exchange' },
    ],
    'api-gateway': [{ file: 'auth.js', risk: 'High', confidence: 88, usage: 'authentication' }],
  };
  const scans = {};
  for (const [repo, expected] of Object.entries(expectations)) {
    const { scan } = await scanAndGet(base, { repoId: repo });
    scans[repo] = scan;
    t.ok(scan && scan.findings.length === expected.length, `${repo}: ${expected.length} finding(s)`, `got ${scan?.findings.length}`);
    for (const exp of expected) {
      const f = scan?.findings.find((x) => x.file === exp.file);
      t.ok(!!f, `${repo}: finding in ${exp.file}`);
      if (!f) continue;
      t.ok(f.risk === exp.risk, `${repo}/${exp.file}: risk ${exp.risk}`, `got ${f.risk}`);
      t.ok(f.confidence === exp.confidence, `${repo}/${exp.file}: confidence ${exp.confidence}`, `got ${f.confidence}`);
      t.ok(f.usageType === exp.usage, `${repo}/${exp.file}: usage ${exp.usage}`, `got ${f.usageType}`);
    }
    t.ok(scan?.stats && scan.stats.files >= 1, `${repo}: carries engine stats`);
  }
  t.ok(scans['auth-service']?.findings.some((f) => f.confidence < 85), 'seeded below-85% finding exists (manual-review path)');

  section('assurance pipeline — analyze, review, proof, exposure');
  for (const [repo, scan] of Object.entries(scans)) {
    if (!scan) continue;
    for (const f of scan.findings) {
      const { status, data } = await post(base, `/api/scan/${scan.id}/findings/${f.id}/analyze`, {});
      const a = data?.finding?.analysis;
      t.ok(status === 200 && a, `${repo}/${f.file}: analyze succeeds`);
      if (!a) continue;
      t.ok(a.classification.explanation.length > 40, `${repo}/${f.file}: plain-English explanation`);
      t.ok(/ML-(DSA|KEM)|X25519MLKEM768/.test(a.patchedCode), `${repo}/${f.file}: patch uses a NIST PQC primitive`);
      t.ok(a.tests.length >= 4 && a.tests.every((x) => x.passed), `${repo}/${f.file}: all equivalence tests pass`);
      const isKem = f.usageType === 'key_exchange';
      t.ok(a.tests.some((x) => x.name.includes(isKem ? 'ML-KEM-768' : 'ML-DSA-65')), `${repo}/${f.file}: correct PQC family tested`);
      t.ok(a.tests.some((x) => x.evidence && /\(\d+ bytes\): [0-9a-f]/.test(x.evidence)), `${repo}/${f.file}: real hex crypto evidence`);
      t.ok(a.review && ['approved', 'approved_with_notes', 'revised'].includes(a.review.verdict), `${repo}/${f.file}: independent review verdict`);
      t.ok(/^[0-9a-f]{64}$/.test(a.digest || ''), `${repo}/${f.file}: valid SHA-256 proof digest`);
      t.ok(a.hndl && typeof a.hndl.urgent === 'boolean', `${repo}/${f.file}: harvest-now-decrypt-later assessment`);
    }
  }
  // key exchange must read as already-exposed / urgent
  {
    const kex = scans['auth-service']?.findings.find((f) => f.usageType === 'key_exchange');
    const kd = await get(base, `/api/scan/${scans['auth-service'].id}`);
    const ka = kd.data.scan.findings.find((f) => f.id === kex.id).analysis;
    t.ok(ka?.hndl?.urgent === true, 'key-exchange exposure flagged urgent (harvest-now)');
  }

  section('migration plan — dependency-aware ordering');
  {
    const pr = await post(base, `/api/scan/${scans['auth-service'].id}/plan`, {});
    t.ok(pr.status === 200 && pr.data.plan.steps.length >= 2, 'plan generates ordered steps');
    t.ok(/key exchange|harvest/i.test(JSON.stringify(pr.data.plan.steps[0])), 'plan sequences key exchange first');
    const pr2 = await post(base, `/api/scan/${scans['auth-service'].id}/plan`, {});
    t.ok(pr2.data.plan.generatedAt === pr.data.plan.generatedAt, 'plan is cached / idempotent');
  }

  section('review actions — approve / escalate / reject');
  {
    const scan = scans['api-gateway'];
    const f = scan.findings[0];
    let r = await post(base, `/api/scan/${scan.id}/findings/${f.id}/action`, { action: 'approve', reviewer: 'Verify Bot' });
    t.ok(r.status === 200 && r.data.finding.status === 'migrated', 'approve → migrated, reviewer recorded');
    t.ok(r.data.finding.reviewer === 'Verify Bot', 'reviewer name stored');
    r = await post(base, `/api/scan/${scan.id}/findings/${f.id}/action`, { action: 'escalate' });
    t.ok(r.status === 200 && r.data.finding.reviewer === 'Demo User', 're-decision allowed; missing reviewer defaults');
    r = await post(base, `/api/scan/${scan.id}/findings/${f.id}/action`, { action: 'bogus' });
    t.ok(r.status === 400, 'invalid action → 400');
    r = await post(base, `/api/scan/${scan.id}/findings/does-not-exist/action`, { action: 'approve' });
    t.ok(r.status === 404, 'unknown finding → 404');
  }

  section('snippet pipeline — multi-language detection');
  const snippets = [
    { name: 'JS JWT RS256', code: `const jwt = require('jsonwebtoken');\nconst t = jwt.sign(p, k, { algorithm: 'RS256' });`, expect: 1 },
    { name: 'Python RSA keygen', code: `from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=2048)`, expect: 1 },
    { name: 'Java KeyPairGenerator', code: `KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");\ng.initialize(2048);\nSignature s = Signature.getInstance("SHA256withRSA");`, expect: 1 },
    { name: 'Go rsa.GenerateKey (bare)', code: `key, err := rsa.GenerateKey(rand.Reader, 2048)\nif err != nil { panic(err) }`, expect: 1 },
    { name: 'no crypto', code: `function add(a, b) { return a + b; }`, expect: 0 },
    { name: 'AES only (not PQ-vulnerable)', code: `const c = crypto.createCipheriv('aes-256-gcm', key, iv);`, expect: 0 },
  ];
  for (const s of snippets) {
    const { scan } = await scanAndGet(base, { code: s.code });
    t.ok(scan && scan.findings.length === s.expect, `snippet "${s.name}" → ${s.expect} finding(s)`, `got ${scan?.findings.length}`);
  }
  // determinism
  {
    const a = await scanAndGet(base, { code: snippets[0].code });
    const b = await scanAndGet(base, { code: snippets[0].code });
    t.ok(a.scan.findings[0].confidence === b.scan.findings[0].confidence, 'snippet confidence is deterministic');
  }

  section('robustness — bad input is handled, never crashes');
  {
    t.ok((await post(base, '/api/scan', {})).status === 400, 'empty scan body → 400');
    t.ok((await post(base, '/api/scan', { repoId: 'nope' })).status === 404, 'unknown repo → 404');
    t.ok((await post(base, '/api/scan', { code: '   ' })).status === 400, 'whitespace snippet → 400');
    t.ok((await postRaw(base, '/api/scan', '{bad json')).status === 400, 'malformed JSON → 400');
    t.ok((await post(base, '/api/scan', { code: 'x'.repeat(250_000) })).status === 413, 'oversized snippet → 413');
    t.ok((await get(base, '/api/scan/does-not-exist')).status === 404, 'unknown scan → 404');
  }

  section('artifacts — CBOM export & scan history');
  {
    const scan = scans['payment-service'];
    const r = await fetch(base + `/api/scan/${scan.id}/export`);
    const disp = r.headers.get('content-disposition') || '';
    const body = await r.json();
    t.ok(r.status === 200 && disp.includes(`recrypt-cbom-${scan.id}.json`), 'CBOM export sets download filename');
    t.ok(body.format === 'recrypt-cbom' && Array.isArray(body.findings), 'CBOM export is well-formed');
    const hist = await get(base, '/api/scans');
    t.ok(hist.status === 200 && hist.data.scans.length >= 1, 'scan history endpoint works');
  }

  return t;
}
