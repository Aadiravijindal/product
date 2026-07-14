#!/usr/bin/env node
/**
 * Recrypt CI policy gate — "stop new quantum-vulnerable crypto from ever merging."
 *
 *   node scripts/ci-gate.mjs [path]        # scan a directory (default: cwd)
 *   node scripts/ci-gate.mjs --changed     # scan only files changed vs origin/main (for PRs)
 *   node scripts/ci-gate.mjs --fail-on high # gate severity: any|high|critical (default: any)
 *
 * Exit 0 = clean, exit 1 = quantum-vulnerable crypto found. Drop it into any CI
 * pipeline and a pull request that introduces RSA/ECC/RS256/legacy-TLS fails the
 * check. Zero dependencies — Node built-ins only.
 *
 * Detection mirrors the Recrypt scanner (lib/scanner.ts); keep the two in sync.
 */

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const SEV_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };

// (regex, algorithm, usage, severity) — the high-signal quantum-vulnerable set.
const RULES = [
  [/rsa\.generate_private_key\s*\(|RSA\.generate\s*\(/g, 'RSA', 'signing/encryption', 'high'],
  [/\.sign\s*\([\s\S]{0,200}?padding\.(PSS|PKCS1v15)/g, 'RSA', 'signing', 'high'],
  [/KeyPairGenerator\.getInstance\s*\(\s*"RSA"|Signature\.getInstance\s*\(\s*"[^"]*RSA/g, 'RSA', 'signing', 'high'],
  [/Cipher\.getInstance\s*\(\s*"RSA/g, 'RSA', 'encryption', 'high'],
  [/ec\.generate_private_key\s*\(|import\s+ecdsa\b|KeyPairGenerator\.getInstance\s*\(\s*"EC"/g, 'ECDSA', 'signing', 'high'],
  [/\bECDH\b|dh\.generate_parameters\s*\(|crypto\.createECDH\s*\(/g, 'ECDH', 'key_exchange', 'critical'],
  [/algorithm:\s*['"]RS256['"]|['"]alg['"]\s*:\s*['"]RS256['"]|SignatureAlgorithm\.RS256/g, 'RSA (JWT RS256)', 'authentication', 'high'],
  [/algorithm:\s*['"]ES256['"]|['"]alg['"]\s*:\s*['"]ES256['"]/g, 'ECDSA (JWT ES256)', 'authentication', 'high'],
  [/TLSv1(\.[01])?\b|SSLv3|PROTOCOL_TLSv1(_[01])?\b|setEnabledProtocols/g, 'Legacy TLS', 'key_exchange', 'medium'],
  [/crypto\.generateKeyPairSync\s*\(\s*['"]rsa['"]|crypto\.generateKeyPairSync\s*\(\s*['"]ec['"]/g, 'RSA/EC', 'signing', 'high'],
];

const SRC_EXT = new Set(['.py', '.java', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.go', '.rb', '.cs']);
const SKIP_DIR = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'out', 'vendor', '__pycache__', 'sample-repos']);

const args = process.argv.slice(2);
const failOnIdx = args.indexOf('--fail-on');
const failOn = failOnIdx !== -1 ? args[failOnIdx + 1] : 'any';
const changedOnly = args.includes('--changed');
const rootArg = args.find((a, i) => !a.startsWith('--') && args[i - 1] !== '--fail-on');
const root = path.resolve(rootArg || '.');

function changedFiles() {
  try {
    const base = process.env.RECRYPT_BASE_REF || 'origin/main';
    const out = execSync(`git diff --name-only --diff-filter=ACMR ${base}...HEAD`, { encoding: 'utf8' });
    return out.split('\n').map((f) => f.trim()).filter(Boolean).map((f) => path.resolve(f));
  } catch {
    console.error('  (could not diff against origin/main — scanning the whole tree instead)');
    return null;
  }
}

function walk(dir, acc) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIR.has(entry.name)) walk(path.join(dir, entry.name), acc);
    } else if (SRC_EXT.has(path.extname(entry.name))) {
      acc.push(path.join(dir, entry.name));
    }
  }
  return acc;
}

function lineOf(content, index) {
  return content.slice(0, index).split('\n').length;
}

function scanFile(file) {
  let content;
  try {
    content = fs.readFileSync(file, 'utf8');
  } catch {
    return [];
  }
  const hits = [];
  for (const [regex, algorithm, usage, severity] of RULES) {
    regex.lastIndex = 0;
    let m;
    while ((m = regex.exec(content)) !== null) {
      hits.push({ file, line: lineOf(content, m.index), algorithm, usage, severity });
      if (m.index === regex.lastIndex) regex.lastIndex++;
    }
  }
  // one finding per (file, algorithm) — report the first line
  const seen = new Set();
  return hits.filter((h) => {
    const key = `${h.file}:${h.algorithm}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const C = { red: (s) => `\x1b[31m${s}\x1b[0m`, green: (s) => `\x1b[32m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`, bold: (s) => `\x1b[1m${s}\x1b[0m` };

console.log(C.bold('\n  Recrypt CI gate — quantum-vulnerable crypto policy\n'));

let files;
if (changedOnly) {
  const ch = changedFiles();
  files = (ch || walk(root, [])).filter((f) => SRC_EXT.has(path.extname(f)) && fs.existsSync(f));
} else {
  files = walk(root, []);
}

const findings = files.flatMap(scanFile);
const rel = (f) => path.relative(root, f) || path.basename(f);

if (findings.length === 0) {
  console.log('  ' + C.green('✔ No quantum-vulnerable cryptography introduced. Gate passed.') + '\n');
  process.exit(0);
}

for (const f of findings) {
  const sev = f.severity === 'critical' ? C.red(f.severity.toUpperCase()) : f.severity === 'high' ? C.red(f.severity) : C.yellow(f.severity);
  console.log(`  ${sev.padEnd(18)} ${C.bold(f.algorithm)} ${C.dim('(' + f.usage + ')')} — ${rel(f.file)}:${f.line}`);
}

const threshold = failOn === 'any' ? 0 : SEV_ORDER[failOn] ?? 0;
const blocking = findings.filter((f) => SEV_ORDER[f.severity] >= threshold);

console.log('');
if (blocking.length > 0) {
  console.log('  ' + C.red(C.bold(`✗ ${blocking.length} quantum-vulnerable usage(s) at or above "${failOn}". Gate failed.`)));
  console.log(C.dim('    Run these through Recrypt to generate a hybrid post-quantum fix before merging.\n'));
  process.exit(1);
}
console.log('  ' + C.yellow(`Found ${findings.length} usage(s), but none at or above "${failOn}". Gate passed with warnings.\n`));
process.exit(0);
