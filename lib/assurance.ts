import crypto from 'crypto';
import type { Finding, HndlAssessment, MigrationPlan, PlanStep, Review, ReviewIssue, Scan, TestResult } from './types';

/**
 * The assurance layer — the part of Recrypt that exists because banks will
 * never deploy LLM-written cryptography on faith:
 *
 *  - HNDL deadlines: Mosca-style "harvest now, decrypt later" math per finding
 *  - Policy reviewer: deterministic static checks on generated patches (the
 *    offline stand-in for the adversarial Claude reviewer)
 *  - Proof bundle digest: SHA-256 over original + patch + evidence, printed
 *    on the certificate (what an HSM signs in production)
 *  - Migration plan: dependency-aware rollout ordering
 */

// ---------------------------------------------------------------------------
// Harvest-now-decrypt-later assessment (Mosca's inequality, simplified)
// ---------------------------------------------------------------------------

/** Conservative planning assumption for a cryptographically relevant quantum computer. */
const Q_YEAR = 2033;
/** Typical enterprise migration lead time in years. */
const MIGRATION_YEARS = 2;

/** How long data protected by this usage must remain secure (shelf life, years). */
function shelfLifeYears(finding: Finding): number {
  const ctx = finding.fullCode;
  if (finding.usageType === 'key_exchange') return 15; // recorded traffic: long-lived secrets
  if (finding.usageType === 'signing') return /payment|settle|transaction|financ/i.test(ctx) ? 10 : 7;
  if (finding.usageType === 'authentication') return 1; // short-lived tokens
  return 10; // encryption at rest
}

export function assessHndl(finding: Finding): HndlAssessment {
  const now = new Date().getFullYear();
  if (finding.usageType === 'key_exchange') {
    return {
      label: 'Already exposed — migrate now',
      detail:
        `Traffic recorded today can be decrypted retroactively once a quantum computer exists ("harvest now, decrypt later"). ` +
        `With secrets that must stay confidential ~${shelfLifeYears(finding)} years and a ~${Q_YEAR} quantum-capability planning assumption, every day of delay adds decryptable traffic.`,
      urgent: true,
    };
  }
  const shelf = shelfLifeYears(finding);
  // Mosca: start migration when (shelf life + migration time) reaches the quantum horizon
  const migrateBy = Q_YEAR - shelf - MIGRATION_YEARS;
  const clamped = Math.max(now, Math.min(migrateBy, 2031)); // 2031 = US federal signature deadline
  const urgent = clamped <= now + 1;
  return {
    label: clamped <= now ? `Migration window is now (${now})` : `Migrate by ${clamped}`,
    detail:
      `Artifacts produced today must stay trustworthy ~${shelf} years; with a ~${MIGRATION_YEARS}-year migration and a ~${Q_YEAR} quantum-capability planning assumption, ` +
      `Mosca's inequality puts the start-by date at ${migrateBy < now ? 'the past — the window is already open' : migrateBy}. Federal deadline for signatures: 2031 (CNSA 2.0 cascades to contractors).`,
    urgent,
  };
}

// ---------------------------------------------------------------------------
// Deterministic policy review (offline stand-in for the adversarial agent)
// ---------------------------------------------------------------------------

interface Check {
  name: string;
  applies: (f: Finding) => boolean;
  /** returns an issue if the check FAILS, null if it passes */
  run: (f: Finding, patched: string) => ReviewIssue | null;
}

const CHECKS: Check[] = [
  {
    name: 'post-quantum primitive present',
    applies: () => true,
    run: (_f, p) =>
      /ML-DSA|ML-KEM|X25519MLKEM768|ml_dsa|ml_kem/i.test(p)
        ? null
        : { severity: 'high', title: 'No NIST post-quantum primitive in patch', detail: 'The patch does not reference ML-DSA (FIPS 204), ML-KEM (FIPS 203), or a hybrid TLS group.' },
  },
  {
    name: 'classical path preserved (hybrid, not rip-and-replace)',
    applies: (f) => f.usageType !== 'key_exchange',
    run: (f, p) => {
      const classical = /rsa|RSA|SHA256withRSA|RS256|ecdsa|ECDSA/;
      return classical.test(p)
        ? null
        : { severity: 'high', title: 'Classical algorithm removed', detail: 'Hybrid migration requires keeping the classical signature during the transition window; the patch appears to rip-and-replace.' };
    },
  },
  {
    name: 'dual verification enforced (both signatures must pass)',
    applies: (f) => f.usageType === 'signing' || f.usageType === 'authentication',
    run: (_f, p) => {
      const dualVerify = /(&&|\band\b)[\s\S]{0,80}(pq|ml_dsa|postQuantum|post_quantum)|BOTH|both must|pq_ok|pqOk|raise ValueError\("post-quantum/i;
      return dualVerify.test(p)
        ? null
        : { severity: 'medium', title: 'Dual verification not clearly enforced', detail: 'Could not statically confirm that verification requires BOTH the classical and post-quantum signatures (composite pattern). Verify manually before rollout.' };
    },
  },
  {
    name: 'no legacy TLS floor remains',
    applies: (f) => f.usageType === 'key_exchange',
    run: (_f, p) =>
      /TLSv1\.[01]"/.test(p)
        ? { severity: 'high', title: 'Legacy TLS versions still enabled', detail: 'The patch still enables TLS 1.0/1.1, which permits downgrade below the hybrid key exchange.' }
        : null,
  },
  {
    name: 'no static-RSA cipher suites remain',
    applies: (f) => f.usageType === 'key_exchange',
    run: (_f, p) =>
      /TLS_RSA_WITH_/.test(p)
        ? { severity: 'high', title: 'Static-RSA cipher suites still pinned', detail: 'TLS_RSA_* suites permit quantum-vulnerable key transport regardless of the preferred group.' }
        : null,
  },
  {
    name: 'no private key material logged or returned',
    applies: () => true,
    run: (_f, p) =>
      /(console\.log|print|logger\.\w+)\s*\([^)]*(private|secret)[_a-zA-Z]*key/i.test(p)
        ? { severity: 'high', title: 'Key material reaches a log statement', detail: 'The patch appears to log or print private/secret key material.' }
        : null,
  },
  {
    name: 'original callable surface preserved',
    applies: () => true,
    run: (f, p) => {
      const names = [...f.fullCode.matchAll(/def\s+([a-zA-Z_]\w*)|function\s+([a-zA-Z_]\w*)/g)]
        .map((m) => m[1] || m[2])
        .filter(Boolean);
      const missing = names.filter((n) => !p.includes(n));
      return missing.length === 0
        ? null
        : { severity: 'medium', title: 'Callable surface changed', detail: `Missing from patch: ${missing.join(', ')} — downstream callers may break.` };
    },
  },
];

export function builtinReview(finding: Finding, patchedCode: string): Review {
  const issues: ReviewIssue[] = [];
  let checksRun = 0;
  for (const check of CHECKS) {
    if (!check.applies(finding)) continue;
    checksRun++;
    const issue = check.run(finding, patchedCode);
    if (issue) issues.push(issue);
  }
  const hasHigh = issues.some((i) => i.severity === 'high');
  return {
    engine: 'builtin',
    verdict: hasHigh ? 'revised' : issues.length > 0 ? 'approved_with_notes' : 'approved',
    summary:
      issues.length === 0
        ? `Ran ${checksRun} adversarial policy checks against the patch — no downgrade paths, key-handling flaws, or compatibility breaks found.`
        : `Ran ${checksRun} adversarial policy checks — ${issues.length} finding(s) recorded for the human reviewer.`,
    issues,
    checksRun,
  };
}

// ---------------------------------------------------------------------------
// Proof bundle digest
// ---------------------------------------------------------------------------

export function proofDigest(finding: Finding, patchedCode: string, tests: TestResult[]): string {
  const bundle = JSON.stringify({
    file: finding.file,
    original: finding.fullCode,
    patched: patchedCode,
    evidence: tests.map((t) => ({ name: t.name, passed: t.passed, detail: t.detail, evidence: t.evidence ?? null })),
  });
  return crypto.createHash('sha256').update(bundle).digest('hex');
}

// ---------------------------------------------------------------------------
// Deterministic migration plan (offline stand-in for the planner agent)
// ---------------------------------------------------------------------------

export function builtinPlan(scan: Scan): MigrationPlan {
  const steps: PlanStep[] = [];
  let order = 1;

  const kex = scan.findings.filter((f) => f.usageType === 'key_exchange');
  const externalSigning = scan.findings.filter(
    (f) => f.usageType === 'signing' && /payment|settle|transaction|extern|clearing/i.test(f.fullCode)
  );
  const auth = scan.findings.filter((f) => f.usageType === 'authentication');
  const rest = scan.findings.filter((f) => !kex.includes(f) && !externalSigning.includes(f) && !auth.includes(f));

  if (kex.length) {
    steps.push({
      order: order++,
      title: 'Hybridize key exchange first (harvest-now-decrypt-later)',
      detail:
        'Key exchange is the only category where the damage is already happening: traffic recorded today is decryptable retroactively. Move to X25519MLKEM768 (hybrid ML-KEM-768) — the group Chrome and Cloudflare already negotiate — with classical fallback for peers that lag.',
      files: kex.map((f) => f.file),
      coordination: kex.some((f) => /partner|conformance|certified/i.test(f.fullCode))
        ? 'A pinned partner-conformance cipher configuration was detected — schedule partner re-certification before rollout.'
        : undefined,
    });
  }
  if (externalSigning.length) {
    steps.push({
      order: order++,
      title: 'Composite signatures on externally-verified artifacts',
      detail:
        'Signatures that external parties verify (settlement/clearing) need coordinated rollout: publish the ML-DSA-65 public key first, run composite (RSA + ML-DSA) in log-only mode, then enforce dual verification once the counterparty confirms.',
      files: externalSigning.map((f) => f.file),
      coordination: 'The verifying counterparty must accept composite signatures before enforcement — sequence the key-publication step with them.',
    });
  }
  if (auth.length) {
    steps.push({
      order: order++,
      title: 'Hybrid tokens for internal authentication',
      detail:
        'Short-lived tokens (JWTs) have the smallest exposure window but the widest blast radius — every downstream verifier must be updated. Ship verification support to all consumers first, then start attaching the detached ML-DSA signature.',
      files: auth.map((f) => f.file),
      coordination: 'Inventory every service that verifies these tokens; enforcement flips only after 100% of verifiers deploy.',
    });
  }
  if (rest.length) {
    steps.push({
      order: order++,
      title: 'Remaining signing and encryption call sites',
      detail: 'Internal-only signatures and encryption-at-rest follow once the externally-coupled paths are hybrid. Batch these by service and reuse the verified patch patterns from the steps above.',
      files: rest.map((f) => f.file),
    });
  }
  steps.push({
    order: order++,
    title: 'Enforce, then retire classical-only acceptance',
    detail:
      'After all verifiers run dual-check for a full rotation cycle, flip to enforcement (reject classical-only), re-run the equivalence suite, and regenerate the compliance certificate as the audit artifact.',
    files: [],
  });

  return {
    engine: 'builtin',
    summary: `${scan.findings.length} finding(s) sequenced by exposure: key exchange first (retroactive decryption risk), externally-verified signatures second (counterparty coordination), tokens and internal paths last (widest but shortest-lived blast radius).`,
    steps,
    generatedAt: new Date().toISOString(),
  };
}
