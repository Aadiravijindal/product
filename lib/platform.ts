import crypto from 'crypto';

/**
 * Enterprise Console ("final product") — auth + fleet model.
 *
 * Auth: single-owner login. The email is the owner's identifier; the passcode
 * comes from the PLATFORM_PASSCODE env var (set it in .env.local locally and
 * in Vercel → Settings → Environment Variables). NEVER hardcode a real
 * password in source — this repo is public on GitHub.
 *
 * Fleet: the three connected sample repos run the REAL Recrypt pipeline
 * end-to-end. The rest of the fleet is a deterministic, representative
 * simulation of what an org-wide deployment looks like — clearly labeled as
 * such in the UI. This is the product-preview build a design partner sees.
 */

const OWNER_EMAIL = process.env.PLATFORM_EMAIL || 'aadijindal258@gmail.com';
const PASSCODE = process.env.PLATFORM_PASSCODE || 'recrypt-preview';

export type Role = 'owner' | 'approver' | 'viewer';

interface Member {
  email: string;
  role: Role;
}

/**
 * Team members. The owner is always present. Additional members come from the
 * PLATFORM_TEAM env var: "email:role,email:role" (role ∈ approver|viewer).
 * Everyone shares the org PASSCODE in this preview; real SSO (Okta/SAML) is
 * the funded roadmap. This models the ROLE system — who may approve merges —
 * which is the part that matters for the audit story.
 */
function team(): Member[] {
  const members: Member[] = [{ email: OWNER_EMAIL.toLowerCase(), role: 'owner' }];
  for (const spec of (process.env.PLATFORM_TEAM || '').split(',')) {
    const [email, role] = spec.split(':').map((s) => s.trim());
    if (email && (role === 'approver' || role === 'viewer')) {
      members.push({ email: email.toLowerCase(), role });
    }
  }
  return members;
}

export function roleFor(email: string): Role | null {
  return team().find((m) => m.email === email.trim().toLowerCase())?.role ?? null;
}

/** Token binds the email + role, so it survives across requests without a DB. */
export function platformToken(email: string, role: Role): string {
  return `${Buffer.from(`${email}|${role}`).toString('base64url')}.${crypto
    .createHmac('sha256', PASSCODE)
    .update(`${email}|${role}`)
    .digest('hex')}`;
}

export function checkLogin(email: string, passcode: string): Role | null {
  const role = roleFor(email);
  if (!role) return null;
  const p = Buffer.from(passcode);
  const q = Buffer.from(PASSCODE);
  const passOk = p.length === q.length && crypto.timingSafeEqual(p, q);
  return passOk ? role : null;
}

export interface Session {
  email: string;
  role: Role;
}

export function verifyToken(token: string | undefined): Session | null {
  if (!token || !token.includes('.')) return null;
  const [payload, mac] = token.split('.');
  let decoded: string;
  try {
    decoded = Buffer.from(payload, 'base64url').toString('utf8');
  } catch {
    return null;
  }
  const expected = crypto.createHmac('sha256', PASSCODE).update(decoded).digest('hex');
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const [email, role] = decoded.split('|');
  if (role !== 'owner' && role !== 'approver' && role !== 'viewer') return null;
  return { email, role };
}

/** Back-compat boolean check used by read-only console endpoints. */
export function checkToken(token: string | undefined): boolean {
  return verifyToken(token) !== null;
}

export function ownerEmail(): string {
  return OWNER_EMAIL;
}

export function teamRoster(): Member[] {
  return team();
}

// ---------------------------------------------------------------------------
// Fleet model — deterministic representative data for the org-wide view
// ---------------------------------------------------------------------------

export interface FleetRepo {
  id: string;
  name: string;
  team: string;
  language: string;
  critical: number;
  high: number;
  medium: number;
  migrated: number;
  lastScanDaysAgo: number;
  /** true = one of the bundled sample repos wired to the real pipeline */
  live?: boolean;
}

export const FLEET: FleetRepo[] = [
  // The three LIVE repos — these run the real scan → loop → proof pipeline.
  { id: 'payment-service', name: 'payment-service', team: 'Payments', language: 'Python', critical: 1, high: 1, medium: 0, migrated: 0, lastScanDaysAgo: 0, live: true },
  { id: 'auth-service', name: 'auth-service', team: 'Identity', language: 'Java', critical: 0, high: 2, medium: 0, migrated: 0, lastScanDaysAgo: 0, live: true },
  { id: 'api-gateway', name: 'api-gateway', team: 'Platform', language: 'Node.js', critical: 0, high: 1, medium: 0, migrated: 0, lastScanDaysAgo: 0, live: true },
  // Representative fleet (simulated, deterministic).
  { id: 'ledger-core', name: 'ledger-core', team: 'Payments', language: 'Java', critical: 4, high: 9, medium: 6, migrated: 12, lastScanDaysAgo: 0 },
  { id: 'settlement-batch', name: 'settlement-batch', team: 'Payments', language: 'Python', critical: 2, high: 5, medium: 3, migrated: 8, lastScanDaysAgo: 0 },
  { id: 'card-tokenizer', name: 'card-tokenizer', team: 'Payments', language: 'Go', critical: 3, high: 4, medium: 2, migrated: 9, lastScanDaysAgo: 1 },
  { id: 'kyc-service', name: 'kyc-service', team: 'Risk', language: 'Python', critical: 1, high: 6, medium: 4, migrated: 6, lastScanDaysAgo: 0 },
  { id: 'fraud-scoring', name: 'fraud-scoring', team: 'Risk', language: 'Python', critical: 0, high: 3, medium: 5, migrated: 7, lastScanDaysAgo: 2 },
  { id: 'identity-provider', name: 'identity-provider', team: 'Identity', language: 'Java', critical: 2, high: 7, medium: 3, migrated: 10, lastScanDaysAgo: 0 },
  { id: 'session-broker', name: 'session-broker', team: 'Identity', language: 'Go', critical: 1, high: 2, medium: 2, migrated: 5, lastScanDaysAgo: 1 },
  { id: 'mobile-bff', name: 'mobile-bff', team: 'Mobile', language: 'Node.js', critical: 0, high: 4, medium: 3, migrated: 6, lastScanDaysAgo: 0 },
  { id: 'partner-api', name: 'partner-api', team: 'Platform', language: 'Node.js', critical: 2, high: 5, medium: 1, migrated: 4, lastScanDaysAgo: 0 },
  { id: 'webhooks-fanout', name: 'webhooks-fanout', team: 'Platform', language: 'Go', critical: 0, high: 2, medium: 4, migrated: 5, lastScanDaysAgo: 3 },
  { id: 'notifications', name: 'notifications', team: 'Platform', language: 'Node.js', critical: 0, high: 1, medium: 3, migrated: 4, lastScanDaysAgo: 1 },
  { id: 'treasury-engine', name: 'treasury-engine', team: 'Treasury', language: 'Java', critical: 3, high: 6, medium: 2, migrated: 7, lastScanDaysAgo: 0 },
  { id: 'fx-rates', name: 'fx-rates', team: 'Treasury', language: 'Python', critical: 0, high: 2, medium: 2, migrated: 3, lastScanDaysAgo: 2 },
  { id: 'reporting-etl', name: 'reporting-etl', team: 'Data', language: 'Python', critical: 1, high: 3, medium: 5, migrated: 4, lastScanDaysAgo: 1 },
  { id: 'data-lake-ingest', name: 'data-lake-ingest', team: 'Data', language: 'Go', critical: 0, high: 2, medium: 3, migrated: 2, lastScanDaysAgo: 0 },
  { id: 'ml-feature-store', name: 'ml-feature-store', team: 'Data', language: 'Python', critical: 0, high: 1, medium: 2, migrated: 2, lastScanDaysAgo: 4 },
  { id: 'admin-console', name: 'admin-console', team: 'Internal Tools', language: 'Node.js', critical: 1, high: 3, medium: 2, migrated: 3, lastScanDaysAgo: 0 },
  { id: 'hr-portal', name: 'hr-portal', team: 'Internal Tools', language: 'Java', critical: 0, high: 1, medium: 3, migrated: 1, lastScanDaysAgo: 5 },
  { id: 'legacy-soap-bridge', name: 'legacy-soap-bridge', team: 'Internal Tools', language: 'Java', critical: 5, high: 8, medium: 4, migrated: 2, lastScanDaysAgo: 0 },
  { id: 'infra-tls-configs', name: 'infra-tls-configs', team: 'SRE', language: 'IaC', critical: 6, high: 11, medium: 7, migrated: 14, lastScanDaysAgo: 0 },
  { id: 'k8s-secrets-policies', name: 'k8s-secrets-policies', team: 'SRE', language: 'IaC', critical: 2, high: 6, medium: 5, migrated: 6, lastScanDaysAgo: 0 },
  { id: 'firmware-signing', name: 'firmware-signing', team: 'SRE', language: 'Go', critical: 4, high: 3, medium: 1, migrated: 3, lastScanDaysAgo: 1 },
];

export interface FixRun {
  id: string;
  startedAt: string;
  finishedAt: string;
  requested: number;
  prsOpened: number;
  merged: number;
  roundsHistogram: { one: number; two: number };
  flawsCaught: number;
  note: string;
}

export const FIX_RUNS: FixRun[] = [
  {
    id: 'run_00042',
    startedAt: '2026-07-12T22:00:00Z',
    finishedAt: '2026-07-13T03:41:00Z',
    requested: 42,
    prsOpened: 42,
    merged: 31,
    roundsHistogram: { one: 29, two: 13 },
    flawsCaught: 17,
    note: 'Overnight run across Payments + Identity. The red-team agent caught 17 flaws in first-draft patches (2 silent downgrade paths, 4 missing dual-verifications) — all rewritten and re-attacked before the PRs opened.',
  },
  {
    id: 'run_00041',
    startedAt: '2026-07-08T22:00:00Z',
    finishedAt: '2026-07-09T02:12:00Z',
    requested: 25,
    prsOpened: 25,
    merged: 25,
    roundsHistogram: { one: 19, two: 6 },
    flawsCaught: 8,
    note: 'infra-tls-configs remediation wave. All 25 merged; exposure score +6.',
  },
];

export interface PolicyRule {
  id: string;
  rule: string;
  scope: string;
  status: 'enforcing' | 'monitor';
  blockedThisMonth: number;
}

export const POLICIES: PolicyRule[] = [
  { id: 'pol-1', rule: 'No new classical-only signatures (RSA/ECDSA without ML-DSA hybrid)', scope: 'All repositories', status: 'enforcing', blockedThisMonth: 7 },
  { id: 'pol-2', rule: 'ML-KEM-768 required for key establishment', scope: 'Services tagged: payments, pii', status: 'enforcing', blockedThisMonth: 3 },
  { id: 'pol-3', rule: 'No TLS below 1.3 in service configs', scope: 'All repositories', status: 'enforcing', blockedThisMonth: 2 },
  { id: 'pol-4', rule: 'JWT signing must be RS256 + ML-DSA-65 composite during hybrid window', scope: 'Identity, Platform', status: 'enforcing', blockedThisMonth: 4 },
  { id: 'pol-5', rule: 'Flag vendored crypto dependencies pinned below quantum-safe versions', scope: 'All repositories', status: 'monitor', blockedThisMonth: 11 },
];

export interface PolicyException {
  id: string;
  rule: string;
  repo: string;
  reason: string;
  approvedBy: string;
  expires: string;
}

export const EXCEPTIONS: PolicyException[] = [
  { id: 'exc-1', rule: 'pol-1', repo: 'legacy-soap-bridge', reason: 'Counterparty (First National) verifier upgrade scheduled Q4', approvedBy: 'CISO', expires: '2026-10-01' },
  { id: 'exc-2', rule: 'pol-3', repo: 'hr-portal', reason: 'Vendor appliance limitation — replacement on order', approvedBy: 'CISO', expires: '2026-09-15' },
];

export interface AuditEvent {
  at: string;
  actor: string;
  action: string;
  target: string;
}

export const AUDIT_SEED: AuditEvent[] = [
  { at: '2026-07-14T08:32:00Z', actor: 'recrypt-agent', action: 'PR opened (hybrid ML-DSA patch, 2 attack rounds survived)', target: 'ledger-core#482' },
  { at: '2026-07-14T08:32:00Z', actor: 'recrypt-agent', action: 'Proof bundle sealed (SHA-256)', target: 'ledger-core#482' },
  { at: '2026-07-14T07:58:00Z', actor: 'policy-gate', action: 'Merge blocked: new RSA-2048 signature (pol-1)', target: 'partner-api PR#211' },
  { at: '2026-07-13T22:00:00Z', actor: 'scheduler', action: 'Nightly fleet scan started (24 repos)', target: 'org' },
  { at: '2026-07-13T16:20:00Z', actor: 'j.chen@company.com', action: 'Approved & merged hybrid patch', target: 'identity-provider#390' },
  { at: '2026-07-13T14:05:00Z', actor: 'recrypt-agent', action: 'Red-team round 2: no defensible flaws — patch finalized', target: 'kyc-service#301' },
  { at: '2026-07-13T14:02:00Z', actor: 'recrypt-agent', action: 'Red-team round 1: 2 flaws (downgrade path, missing dual-verify) — rewriting', target: 'kyc-service#301' },
  { at: '2026-07-12T09:44:00Z', actor: 'CISO', action: 'Policy exception granted until 2026-10-01', target: 'legacy-soap-bridge / pol-1' },
];

export function fleetSummary() {
  const totals = FLEET.reduce(
    (acc, r) => {
      const open = r.critical + r.high + r.medium;
      acc.repos += 1;
      acc.open += open;
      acc.migrated += r.migrated;
      acc.critical += r.critical;
      return acc;
    },
    { repos: 0, open: 0, migrated: 0, critical: 0 }
  );
  const total = totals.open + totals.migrated;
  const pct = total === 0 ? 0 : Math.round((totals.migrated / total) * 100);
  // Simple deterministic score: coverage minus open-critical pressure.
  const score = Math.max(0, Math.min(100, Math.round(pct - totals.critical * 0.5 + 18)));
  // 8-quarter history derived from the current score so the chart is always
  // coherent: a slow start, then acceleration as fix runs land.
  const steps = [22, 19, 17, 14, 10, 7, 3, 0];
  const trend = steps.map((d) => Math.max(4, score - d));
  return {
    ...totals,
    totalUsages: total,
    migratedPct: pct,
    exposureScore: score,
    trend,
    deadlineYear: 2030,
    onTrack: pct >= 35,
  };
}
