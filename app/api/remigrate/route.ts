import { NextRequest, NextResponse } from 'next/server';
import { allScans, appendAudit } from '@/lib/store';
import { checkToken } from '@/lib/platform';
import { PQ_TARGETS, proveTarget, targetKind } from '@/lib/verify';
import type { PqTarget } from '@/lib/verify';

/**
 * POST { target } — the crypto-agility re-migration drill.
 * Re-executes the REAL alternative algorithm (ML-DSA-87, SLH-DSA/FIPS 205,
 * ML-KEM-1024, …) against every applicable stored finding, proving the whole
 * fleet can be re-migrated to a new post-quantum target on demand. This is
 * the "PQC is not the last migration" muscle — run for real, not simulated.
 * Console session required.
 */
export const maxDuration = 300;

/** GET — the available re-migration targets. */
export async function GET() {
  return NextResponse.json({ targets: PQ_TARGETS });
}

export async function POST(req: NextRequest) {
  if (!checkToken(req.cookies.get('recrypt_platform')?.value)) {
    return NextResponse.json({ error: 'console sign-in required' }, { status: 401 });
  }
  let body: { target?: PqTarget };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }
  const target = body.target;
  if (!target || !PQ_TARGETS.some((t) => t.id === target)) {
    return NextResponse.json({ error: 'unknown target', targets: PQ_TARGETS.map((t) => t.id) }, { status: 400 });
  }

  const kind = targetKind(target);
  const wantUsage = kind === 'kem' ? 'key_exchange' : 'signing';

  const scans = await allScans();
  let applicable = 0;
  let proven = 0;
  let failed = 0;
  let sampleEvidence = '';

  for (const scan of scans) {
    for (const f of scan.findings) {
      if (!f.analysis) continue;
      // signature targets re-prove signing/auth findings; KEM targets re-prove key exchange
      const isSig = f.usageType === 'signing' || f.usageType === 'authentication';
      const matches = kind === 'kem' ? f.usageType === 'key_exchange' : isSig;
      if (!matches) continue;
      applicable++;
      const result = proveTarget(target);
      if (result.passed) proven++;
      else failed++;
      if (!sampleEvidence && result.evidence) sampleEvidence = result.evidence;
    }
  }

  const label = PQ_TARGETS.find((t) => t.id === target)!.label;
  await appendAudit(
    'agility-drill',
    `Re-migration proof to ${label}: ${proven}/${applicable} applicable findings re-proven with the real algorithm, ${failed} failed`,
    wantUsage
  );

  return NextResponse.json({ target, label, kind, applicable, proven, failed, sampleEvidence });
}
