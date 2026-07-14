import { NextRequest, NextResponse } from 'next/server';
import { AUDIT_SEED, EXCEPTIONS, FIX_RUNS, FLEET, POLICIES, checkToken, fleetSummary, ownerEmail } from '@/lib/platform';

/** GET — full console payload. Requires the owner session cookie. */
export async function GET(req: NextRequest) {
  if (!checkToken(req.cookies.get('recrypt_platform')?.value)) {
    return NextResponse.json({ error: 'not signed in' }, { status: 401 });
  }
  return NextResponse.json({
    owner: ownerEmail(),
    summary: fleetSummary(),
    repos: FLEET,
    fixRuns: FIX_RUNS,
    policies: POLICIES,
    exceptions: EXCEPTIONS,
    audit: AUDIT_SEED,
  });
}
