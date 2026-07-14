import { NextRequest, NextResponse } from 'next/server';
import { allScans, appendAudit, saveScan } from '@/lib/store';
import { checkToken } from '@/lib/platform';
import { runEquivalenceTests } from '@/lib/verify';

/**
 * POST — the crypto-agility drill: re-execute the REAL equivalence tests on
 * every stored analysis across every scan, right now, and report drift.
 * This is the muscle the platform exercises when NIST revises a parameter
 * set or a new FIPS lands: "re-verify the whole fleet" as one operation.
 * Console session required (it rewrites stored test evidence).
 */
export const maxDuration = 300;

export async function POST(req: NextRequest) {
  if (!checkToken(req.cookies.get('recrypt_platform')?.value)) {
    return NextResponse.json({ error: 'console sign-in required' }, { status: 401 });
  }

  const scans = await allScans();
  let analyses = 0;
  let testsRun = 0;
  let testsPassed = 0;
  let regressions = 0;

  for (const scan of scans) {
    let touched = false;
    for (const f of scan.findings) {
      if (!f.analysis) continue;
      const before = f.analysis.tests.filter((t) => t.passed).length;
      const fresh = runEquivalenceTests(f, f.analysis.patchedCode);
      f.analysis.tests = fresh;
      const after = fresh.filter((t) => t.passed).length;
      analyses++;
      testsRun += fresh.length;
      testsPassed += after;
      if (after < before) regressions++;
      touched = true;
    }
    if (touched) await saveScan(scan);
  }

  await appendAudit(
    'agility-drill',
    `Fleet re-verification: ${analyses} stored patches re-proven, ${testsPassed}/${testsRun} tests passed, ${regressions} regression${regressions === 1 ? '' : 's'}`,
    'all-scans'
  );

  return NextResponse.json({ analyses, testsRun, testsPassed, regressions });
}
