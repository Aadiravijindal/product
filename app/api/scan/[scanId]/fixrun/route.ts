import { NextRequest, NextResponse } from 'next/server';
import { addFixRun, appendAudit, getScan, listFixRuns, saveScan } from '@/lib/store';
import { claudeAvailable, classifyFinding, generateRemediation, hardenPatchLive } from '@/lib/claude';
import { builtinRemediation } from '@/lib/remediation';
import { assessHndl, builtinReview, proofDigest } from '@/lib/assurance';
import { runEquivalenceTests } from '@/lib/verify';
import type { Analysis, Finding, FixRunRecord } from '@/lib/types';

/** A live batch across many findings needs the long window. */
export const maxDuration = 300;

const LIVE_CONCURRENCY = 3;
const LIVE_MAX_FINDINGS = 6; // interactive cap; the built-in engine has no cap

async function analyzeOne(finding: Finding): Promise<Analysis> {
  let analysis: Analysis;
  if (claudeAvailable()) {
    try {
      const [classification, remediation] = await Promise.all([classifyFinding(finding), generateRemediation(finding)]);
      const hardened = await hardenPatchLive(finding, remediation);
      analysis = {
        engine: 'claude',
        classification,
        patchedCode: hardened.patch.patchedCode,
        changes: hardened.patch.changes,
        newAlgorithm: hardened.patch.newAlgorithm,
        tests: [],
        review: hardened.review,
        generatedAt: new Date().toISOString(),
      };
    } catch {
      const b = builtinRemediation(finding);
      analysis = {
        engine: 'builtin',
        engineNote: 'Live call failed during the batch — served from the built-in remediation library.',
        classification: b.classification,
        patchedCode: b.patchedCode,
        changes: b.changes,
        newAlgorithm: b.newAlgorithm,
        tests: [],
        review: builtinReview(finding, b.patchedCode),
        generatedAt: new Date().toISOString(),
      };
    }
  } else {
    const b = builtinRemediation(finding);
    analysis = {
      engine: 'builtin',
      engineNote: 'No ANTHROPIC_API_KEY configured — served from the built-in remediation library.',
      classification: b.classification,
      patchedCode: b.patchedCode,
      changes: b.changes,
      newAlgorithm: b.newAlgorithm,
      tests: [],
      review: builtinReview(finding, b.patchedCode),
      generatedAt: new Date().toISOString(),
    };
  }
  analysis.tests = runEquivalenceTests(finding, analysis.patchedCode);
  analysis.digest = proofDigest(finding, analysis.patchedCode, analysis.tests);
  analysis.hndl = assessHndl(finding);
  return analysis;
}

/**
 * POST — run the full pipeline across every unanalyzed finding in the scan
 * (the real "fix run"), with bounded parallelism, and record honest stats.
 */
export async function POST(_req: NextRequest, ctx: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await ctx.params;
  const scan = await getScan(scanId);
  if (!scan) return NextResponse.json({ error: 'scan not found' }, { status: 404 });

  const pending = scan.findings.filter((f) => !f.analysis);
  if (pending.length === 0) {
    return NextResponse.json({ error: 'nothing to run — every finding is already analyzed' }, { status: 400 });
  }
  const live = claudeAvailable();
  const batch = live ? pending.slice(0, LIVE_MAX_FINDINGS) : pending;

  const startedAt = new Date().toISOString();
  let flawsCaught = 0;
  let roundsOne = 0;
  let roundsTwo = 0;
  let testsPassed = 0;
  let testsRun = 0;

  // bounded-concurrency worker pool
  let next = 0;
  async function worker() {
    while (next < batch.length) {
      const f = batch[next++];
      const analysis = await analyzeOne(f);
      f.analysis = analysis;
      const rounds = analysis.review?.rounds;
      if (rounds && rounds.length >= 2) roundsTwo++;
      else roundsOne++;
      flawsCaught += rounds?.reduce((n, r) => n + r.issueCount, 0) ?? analysis.review?.issues.length ?? 0;
      testsRun += analysis.tests.length;
      testsPassed += analysis.tests.filter((t) => t.passed).length;
    }
  }
  await Promise.all(Array.from({ length: Math.min(LIVE_CONCURRENCY, batch.length) }, worker));

  await saveScan(scan);

  const run: FixRunRecord = {
    id: `run_${scanId.slice(-6)}_${Date.now().toString(36)}`,
    scanId,
    source: scan.source.type === 'repo' || scan.source.type === 'github' ? scan.source.repoName : scan.source.label,
    startedAt,
    finishedAt: new Date().toISOString(),
    requested: batch.length,
    completed: batch.filter((f) => f.analysis).length,
    engine: live ? 'claude' : 'builtin',
    flawsCaught,
    roundsHistogram: { one: roundsOne, two: roundsTwo },
    testsPassed,
    testsRun,
  };
  await addFixRun(run);
  await appendAudit(
    'recrypt-agent',
    `Fix run completed: ${run.completed}/${run.requested} findings, ${flawsCaught} flaws caught by the red team, ${testsPassed}/${testsRun} equivalence tests passed`,
    run.source
  );

  return NextResponse.json({ run, remaining: pending.length - batch.length });
}

/** GET — list recorded fix runs (newest first). */
export async function GET() {
  return NextResponse.json({ runs: await listFixRuns() });
}
