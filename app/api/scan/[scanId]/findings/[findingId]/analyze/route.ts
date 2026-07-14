import { NextRequest, NextResponse } from 'next/server';
import { appendAudit, getScan, saveScan } from '@/lib/store';
import { claudeAvailable, classifyFinding, generateRemediation, hardenPatchLive } from '@/lib/claude';
import { builtinRemediation } from '@/lib/remediation';
import { assessHndl, builtinReview, proofDigest } from '@/lib/assurance';
import { runEquivalenceTests } from '@/lib/verify';
import type { Analysis, Finding, Review } from '@/lib/types';

/**
 * Vercel: allow this function to run the full live pipeline (multi-round
 * adversarial loop can take a few minutes). Ignored by plain `next start`.
 */
export const maxDuration = 300;

/** Never surface raw API error payloads in the UI. */
function friendlyApiError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (/authentication|401|invalid x-api-key/i.test(msg)) return 'the configured API key was rejected';
  if (/rate.?limit|429/i.test(msg)) return 'the API is rate-limited';
  if (/timeout|timed out|ETIMEDOUT|ECONNRESET|fetch failed|ENOTFOUND/i.test(msg)) return 'the API could not be reached';
  if (/overloaded|529|500|503/i.test(msg)) return 'the API is temporarily overloaded';
  return 'the request did not complete';
}

/**
 * POST — run the full assurance pipeline for one finding:
 *
 *   classify ─┐
 *             ├─► generate hybrid patch ─► ADVERSARIAL REVIEW (independent
 *   context ──┘        agent) ─► bounded revision if needed ─► real
 *   equivalence tests ─► proof-bundle digest ─► human decision
 *
 * Falls back to the built-in engine (template patches + deterministic policy
 * review) if no API key is configured or a live call fails, so a live demo
 * never shows a stack trace.
 */
/**
 * In-flight de-duplication: if the browser times out and the user hits Retry
 * while the first (long) live pipeline is still running on this instance, the
 * retry JOINS the existing run instead of starting a second expensive one.
 */
const inFlight = new Map<string, Promise<Analysis>>();

export async function POST(_req: NextRequest, ctx: { params: Promise<{ scanId: string; findingId: string }> }) {
  const { scanId, findingId } = await ctx.params;
  const scan = await getScan(scanId);
  const finding = scan?.findings.find((f) => f.id === findingId);
  if (!scan || !finding) return NextResponse.json({ error: 'finding not found' }, { status: 404 });

  if (finding.analysis) return NextResponse.json({ finding });

  const flightKey = `${scanId}/${findingId}`;
  const existing = inFlight.get(flightKey);
  if (existing) {
    const analysis = await existing;
    finding.analysis = analysis;
    return NextResponse.json({ finding });
  }

  const run = analyzeFinding(finding);
  inFlight.set(flightKey, run);
  try {
    const analysis = await run;
    finding.analysis = analysis;
    await saveScan(scan);
    const rounds = analysis.review?.rounds?.length ?? 1;
    const flaws = analysis.review?.rounds?.reduce((n, r) => n + r.issueCount, 0) ?? 0;
    await appendAudit(
      analysis.engine === 'claude' ? 'recrypt-agent' : 'builtin-engine',
      `Patch generated & verified (${rounds} attack round${rounds === 1 ? '' : 's'}, ${flaws} flaw${flaws === 1 ? '' : 's'} caught, ${analysis.tests.filter((t) => t.passed).length}/${analysis.tests.length} proofs passed)`,
      finding.file
    );
    return NextResponse.json({ finding });
  } finally {
    inFlight.delete(flightKey);
  }
}

async function analyzeFinding(finding: Finding): Promise<Analysis> {
  let analysis: Analysis;

  if (claudeAvailable()) {
    try {
      // Stage 1+2: classification and patch generation in parallel
      const [classification, remediation] = await Promise.all([
        classifyFinding(finding),
        generateRemediation(finding),
      ]);

      // Stage 3: adversarial hardening LOOP — red-team agent attacks, blue-team
      // agent rewrites, repeat until the attacker can't break it (bounded rounds).
      let review: Review;
      let patch = remediation;
      try {
        const hardened = await hardenPatchLive(finding, remediation);
        patch = hardened.patch;
        review = hardened.review;
      } catch {
        // Reviewer call failed — fall back to the deterministic policy checks
        review = builtinReview(finding, patch.patchedCode);
      }

      analysis = {
        engine: 'claude',
        classification,
        patchedCode: patch.patchedCode,
        changes: patch.changes,
        newAlgorithm: patch.newAlgorithm,
        tests: [],
        review,
        generatedAt: new Date().toISOString(),
      };
    } catch (err) {
      const builtin = builtinRemediation(finding);
      analysis = {
        engine: 'builtin',
        engineNote: `Live AI analysis is unavailable right now (${friendlyApiError(err)}) — this result was served from the built-in remediation library instead.`,
        classification: builtin.classification,
        patchedCode: builtin.patchedCode,
        changes: builtin.changes,
        newAlgorithm: builtin.newAlgorithm,
        tests: [],
        review: builtinReview(finding, builtin.patchedCode),
        generatedAt: new Date().toISOString(),
      };
    }
  } else {
    const builtin = builtinRemediation(finding);
    analysis = {
      engine: 'builtin',
      engineNote:
        'No ANTHROPIC_API_KEY configured — served from the built-in remediation library. Set the key to enable the live two-agent pipeline on arbitrary code.',
      classification: builtin.classification,
      patchedCode: builtin.patchedCode,
      changes: builtin.changes,
      newAlgorithm: builtin.newAlgorithm,
      tests: [],
      review: builtinReview(finding, builtin.patchedCode),
      generatedAt: new Date().toISOString(),
    };
  }

  // Stage 4: equivalence tests are real regardless of which engine produced the patch
  analysis.tests = runEquivalenceTests(finding, analysis.patchedCode);
  // Stage 5: tamper-evident proof bundle digest over code + patch + evidence
  analysis.digest = proofDigest(finding, analysis.patchedCode, analysis.tests);
  // Harvest-now-decrypt-later exposure window (deterministic Mosca-style math)
  analysis.hndl = assessHndl(finding);

  return analysis;
}
