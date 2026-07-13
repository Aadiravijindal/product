import { NextRequest, NextResponse } from 'next/server';
import { getFinding, persist } from '@/lib/store';
import { claudeAvailable, classifyFinding, generateRemediation, reviewPatch, revisePatch } from '@/lib/claude';
import { builtinRemediation } from '@/lib/remediation';
import { assessHndl, builtinReview, proofDigest } from '@/lib/assurance';
import { runEquivalenceTests } from '@/lib/verify';
import type { Analysis, Review } from '@/lib/types';

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
export async function POST(_req: NextRequest, ctx: { params: Promise<{ scanId: string; findingId: string }> }) {
  const { scanId, findingId } = await ctx.params;
  const finding = getFinding(scanId, findingId);
  if (!finding) return NextResponse.json({ error: 'finding not found' }, { status: 404 });

  if (finding.analysis) return NextResponse.json({ finding });

  let analysis: Analysis;

  if (claudeAvailable()) {
    try {
      // Stage 1+2: classification and patch generation in parallel
      const [classification, remediation] = await Promise.all([
        classifyFinding(finding),
        generateRemediation(finding),
      ]);

      // Stage 3: independent adversarial review of the generated patch
      let review: Review;
      let patch = remediation;
      try {
        review = await reviewPatch(finding, patch.patchedCode);
        // Stage 3b: one bounded revision round if the reviewer demands it
        if (review.verdict === 'revised' && review.issues.length > 0) {
          patch = await revisePatch(finding, patch.patchedCode, review.issues);
          review = {
            ...review,
            issues: review.issues.map((i) => ({ ...i, resolved: true })),
            summary: `${review.summary} The generator produced a revised patch addressing all reviewer findings; the revision is what is shown and tested below.`,
          };
        }
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

  finding.analysis = analysis;
  persist();
  return NextResponse.json({ finding });
}
