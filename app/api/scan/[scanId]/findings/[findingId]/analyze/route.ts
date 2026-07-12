import { NextRequest, NextResponse } from 'next/server';
import { getFinding } from '@/lib/store';
import { claudeAvailable, classifyFinding, generateRemediation } from '@/lib/claude';
import { builtinRemediation } from '@/lib/remediation';
import { runEquivalenceTests } from '@/lib/verify';
import type { Analysis } from '@/lib/types';

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
 * POST — run the remediation agent for one finding:
 * classification (Claude) → hybrid patch (Claude) → real equivalence tests.
 * Falls back to the built-in template engine if no API key is configured or
 * the live call fails, so a live demo never shows a stack trace.
 */
export async function POST(_req: NextRequest, ctx: { params: Promise<{ scanId: string; findingId: string }> }) {
  const { scanId, findingId } = await ctx.params;
  const finding = getFinding(scanId, findingId);
  if (!finding) return NextResponse.json({ error: 'finding not found' }, { status: 404 });

  if (finding.analysis) return NextResponse.json({ finding });

  let analysis: Analysis;

  if (claudeAvailable()) {
    try {
      const [classification, remediation] = await Promise.all([
        classifyFinding(finding),
        generateRemediation(finding),
      ]);
      analysis = {
        engine: 'claude',
        classification,
        patchedCode: remediation.patchedCode,
        changes: remediation.changes,
        newAlgorithm: remediation.newAlgorithm,
        tests: [],
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
        generatedAt: new Date().toISOString(),
      };
    }
  } else {
    const builtin = builtinRemediation(finding);
    analysis = {
      engine: 'builtin',
      engineNote:
        'No ANTHROPIC_API_KEY configured — served from the built-in remediation library. Set the key to enable live AI analysis of arbitrary code.',
      classification: builtin.classification,
      patchedCode: builtin.patchedCode,
      changes: builtin.changes,
      newAlgorithm: builtin.newAlgorithm,
      tests: [],
      generatedAt: new Date().toISOString(),
    };
  }

  // Equivalence tests are real regardless of which engine produced the patch.
  analysis.tests = runEquivalenceTests(finding, analysis.patchedCode);

  finding.analysis = analysis;
  return NextResponse.json({ finding });
}
