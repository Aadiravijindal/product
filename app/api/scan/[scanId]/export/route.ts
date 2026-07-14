import { NextRequest, NextResponse } from 'next/server';
import { getScan } from '@/lib/store';

/**
 * GET — CBOM-style JSON export of a scan, downloadable. The shape follows the
 * spirit of CycloneDX CBOM: components with crypto properties + remediation
 * and verification status, so it can feed a customer's existing tooling.
 */
export async function GET(_req: NextRequest, ctx: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await ctx.params;
  const scan = await getScan(scanId);
  if (!scan) return NextResponse.json({ error: 'scan not found' }, { status: 404 });

  const doc = {
    format: 'recrypt-cbom',
    version: 1,
    generatedAt: new Date().toISOString(),
    scan: {
      id: scan.id,
      source: scan.source.type === 'repo' || scan.source.type === 'github' ? scan.source.repoName : scan.source.type === 'cbom' ? scan.source.label : 'pasted-snippet',
      scannedAt: scan.createdAt,
      stats: scan.stats,
    },
    findings: scan.findings.map((f) => ({
      id: f.id,
      file: f.file,
      lines: [f.lineStart, f.lineEnd],
      language: f.language,
      algorithm: f.algorithm,
      usageType: f.usageType,
      risk: f.risk,
      confidence: f.confidence,
      status: f.status,
      reviewer: f.reviewer ?? null,
      reviewedAt: f.reviewedAt ?? null,
      remediation: f.analysis
        ? {
            engine: f.analysis.engine,
            proposedAlgorithm: f.analysis.newAlgorithm,
            changes: f.analysis.changes,
            equivalenceTests: f.analysis.tests.map((t) => ({
              name: t.name,
              passed: t.passed,
              detail: t.detail,
            })),
          }
        : null,
    })),
  };

  return new NextResponse(JSON.stringify(doc, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="recrypt-cbom-${scan.id}.json"`,
    },
  });
}
