import { NextRequest, NextResponse } from 'next/server';
import { getSampleRepo } from '@/lib/samples';
import { scanFiles } from '@/lib/scanner';
import { newScanId, saveScan } from '@/lib/store';
import type { Scan } from '@/lib/types';

/**
 * POST /api/scan
 * body: { repoId: string } to scan a sample repo, or { code: string } for a
 * pasted snippet. Both go through the exact same scan pipeline.
 */
export async function POST(req: NextRequest) {
  let body: { repoId?: string; code?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  const scanId = newScanId();
  let scan: Scan;

  if (body.repoId) {
    const repo = getSampleRepo(body.repoId);
    if (!repo) return NextResponse.json({ error: 'unknown repo' }, { status: 404 });
    const findings = scanFiles({ files: repo.files, scanId, repoId: repo.id });
    scan = {
      id: scanId,
      source: { type: 'repo', repoId: repo.id, repoName: repo.name },
      createdAt: new Date().toISOString(),
      findings,
    };
  } else if (typeof body.code === 'string' && body.code.trim().length > 0) {
    if (body.code.length > 200_000) {
      return NextResponse.json({ error: 'snippet too large (200 KB max for the demo)' }, { status: 413 });
    }
    const findings = scanFiles({
      files: [{ path: 'pasted-snippet', content: body.code }],
      scanId,
    });
    scan = {
      id: scanId,
      source: { type: 'snippet', label: 'Pasted snippet' },
      createdAt: new Date().toISOString(),
      findings,
    };
  } else {
    return NextResponse.json({ error: 'provide repoId or code' }, { status: 400 });
  }

  saveScan(scan);
  return NextResponse.json({ scanId: scan.id, findingCount: scan.findings.length });
}
