import { NextRequest, NextResponse } from 'next/server';
import { getSampleRepo } from '@/lib/samples';
import { PATTERN_COUNT, scanFiles } from '@/lib/scanner';
import { appendAudit, newScanId, saveScan } from '@/lib/store';
import { fetchPublicRepo, parseGithubUrl } from '@/lib/github';
import type { Scan } from '@/lib/types';

/** Fetching + scanning a real GitHub repo can take a while on big repos. */
export const maxDuration = 120;

/**
 * POST /api/scan
 * body: { repoId } for a sample repo, { code } for a pasted snippet, or
 * { githubUrl } to fetch and scan any PUBLIC GitHub repository for real.
 * All three go through the identical detection pipeline.
 */
export async function POST(req: NextRequest) {
  let body: { repoId?: string; code?: string; githubUrl?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  const t0 = process.hrtime.bigint();
  let scan: Scan;

  if (body.repoId) {
    const repo = getSampleRepo(body.repoId);
    if (!repo) return NextResponse.json({ error: 'unknown repo' }, { status: 404 });
    const scanId = newScanId(repo.id);
    const findings = scanFiles({ files: repo.files, scanId, repoId: repo.id });
    scan = {
      id: scanId,
      source: { type: 'repo', repoId: repo.id, repoName: repo.name },
      createdAt: new Date().toISOString(),
      findings,
      stats: { files: repo.files.length, patterns: PATTERN_COUNT, durationMs: Number(process.hrtime.bigint() - t0) / 1e6 },
    };
  } else if (typeof body.githubUrl === 'string' && body.githubUrl.trim().length > 0) {
    const ref = parseGithubUrl(body.githubUrl);
    if (!ref) {
      return NextResponse.json({ error: 'not a GitHub repository URL (expected github.com/owner/repo)' }, { status: 400 });
    }
    let fetched;
    try {
      fetched = await fetchPublicRepo(ref);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'fetch failed';
      return NextResponse.json({ error: `Could not fetch ${ref.owner}/${ref.repo}: ${msg}` }, { status: 502 });
    }
    if (fetched.files.length === 0) {
      return NextResponse.json({ error: 'repository fetched, but no scannable source/config files found' }, { status: 422 });
    }
    const scanId = newScanId();
    const findings = scanFiles({ files: fetched.files, scanId });
    scan = {
      id: scanId,
      source: { type: 'github', url: ref.url, repoName: `${ref.owner}/${ref.repo}` },
      createdAt: new Date().toISOString(),
      findings,
      stats: { files: fetched.files.length, patterns: PATTERN_COUNT, durationMs: Number(process.hrtime.bigint() - t0) / 1e6 },
    };
    await appendAudit('scanner', `GitHub repo scanned (${fetched.files.length} files @ ${fetched.branch}, ${findings.length} findings)`, `${ref.owner}/${ref.repo}`);
  } else if (typeof body.code === 'string' && body.code.trim().length > 0) {
    if (body.code.length > 200_000) {
      return NextResponse.json({ error: 'snippet too large (200 KB max for the demo)' }, { status: 413 });
    }
    const scanId = newScanId();
    const findings = scanFiles({
      files: [{ path: 'pasted-snippet', content: body.code }],
      scanId,
    });
    scan = {
      id: scanId,
      source: { type: 'snippet', label: 'Pasted snippet' },
      createdAt: new Date().toISOString(),
      findings,
      stats: { files: 1, patterns: PATTERN_COUNT, durationMs: Number(process.hrtime.bigint() - t0) / 1e6 },
    };
  } else {
    return NextResponse.json({ error: 'provide repoId, githubUrl, or code' }, { status: 400 });
  }

  await saveScan(scan);
  if (scan.source.type === 'repo') {
    await appendAudit('scanner', `Sample repo scanned (${scan.findings.length} findings)`, scan.source.repoName);
  }
  return NextResponse.json({ scanId: scan.id, findingCount: scan.findings.length });
}
