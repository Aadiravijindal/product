import { NextRequest, NextResponse } from 'next/server';
import { appendAudit, getScan } from '@/lib/store';
import { githubToken, parseGithubUrl } from '@/lib/github';
import { openPullRequest } from '@/lib/pr-github';
import { notify } from '@/lib/notify';

/**
 * POST — open a REAL pull request on GitHub with this finding's hybrid patch.
 * Requires GITHUB_TOKEN (repo scope). The target repo comes from the scan
 * source (github scans) or an explicit { repoUrl } for other scan types.
 */
export const maxDuration = 60;

export async function POST(req: NextRequest, ctx: { params: Promise<{ scanId: string; findingId: string }> }) {
  const { scanId, findingId } = await ctx.params;
  const scan = await getScan(scanId);
  const finding = scan?.findings.find((f) => f.id === findingId);
  if (!scan || !finding) return NextResponse.json({ error: 'finding not found' }, { status: 404 });
  if (!finding.analysis) return NextResponse.json({ error: 'analyze the finding first' }, { status: 400 });
  if (!githubToken()) {
    return NextResponse.json(
      { error: 'GITHUB_TOKEN not configured. Add it to .env.local (and Vercel env) — a fine-grained token with repo contents+pull-requests write access.' },
      { status: 503 }
    );
  }

  let explicit: string | undefined;
  try {
    const body = (await req.json()) as { repoUrl?: string };
    explicit = body.repoUrl;
  } catch { /* no body is fine */ }

  const url = explicit || (scan.source.type === 'github' ? scan.source.url : undefined);
  if (!url) return NextResponse.json({ error: 'provide repoUrl — this scan did not come from a GitHub repo' }, { status: 400 });
  const ref = parseGithubUrl(url);
  if (!ref) return NextResponse.json({ error: 'not a valid GitHub repository URL' }, { status: 400 });

  try {
    const pr = await openPullRequest({ owner: ref.owner, repo: ref.repo, finding });
    await appendAudit('recrypt-agent', `REAL pull request opened: #${pr.number} (branch ${pr.branch})`, `${ref.owner}/${ref.repo}`);
    await notify(`:closed_lock_with_key: Recrypt opened PR #${pr.number} on ${ref.owner}/${ref.repo}: ${pr.url}`);
    return NextResponse.json({ pr });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'PR creation failed';
    return NextResponse.json({ error: msg }, { status: 502 });
  }
}
