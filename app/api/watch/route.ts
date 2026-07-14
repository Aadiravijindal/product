import { NextRequest, NextResponse } from 'next/server';
import { appendAudit, getWatchlist, saveWatchlist } from '@/lib/store';
import type { WatchEntry } from '@/lib/store';
import { getSampleRepo } from '@/lib/samples';
import { parseGithubUrl } from '@/lib/github';
import { checkToken } from '@/lib/platform';
import { rescanEntry } from '@/lib/watch';

/** Continuous monitoring can fetch real repos. */
export const maxDuration = 300;

/** GET — the watchlist with drift status. */
export async function GET() {
  return NextResponse.json({ watchlist: await getWatchlist() });
}

/** POST { repoId } or { githubUrl } — add a repo to continuous watch (console session required). */
export async function POST(req: NextRequest) {
  if (!checkToken(req.cookies.get('recrypt_platform')?.value)) {
    return NextResponse.json({ error: 'console sign-in required' }, { status: 401 });
  }
  let body: { repoId?: string; githubUrl?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  let entry: WatchEntry;
  if (body.repoId) {
    const repo = getSampleRepo(body.repoId);
    if (!repo) return NextResponse.json({ error: 'unknown repo' }, { status: 404 });
    entry = {
      key: repo.id, label: repo.name, kind: 'sample',
      addedAt: new Date().toISOString(), lastScanAt: '', lastScanId: '',
      signatures: [], lastFindingCount: 0, newSinceLast: [],
    };
  } else if (body.githubUrl) {
    const ref = parseGithubUrl(body.githubUrl);
    if (!ref) return NextResponse.json({ error: 'not a GitHub repository URL' }, { status: 400 });
    entry = {
      key: `gh:${ref.owner}/${ref.repo}`, label: `${ref.owner}/${ref.repo}`, kind: 'github', githubUrl: ref.url,
      addedAt: new Date().toISOString(), lastScanAt: '', lastScanId: '',
      signatures: [], lastFindingCount: 0, newSinceLast: [],
    };
  } else {
    return NextResponse.json({ error: 'provide repoId or githubUrl' }, { status: 400 });
  }

  const list = await getWatchlist();
  if (list.some((w) => w.key === entry.key)) {
    return NextResponse.json({ error: 'already watching this repo' }, { status: 409 });
  }
  if (list.length >= 20) return NextResponse.json({ error: 'watchlist full (20 max in the preview)' }, { status: 409 });

  try {
    entry = await rescanEntry(entry);
    entry.newSinceLast = []; // baseline scan — nothing is "new" yet
  } catch (err) {
    return NextResponse.json({ error: `initial scan failed: ${err instanceof Error ? err.message : 'error'}` }, { status: 502 });
  }
  list.push(entry);
  await saveWatchlist(list);
  await appendAudit('watcher', `Repo added to continuous watch (baseline: ${entry.lastFindingCount} findings)`, entry.label);
  return NextResponse.json({ entry });
}

/** DELETE { key } — stop watching. */
export async function DELETE(req: NextRequest) {
  if (!checkToken(req.cookies.get('recrypt_platform')?.value)) {
    return NextResponse.json({ error: 'console sign-in required' }, { status: 401 });
  }
  const key = new URL(req.url).searchParams.get('key') ?? '';
  const list = await getWatchlist();
  const next = list.filter((w) => w.key !== key);
  if (next.length === list.length) return NextResponse.json({ error: 'not watching that repo' }, { status: 404 });
  await saveWatchlist(next);
  return NextResponse.json({ ok: true });
}
