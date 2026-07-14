import { newScanId, saveScan } from './store';
import type { WatchEntry } from './store';
import { getSampleRepo } from './samples';
import { PATTERN_COUNT, scanFiles } from './scanner';
import { fetchPublicRepo, parseGithubUrl } from './github';
import type { Scan } from './types';

function signatures(scan: Scan): string[] {
  return scan.findings.map((f) => `${f.findingKey}:${f.file}`).sort();
}

/** Scan one watch target, persist the scan, and compute drift vs the previous pass. */
export async function rescanEntry(entry: WatchEntry): Promise<WatchEntry> {
  let files: { path: string; content: string }[];
  let repoId: string | undefined;
  if (entry.kind === 'sample') {
    const repo = getSampleRepo(entry.key);
    if (!repo) throw new Error('sample repo gone');
    files = repo.files;
    repoId = repo.id;
  } else {
    const ref = parseGithubUrl(entry.githubUrl!);
    if (!ref) throw new Error('bad url');
    files = (await fetchPublicRepo(ref)).files;
  }
  const scanId = repoId ? newScanId(repoId) : newScanId();
  const findings = scanFiles({ files, scanId, repoId });
  const scan: Scan = {
    id: scanId,
    source: repoId
      ? { type: 'repo', repoId, repoName: entry.label }
      : { type: 'github', url: entry.githubUrl!, repoName: entry.label },
    createdAt: new Date().toISOString(),
    findings,
    stats: { files: files.length, patterns: PATTERN_COUNT, durationMs: 0 },
  };
  await saveScan(scan);
  const sigs = signatures(scan);
  const previous = new Set(entry.signatures);
  const fresh = sigs.filter((s) => !previous.has(s));
  return {
    ...entry,
    lastScanAt: scan.createdAt,
    lastScanId: scanId,
    signatures: sigs,
    lastFindingCount: findings.length,
    newSinceLast: fresh,
  };
}
