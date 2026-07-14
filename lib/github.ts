import zlib from 'zlib';

/**
 * Fetch a PUBLIC GitHub repository's source for scanning — no OAuth, no
 * cloning: one tarball download from codeload.github.com, parsed in memory
 * with a minimal tar reader (the format is 512-byte headers; no dependency
 * needed). Private-repo access via a GitHub App is the funded roadmap; this
 * is the real "point Recrypt at a repo URL" path for everything public.
 */

const MAX_TARBALL_BYTES = 30 * 1024 * 1024; // refuse >30MB compressed
const MAX_FILE_BYTES = 400 * 1024; // skip huge single files
const MAX_FILES = 400; // scan cap per repo

/** Source + config extensions the detection engine understands. */
const SCANNABLE = /\.(py|java|js|jsx|ts|tsx|go|tf|ya?ml|conf|cfg|properties|pem|crt|cer|key|pub|toml|ini|env|sh)$|(^|\/)(nginx\.conf|Dockerfile|docker-compose\.ya?ml)$/i;
const SKIP_DIRS = /(^|\/)(node_modules|vendor|dist|build|\.git|\.next|target|__pycache__|venv|\.venv|coverage|third_party)(\/|$)/;

export interface GithubRepoRef {
  owner: string;
  repo: string;
  url: string;
}

export function parseGithubUrl(input: string): GithubRepoRef | null {
  const m = input
    .trim()
    .match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:\/.*)?$/);
  if (!m) return null;
  return { owner: m[1], repo: m[2], url: `https://github.com/${m[1]}/${m[2]}` };
}

/**
 * Optional GitHub token (classic PAT or fine-grained) from the environment.
 * With it set, PRIVATE repositories can be scanned and pull requests can be
 * opened for real. Without it, public repos still work unauthenticated.
 */
export function githubToken(): string {
  return process.env.GITHUB_TOKEN || process.env.GH_TOKEN || '';
}

export function ghHeaders(): Record<string, string> {
  const h: Record<string, string> = { accept: 'application/vnd.github+json', 'user-agent': 'recrypt-scanner' };
  const tok = githubToken();
  if (tok) h.authorization = `Bearer ${tok}`;
  return h;
}

async function defaultBranch(ref: GithubRepoRef): Promise<string> {
  try {
    const res = await fetch(`https://api.github.com/repos/${ref.owner}/${ref.repo}`, {
      headers: ghHeaders(),
      cache: 'no-store',
    });
    if (res.ok) {
      const d = (await res.json()) as { default_branch?: string };
      if (d.default_branch) return d.default_branch;
    }
  } catch { /* fall through to guesses */ }
  return 'main';
}

/** Minimal tar reader: yields { path, content } for regular files. */
function* untar(buf: Buffer): Generator<{ path: string; content: Buffer }> {
  let off = 0;
  while (off + 512 <= buf.length) {
    const header = buf.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break; // end-of-archive
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    const sizeOctal = header.subarray(124, 136).toString('utf8').replace(/\0.*$/, '').trim();
    const size = parseInt(sizeOctal || '0', 8) || 0;
    const type = String.fromCharCode(header[156]);
    // ustar long-name prefix (field at 345)
    const prefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/, '');
    const full = prefix ? `${prefix}/${name}` : name;
    off += 512;
    if (type === '0' || type === '\0') {
      yield { path: full, content: buf.subarray(off, off + size) };
    }
    off += Math.ceil(size / 512) * 512;
  }
}

export interface FetchedRepo {
  files: { path: string; content: string }[];
  totalFiles: number;
  skipped: number;
  branch: string;
}

export async function fetchPublicRepo(ref: GithubRepoRef): Promise<FetchedRepo> {
  const branch = await defaultBranch(ref);
  const candidates = [branch, 'main', 'master'].filter((b, i, a) => a.indexOf(b) === i);

  let tarball: Buffer | null = null;
  let used = branch;
  for (const b of candidates) {
    // api.github.com/tarball honors the auth token, so private repos work too.
    const url = githubToken()
      ? `https://api.github.com/repos/${ref.owner}/${ref.repo}/tarball/${b}`
      : `https://codeload.github.com/${ref.owner}/${ref.repo}/tar.gz/refs/heads/${b}`;
    const res = await fetch(url, {
      headers: ghHeaders(),
      cache: 'no-store',
      redirect: 'follow',
    });
    if (!res.ok) continue;
    const raw = Buffer.from(await res.arrayBuffer());
    if (raw.length > MAX_TARBALL_BYTES) {
      throw new Error(`repository too large for the demo scanner (>${Math.round(MAX_TARBALL_BYTES / 1e6)}MB)`);
    }
    tarball = raw;
    used = b;
    break;
  }
  if (!tarball) {
    throw new Error('could not fetch the repository — is it public and spelled correctly?');
  }

  const tar = zlib.gunzipSync(tarball);
  const files: { path: string; content: string }[] = [];
  let totalFiles = 0;
  let skipped = 0;

  for (const entry of untar(tar)) {
    // strip the "<repo>-<branch>/" top-level directory
    const rel = entry.path.split('/').slice(1).join('/');
    if (!rel) continue;
    totalFiles++;
    if (SKIP_DIRS.test(rel) || !SCANNABLE.test(rel)) continue;
    if (entry.content.length > MAX_FILE_BYTES) { skipped++; continue; }
    if (files.length >= MAX_FILES) { skipped++; continue; }
    // binary guard: NUL byte in the first KB → not text
    if (entry.content.subarray(0, 1024).includes(0)) { skipped++; continue; }
    files.push({ path: rel, content: entry.content.toString('utf8') });
  }

  return { files, totalFiles, skipped, branch: used };
}
