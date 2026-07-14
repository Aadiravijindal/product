import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { Scan } from './types';
import { getSampleRepo } from './samples';
import { PATTERN_COUNT, scanFiles } from './scanner';

/**
 * Scan store with two backends:
 *
 *  - Local / single-process (`next dev`, `next start`, the verify harness):
 *    an in-memory map written through to a JSON file, so scans survive restarts.
 *
 *  - Serverless (Vercel): a shared Redis (Upstash REST) keyed store. On Vercel
 *    every API route is a SEPARATE function with its own memory, so an in-memory
 *    map can never be shared between `/api/scan` and `/api/.../analyze`. Redis is
 *    the shared source of truth. Enabled automatically when the KV/Upstash env
 *    vars are present — no code change, just set them in the Vercel dashboard.
 *
 * Sample-repo scans are additionally *reconstructable* from their scanId alone
 * (the id embeds the repo id, and the sample files + finding ids are
 * deterministic), so the core scan→analyze demo works on any instance even
 * before Redis is configured.
 */

const DATA_FILE = path.join(process.cwd(), '.recrypt-data.json');
const MAX_SCANS = 40;
const ID_SEP = '~';

const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
const KV_ENABLED = Boolean(KV_URL && KV_TOKEN);

export function storeBackend(): 'redis' | 'memory' {
  return KV_ENABLED ? 'redis' : 'memory';
}

// ---------------------------------------------------------------------------
// Redis (Upstash REST) — one command per fetch, values carried in the body so
// large scan JSON is never crammed into a URL.
// ---------------------------------------------------------------------------

async function kv<T = unknown>(command: (string | number)[]): Promise<T> {
  const res = await fetch(KV_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${KV_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(command),
    cache: 'no-store',
  });
  if (!res.ok) throw new Error(`kv ${command[0]} failed: ${res.status}`);
  const data = (await res.json()) as { result: T };
  return data.result;
}

// ---------------------------------------------------------------------------
// In-memory + file backend (local / single process)
// ---------------------------------------------------------------------------

interface MemStore {
  scans: Map<string, Scan>;
}
const g = globalThis as unknown as { __recryptStore?: MemStore };

function loadMem(): MemStore {
  const s: MemStore = { scans: new Map() };
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) as Scan[];
      for (const scan of raw) s.scans.set(scan.id, scan);
    }
  } catch {
    // corrupt/unreadable data file — start fresh rather than crash
  }
  return s;
}

function mem(): MemStore {
  if (!g.__recryptStore) g.__recryptStore = loadMem();
  return g.__recryptStore;
}

function persistMem(): void {
  try {
    const scans = [...mem().scans.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    while (scans.length > MAX_SCANS) mem().scans.delete(scans.pop()!.id);
    fs.writeFileSync(DATA_FILE, JSON.stringify(scans));
  } catch {
    // read-only filesystem — keep operating in-memory
  }
}

// ---------------------------------------------------------------------------
// Sample-repo reconstruction — deterministic rebuild from the scanId
// ---------------------------------------------------------------------------

function reconstructSample(scanId: string): Scan | undefined {
  const sep = scanId.indexOf(ID_SEP);
  if (sep < 0) return undefined;
  const repoId = scanId.slice(0, sep);
  const repo = getSampleRepo(repoId);
  if (!repo) return undefined;
  const findings = scanFiles({ files: repo.files, scanId, repoId: repo.id });
  return {
    id: scanId,
    source: { type: 'repo', repoId: repo.id, repoName: repo.name },
    createdAt: new Date().toISOString(),
    findings,
    stats: { files: repo.files.length, patterns: PATTERN_COUNT, durationMs: 0 },
  };
}

// ---------------------------------------------------------------------------
// Public API (async — Redis calls are network calls)
// ---------------------------------------------------------------------------

/** Scan id. For sample repos the repo id is embedded so the scan can be rebuilt anywhere. */
export function newScanId(repoId?: string): string {
  const rand = crypto.randomBytes(5).toString('hex');
  return repoId ? `${repoId}${ID_SEP}${rand}` : rand;
}

export async function saveScan(scan: Scan): Promise<void> {
  if (KV_ENABLED) {
    await kv(['SET', `scan:${scan.id}`, JSON.stringify(scan)]);
    await kv(['ZADD', 'scans:index', Date.parse(scan.createdAt) || Date.now(), scan.id]);
    // keep the history index bounded
    await kv(['ZREMRANGEBYRANK', 'scans:index', '0', String(-MAX_SCANS - 1)]).catch(() => {});
    return;
  }
  mem().scans.set(scan.id, scan);
  persistMem();
}

export async function getScan(id: string): Promise<Scan | undefined> {
  if (KV_ENABLED) {
    const raw = await kv<string | null>(['GET', `scan:${id}`]);
    if (raw) return JSON.parse(raw) as Scan;
    const rebuilt = reconstructSample(id);
    if (rebuilt) {
      await saveScan(rebuilt);
      return rebuilt;
    }
    return undefined;
  }
  const hit = mem().scans.get(id);
  if (hit) return hit;
  const rebuilt = reconstructSample(id);
  if (rebuilt) {
    mem().scans.set(id, rebuilt);
    return rebuilt;
  }
  return undefined;
}

export async function allScans(): Promise<Scan[]> {
  if (KV_ENABLED) {
    const ids = await kv<string[]>(['ZRANGE', 'scans:index', '0', String(MAX_SCANS - 1), 'REV']);
    if (!ids || ids.length === 0) return [];
    const raw = await kv<(string | null)[]>(['MGET', ...ids.map((i) => `scan:${i}`)]);
    return raw
      .filter((r): r is string => Boolean(r))
      .map((r) => JSON.parse(r) as Scan)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
  return [...mem().scans.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function getFinding(scanId: string, findingId: string) {
  return (await getScan(scanId))?.findings.find((f) => f.id === findingId);
}
