import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { Scan } from './types';

/**
 * Write-through store: in-memory map backed by a JSON file, so scans,
 * analyses, and review decisions survive server restarts. No database by
 * design — one file, zero setup.
 */

const DATA_FILE = path.join(process.cwd(), '.recrypt-data.json');
const MAX_SCANS = 40;

interface Store {
  scans: Map<string, Scan>;
}

const g = globalThis as unknown as { __recryptStore?: Store };

function load(): Store {
  const s: Store = { scans: new Map() };
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

function store(): Store {
  if (!g.__recryptStore) g.__recryptStore = load();
  return g.__recryptStore;
}

export function persist(): void {
  try {
    const scans = [...store().scans.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    while (scans.length > MAX_SCANS) {
      const dropped = scans.pop()!;
      store().scans.delete(dropped.id);
    }
    fs.writeFileSync(DATA_FILE, JSON.stringify(scans));
  } catch {
    // read-only filesystem — keep operating in-memory
  }
}

export function newScanId(): string {
  return crypto.randomBytes(5).toString('hex');
}

export function saveScan(scan: Scan): void {
  store().scans.set(scan.id, scan);
  persist();
}

export function getScan(id: string): Scan | undefined {
  return store().scans.get(id);
}

export function allScans(): Scan[] {
  return [...store().scans.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function getFinding(scanId: string, findingId: string) {
  return getScan(scanId)?.findings.find((f) => f.id === findingId);
}
