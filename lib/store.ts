import crypto from 'crypto';
import type { Scan } from './types';

/**
 * In-memory demo store. Survives Next.js dev-mode module reloads by hanging
 * off globalThis. No database by design — this is a demo.
 */

interface Store {
  scans: Map<string, Scan>;
}

const g = globalThis as unknown as { __recryptStore?: Store };

function store(): Store {
  if (!g.__recryptStore) g.__recryptStore = { scans: new Map() };
  return g.__recryptStore;
}

export function newScanId(): string {
  return crypto.randomBytes(5).toString('hex');
}

export function saveScan(scan: Scan): void {
  store().scans.set(scan.id, scan);
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
