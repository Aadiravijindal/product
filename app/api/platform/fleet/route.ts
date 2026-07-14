import { NextRequest, NextResponse } from 'next/server';
import { AUDIT_SEED, EXCEPTIONS, FIX_RUNS, FLEET, POLICIES, checkToken, fleetSummary, ownerEmail } from '@/lib/platform';
import { allScans, listAudit, listFixRuns } from '@/lib/store';

/**
 * GET — full console payload. Requires the owner session cookie.
 * Real data (actual scans, fix runs, audit events from this deployment) is
 * merged in front of the labeled representative simulation.
 */
export async function GET(req: NextRequest) {
  if (!checkToken(req.cookies.get('recrypt_platform')?.value)) {
    return NextResponse.json({ error: 'not signed in' }, { status: 401 });
  }

  const [scans, realRuns, realAudit] = await Promise.all([allScans(), listFixRuns(), listAudit()]);

  // Live rows: fold the most recent real scan per source into the fleet view.
  const latestBySource = new Map<string, { scanId: string; open: number; critical: number; high: number; medium: number; migrated: number; when: string }>();
  for (const s of scans) {
    const name = s.source.type === 'repo' || s.source.type === 'github' ? s.source.repoName : s.source.label;
    if (latestBySource.has(name)) continue; // scans are newest-first
    const open = s.findings.filter((f) => f.status !== 'migrated');
    latestBySource.set(name, {
      scanId: s.id,
      open: open.length,
      critical: open.filter((f) => f.risk === 'Critical').length,
      high: open.filter((f) => f.risk === 'High').length,
      medium: open.filter((f) => f.risk === 'Medium').length,
      migrated: s.findings.filter((f) => f.status === 'migrated').length,
      when: s.createdAt,
    });
  }

  const repos = FLEET.map((r) => {
    if (!r.live) return r;
    const real = latestBySource.get(r.name);
    if (!real) return r;
    return {
      ...r,
      critical: real.critical,
      high: real.high,
      medium: real.medium,
      migrated: real.migrated,
      lastScanDaysAgo: Math.floor((Date.now() - Date.parse(real.when)) / 86_400_000),
      scanId: real.scanId,
    };
  });

  // Real GitHub/CBOM scans appear as extra live rows at the top.
  const extraRows = [...latestBySource.entries()]
    .filter(([name]) => !FLEET.some((r) => r.name === name) && name !== 'Pasted snippet')
    .slice(0, 10)
    .map(([name, real]) => ({
      id: `real-${name}`,
      name,
      team: 'Connected',
      language: '—',
      critical: real.critical,
      high: real.high,
      medium: real.medium,
      migrated: real.migrated,
      lastScanDaysAgo: Math.floor((Date.now() - Date.parse(real.when)) / 86_400_000),
      live: true,
      scanId: real.scanId,
    }));

  return NextResponse.json({
    owner: ownerEmail(),
    summary: fleetSummary(),
    repos: [...extraRows, ...repos],
    fixRuns: { real: realRuns, simulated: FIX_RUNS },
    policies: POLICIES,
    exceptions: EXCEPTIONS,
    audit: { real: realAudit, seed: AUDIT_SEED },
  });
}
