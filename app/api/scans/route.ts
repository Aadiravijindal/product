import { NextResponse } from 'next/server';
import { allScans } from '@/lib/store';

/** GET — scan history summaries for the home screen. */
export async function GET() {
  const scans = allScans().map((s) => {
    const migrated = s.findings.filter((f) => f.status === 'migrated').length;
    return {
      id: s.id,
      name: s.source.type === 'repo' ? s.source.repoName : 'Pasted snippet',
      createdAt: s.createdAt,
      findings: s.findings.length,
      migrated,
      critical: s.findings.filter((f) => f.risk === 'Critical').length,
    };
  });
  return NextResponse.json({ scans: scans.slice(0, 8) });
}
