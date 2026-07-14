import { NextRequest, NextResponse } from 'next/server';
import { getScan } from '@/lib/store';
import { buildComplianceReport } from '@/lib/compliance';

/**
 * GET — auditor-facing compliance pack for a scan. Maps every finding to the
 * PCI DSS / DORA / FFIEC / CNSA 2.0 / federal controls it touches and reports
 * per-framework readiness. `?format=json` (default) downloads the machine-readable
 * report; the dashboard also renders a summary from the same builder.
 */
export async function GET(_req: NextRequest, ctx: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await ctx.params;
  const scan = await getScan(scanId);
  if (!scan) return NextResponse.json({ error: 'scan not found' }, { status: 404 });

  const report = buildComplianceReport(scan);
  return new NextResponse(JSON.stringify(report, null, 2), {
    headers: {
      'Content-Type': 'application/json',
      'Content-Disposition': `attachment; filename="recrypt-compliance-${scan.id}.json"`,
    },
  });
}
