import { NextRequest, NextResponse } from 'next/server';
import { appendAudit, getScan, saveScan } from '@/lib/store';
import type { FindingStatus } from '@/lib/types';

const ACTIONS: Record<string, FindingStatus> = {
  approve: 'migrated',
  reject: 'rejected',
  escalate: 'escalated',
};

export async function POST(req: NextRequest, ctx: { params: Promise<{ scanId: string; findingId: string }> }) {
  const { scanId, findingId } = await ctx.params;
  const scan = await getScan(scanId);
  const finding = scan?.findings.find((f) => f.id === findingId);
  if (!scan || !finding) return NextResponse.json({ error: 'finding not found' }, { status: 404 });

  let body: { action?: string; reviewer?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  const status = ACTIONS[body.action ?? ''];
  if (!status) return NextResponse.json({ error: 'action must be approve | reject | escalate' }, { status: 400 });

  finding.status = status;
  finding.reviewer = (body.reviewer || 'Demo User').slice(0, 80);
  finding.reviewedAt = new Date().toISOString();
  await saveScan(scan);
  await appendAudit(finding.reviewer, `Decision: ${body.action} (${finding.algorithm})`, finding.file);
  return NextResponse.json({ finding });
}
