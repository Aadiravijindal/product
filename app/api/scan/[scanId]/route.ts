import { NextRequest, NextResponse } from 'next/server';
import { getScan } from '@/lib/store';

export async function GET(_req: NextRequest, ctx: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await ctx.params;
  const scan = await getScan(scanId);
  if (!scan) return NextResponse.json({ error: 'scan not found — rescan from the home page' }, { status: 404 });
  return NextResponse.json({ scan });
}
