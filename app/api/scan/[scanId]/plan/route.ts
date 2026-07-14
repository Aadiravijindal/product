import { NextRequest, NextResponse } from 'next/server';
import { getScan, saveScan } from '@/lib/store';
import { claudeAvailable, generatePlanLive } from '@/lib/claude';
import { builtinPlan } from '@/lib/assurance';

/** Vercel: the live plan call can exceed the default function timeout. */
export const maxDuration = 120;

/** POST — generate (or return the cached) dependency-aware migration plan for a scan. */
export async function POST(_req: NextRequest, ctx: { params: Promise<{ scanId: string }> }) {
  const { scanId } = await ctx.params;
  const scan = await getScan(scanId);
  if (!scan) return NextResponse.json({ error: 'scan not found' }, { status: 404 });
  if (scan.findings.length === 0) return NextResponse.json({ error: 'nothing to plan — no findings' }, { status: 400 });

  if (scan.plan) return NextResponse.json({ plan: scan.plan });

  if (claudeAvailable()) {
    try {
      const live = await generatePlanLive(scan);
      scan.plan = {
        engine: 'claude',
        summary: live.summary,
        steps: live.steps,
        generatedAt: new Date().toISOString(),
      };
    } catch {
      scan.plan = builtinPlan(scan);
    }
  } else {
    scan.plan = builtinPlan(scan);
  }

  await saveScan(scan);
  return NextResponse.json({ plan: scan.plan });
}
