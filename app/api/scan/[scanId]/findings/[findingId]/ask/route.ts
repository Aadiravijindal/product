import { NextRequest, NextResponse } from 'next/server';
import { getFinding } from '@/lib/store';
import { askAgent, claudeAvailable } from '@/lib/claude';

/** POST { question } — live Q&A grounded in one finding. Requires the Claude API. */
export async function POST(req: NextRequest, ctx: { params: Promise<{ scanId: string; findingId: string }> }) {
  const { scanId, findingId } = await ctx.params;
  const finding = await getFinding(scanId, findingId);
  if (!finding) return NextResponse.json({ error: 'finding not found' }, { status: 404 });

  if (!claudeAvailable()) {
    return NextResponse.json(
      { error: 'Live Q&A needs a Claude API key (ANTHROPIC_API_KEY). Everything else works without it.' },
      { status: 503 }
    );
  }

  let body: { question?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }
  const question = (body.question ?? '').trim();
  if (!question) return NextResponse.json({ error: 'question required' }, { status: 400 });
  if (question.length > 500) return NextResponse.json({ error: 'question too long (500 chars max)' }, { status: 413 });

  try {
    const answer = await askAgent(finding, question);
    return NextResponse.json({ answer });
  } catch {
    return NextResponse.json(
      { error: 'The agent could not answer right now — please retry.' },
      { status: 502 }
    );
  }
}
