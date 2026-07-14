import { NextRequest, NextResponse } from 'next/server';
import { POLICIES } from '@/lib/platform';
import { checkToken } from '@/lib/platform';
import { appendAudit, getPolicyState, savePolicyState } from '@/lib/store';

/**
 * The live policy engine. GET returns rules with their persisted
 * enabled/monitor state; PATCH flips a rule (console session required);
 * POST /check runs pasted code through the real detection engine and maps
 * findings to policy verdicts — the same logic the CI gate enforces.
 */

export async function GET() {
  const overrides = await getPolicyState();
  const rules = POLICIES.map((p) => ({
    ...p,
    status: overrides[p.id] === undefined ? p.status : overrides[p.id] ? 'enforcing' : 'monitor',
  }));
  return NextResponse.json({ rules });
}

export async function PATCH(req: NextRequest) {
  if (!checkToken(req.cookies.get('recrypt_platform')?.value)) {
    return NextResponse.json({ error: 'console sign-in required' }, { status: 401 });
  }
  let body: { id?: string; enforcing?: boolean };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }
  const rule = POLICIES.find((p) => p.id === body.id);
  if (!rule || typeof body.enforcing !== 'boolean') {
    return NextResponse.json({ error: 'provide a valid rule id and enforcing:boolean' }, { status: 400 });
  }
  const state = await getPolicyState();
  state[rule.id] = body.enforcing;
  await savePolicyState(state);
  await appendAudit('console-owner', `Policy ${body.enforcing ? 'set to ENFORCING' : 'set to monitor-only'}`, rule.id);
  return NextResponse.json({ ok: true, id: rule.id, status: body.enforcing ? 'enforcing' : 'monitor' });
}
