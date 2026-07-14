import { NextRequest, NextResponse } from 'next/server';
import { POLICIES } from '@/lib/platform';
import { getPolicyState } from '@/lib/store';
import { scanFiles } from '@/lib/scanner';
import type { UsageType } from '@/lib/types';

/**
 * POST { code, filename? } — run a snippet/diff through the real detection
 * engine and return the policy verdict: which enabled rules it violates.
 * This is the same decision a merge would face at the CI gate.
 */

const RULE_FOR_USAGE: Record<UsageType, string> = {
  signing: 'pol-1',
  authentication: 'pol-4',
  key_exchange: 'pol-2',
  encryption: 'pol-1',
};

export async function POST(req: NextRequest) {
  let body: { code?: string; filename?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }
  const code = (body.code ?? '').trim();
  if (!code) return NextResponse.json({ error: 'code required' }, { status: 400 });
  if (code.length > 200_000) return NextResponse.json({ error: 'too large (200 KB max)' }, { status: 413 });

  const findings = scanFiles({
    files: [{ path: body.filename || 'policy-check-input', content: code }],
    scanId: 'policycheck',
  });

  const overrides = await getPolicyState();
  const isEnforcing = (id: string) => {
    const rule = POLICIES.find((p) => p.id === id);
    if (!rule) return false;
    return overrides[id] === undefined ? rule.status === 'enforcing' : overrides[id];
  };

  const violations = findings.map((f) => {
    const ruleId = RULE_FOR_USAGE[f.usageType];
    const rule = POLICIES.find((p) => p.id === ruleId)!;
    const enforcing = isEnforcing(ruleId);
    return {
      line: f.lineStart,
      algorithm: f.algorithm,
      usageType: f.usageType,
      ruleId,
      rule: rule.rule,
      action: enforcing ? 'BLOCK' : 'WARN',
    };
  });

  const blocked = violations.some((v) => v.action === 'BLOCK');
  return NextResponse.json({
    verdict: blocked ? 'blocked' : violations.length > 0 ? 'warn' : 'pass',
    wouldMerge: !blocked,
    violations,
  });
}
