import { NextRequest, NextResponse } from 'next/server';
import { appendAudit, newScanId, saveScan } from '@/lib/store';
import { PATTERN_COUNT } from '@/lib/scanner';
import type { Finding, RiskLevel, Scan, UsageType } from '@/lib/types';

/**
 * POST /api/import/cbom — ingest a CycloneDX-style CBOM produced by a
 * discovery tool (IBM Quantum Safe, SandboxAQ AQtive Guard, cbomkit, …) and
 * turn its crypto components into Recrypt findings, ready for the
 * remediation pipeline. This is the "sit on top of the incumbents" path:
 * their inventory in, our fixes out.
 *
 * Accepts the CycloneDX 1.6 crypto shape (components[].cryptoProperties) and
 * degrades gracefully to name/description matching for looser exports.
 */

interface CdxComponent {
  name?: string;
  type?: string;
  description?: string;
  cryptoProperties?: {
    assetType?: string;
    algorithmProperties?: { variant?: string; primitive?: string; parameterSetIdentifier?: string };
    oid?: string;
  };
  evidence?: { occurrences?: { location?: string }[] };
}

const VULNERABLE = /\b(rsa|ecdsa|ecdh|ec|dsa|dh|diffie|x25519|ed25519|secp\d+|prime256|p-256|p-384|rs256|es256)\b/i;
const SAFE = /\b(ml-kem|ml-dsa|kyber|dilithium|sphincs|slh-dsa|falcon|aes|sha-?\d|hmac|chacha)\b/i;

function usageFor(primitive: string | undefined, text: string): UsageType {
  const p = (primitive || '').toLowerCase();
  if (p.includes('kem') || p.includes('key-agree') || /ecdh|diffie|x25519|key.?exchange|tls/i.test(text)) return 'key_exchange';
  if (p.includes('signature') || /sign|jwt|rs256|es256|certificate/i.test(text)) return 'signing';
  if (/token|auth|session/i.test(text)) return 'authentication';
  return 'encryption';
}

function riskFor(usage: UsageType, text: string): RiskLevel {
  if (usage === 'key_exchange') return 'Critical'; // harvest-now-decrypt-later
  if (/payment|settlement|pci|prod/i.test(text)) return 'Critical';
  if (usage === 'signing' || usage === 'authentication') return 'High';
  return 'Medium';
}

export async function POST(req: NextRequest) {
  let doc: { bomFormat?: string; components?: CdxComponent[]; metadata?: { tools?: { name?: string }[] | { components?: { name?: string }[] } } };
  try {
    doc = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON — paste the CBOM document itself' }, { status: 400 });
  }
  const components = Array.isArray(doc.components) ? doc.components : [];
  if (components.length === 0) {
    return NextResponse.json({ error: 'no components[] found — is this a CycloneDX CBOM export?' }, { status: 422 });
  }
  if (components.length > 2000) {
    return NextResponse.json({ error: 'CBOM too large for the demo (2000 components max)' }, { status: 413 });
  }

  const toolsRaw = doc.metadata?.tools;
  const toolName = Array.isArray(toolsRaw) ? toolsRaw[0]?.name : toolsRaw?.components?.[0]?.name;

  const scanId = newScanId();
  const findings: Finding[] = [];
  let seq = 0;
  let skippedSafe = 0;

  for (const c of components) {
    const cp = c.cryptoProperties;
    const text = [c.name, c.description, cp?.algorithmProperties?.variant, cp?.algorithmProperties?.parameterSetIdentifier]
      .filter(Boolean)
      .join(' ');
    const isCryptoAsset = cp?.assetType === 'algorithm' || cp?.assetType === 'certificate' || cp?.assetType === 'protocol' || VULNERABLE.test(text);
    if (!isCryptoAsset) continue;
    if (SAFE.test(text) && !VULNERABLE.test(text)) { skippedSafe++; continue; }
    if (!VULNERABLE.test(text)) continue;

    const algorithm = cp?.algorithmProperties?.variant || cp?.algorithmProperties?.parameterSetIdentifier || (text.match(VULNERABLE)?.[0] ?? 'RSA').toUpperCase();
    const usage = usageFor(cp?.algorithmProperties?.primitive, text);
    const location = c.evidence?.occurrences?.[0]?.location || c.name || `component-${seq}`;
    const reference = JSON.stringify(c, null, 2).slice(0, 4000);

    findings.push({
      id: `f_${scanId}_${seq++}`,
      scanId,
      file: location,
      lineStart: 1,
      lineEnd: 1,
      language: 'cbom',
      findingKey: usage === 'key_exchange' ? 'ecdh-key-exchange' : 'rsa-signing',
      algorithm,
      usageType: usage,
      risk: riskFor(usage, text),
      confidence: cp ? 90 : 70,
      status: 'not_reviewed',
      fullCode: `// Imported from ${toolName || 'discovery-tool'} CBOM — component evidence:\n${reference}`,
      snippet: reference.split('\n').slice(0, 14).join('\n'),
    });
  }

  if (findings.length === 0) {
    return NextResponse.json({ error: `parsed ${components.length} components but none are quantum-vulnerable crypto assets${skippedSafe ? ` (${skippedSafe} already post-quantum)` : ''}` }, { status: 422 });
  }

  const scan: Scan = {
    id: scanId,
    source: { type: 'cbom', label: `CBOM import (${components.length} components)`, tool: toolName },
    createdAt: new Date().toISOString(),
    findings,
    stats: { files: components.length, patterns: PATTERN_COUNT, durationMs: 0 },
  };
  await saveScan(scan);
  await appendAudit('importer', `CBOM ingested: ${components.length} components → ${findings.length} vulnerable findings${skippedSafe ? `, ${skippedSafe} already PQC` : ''}`, toolName || 'cyclonedx');
  return NextResponse.json({ scanId, findingCount: findings.length, skippedSafe });
}
