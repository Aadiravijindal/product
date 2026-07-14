import Anthropic from '@anthropic-ai/sdk';
import type { Classification, Finding, Review, ReviewIssue, ReviewRound, Scan } from './types';

/**
 * Live LLM calls for classification and patch generation.
 *
 * Uses claude-opus-4-8 with JSON-schema-constrained output (structured
 * outputs beta). Sampling parameters are not set — current Opus models
 * reject them; run-to-run consistency comes from the tightly-scoped prompts
 * and the schema constraint instead.
 */

const MODEL = 'claude-opus-4-8';
const BETAS = ['structured-outputs-2025-11-13'];

export function claudeAvailable(): boolean {
  return Boolean(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN);
}

let client: Anthropic | null = null;
function getClient(): Anthropic {
  // Generous single-shot timeout: the revision round regenerates a whole file
  // and can legitimately take ~60-100s on large inputs. maxRetries: 0 avoids
  // stacking two timeouts back-to-back (which produced a long blank wait).
  if (!client) client = new Anthropic({ timeout: 120_000, maxRetries: 0 });
  return client;
}

function firstText(response: { content: { type: string; text?: string }[] }): string {
  for (const block of response.content) {
    if (block.type === 'text' && block.text) return block.text;
  }
  throw new Error('no text block in response');
}

export async function classifyFinding(finding: Finding): Promise<Classification> {
  const response = await getClient().beta.messages.create({
    model: MODEL,
    max_tokens: 2048,
    betas: BETAS,
    system:
      'You are a cryptography migration assistant embedded in a post-quantum migration tool. Be precise and consistent; identical inputs should produce identical analyses.',
    messages: [
      {
        role: 'user',
        content: `You are a cryptography migration assistant. Given this code snippet (from file "${finding.file}"):

${finding.fullCode}

Identify: (1) the exact cryptographic algorithm and key size used, (2) what it's used for (signing, key exchange, encryption-at-rest, or authentication), (3) a one-to-two sentence plain-English explanation suitable for a non-cryptographer engineering leader, explaining why it needs migration to post-quantum cryptography, referencing the specific business context if inferable from the code (e.g. "payment", "auth").`,
      },
    ],
    output_format: {
      type: 'json_schema',
      schema: {
        type: 'object',
        properties: {
          algorithm: { type: 'string' },
          key_size: { type: 'string' },
          usage_type: {
            type: 'string',
            enum: ['signing', 'key_exchange', 'encryption-at-rest', 'authentication'],
          },
          explanation: { type: 'string' },
        },
        required: ['algorithm', 'key_size', 'usage_type', 'explanation'],
        additionalProperties: false,
      },
    },
  });
  return JSON.parse(firstText(response)) as Classification;
}

export interface RemediationResult {
  patchedCode: string;
  changes: string[];
  newAlgorithm: string;
}

export async function generateRemediation(finding: Finding): Promise<RemediationResult> {
  const isKem = finding.usageType === 'key_exchange';
  const response = await getClient().beta.messages.create({
    model: MODEL,
    max_tokens: 8192,
    betas: BETAS,
    system:
      'You are a cryptography migration assistant embedded in a post-quantum migration tool. Generate correct, minimal, production-plausible patches. Be consistent; identical inputs should produce identical patches.',
    messages: [
      {
        role: 'user',
        content: `You are a cryptography migration assistant. Given this vulnerable ${finding.language} code (from file "${finding.file}"):

${finding.fullCode}

Generate a HYBRID replacement that keeps the original classical algorithm running alongside a NIST-standardized post-quantum algorithm (use ML-DSA-65 / FIPS 204 for signing operations, ML-KEM-768 / FIPS 203 for key exchange operations). The output must be a minimal diff — do not rewrite surrounding logic that doesn't need to change, keep original function names, comments, and structure intact. Use a real library for the language (Python: liboqs-python via "import oqs"; Java: JDK 24+ / BouncyCastle ML-DSA provider names; JavaScript/Node: @noble/post-quantum). Verifiers must check BOTH the classical and post-quantum results during the hybrid period (the draft-ietf-lamps-pq-composite-sigs pattern for signatures${isKem ? ', the X25519MLKEM768 pattern for key exchange' : ''}).

Return the FULL patched file content, a short list of what changed, and a short label for the new algorithm (e.g. "RSA-2048 + ML-DSA-65 (hybrid)").`,
      },
    ],
    output_format: {
      type: 'json_schema',
      schema: {
        type: 'object',
        properties: {
          patched_code: { type: 'string' },
          changes: { type: 'array', items: { type: 'string' } },
          new_algorithm: { type: 'string' },
        },
        required: ['patched_code', 'changes', 'new_algorithm'],
        additionalProperties: false,
      },
    },
  });
  const parsed = JSON.parse(firstText(response)) as {
    patched_code: string;
    changes: string[];
    new_algorithm: string;
  };
  return { patchedCode: parsed.patched_code, changes: parsed.changes, newAlgorithm: parsed.new_algorithm };
}

// ---------------------------------------------------------------------------
// Adversarial patch review — a SEPARATE agent context whose only job is to
// attack the generator's patch. This is the core of the assurance pipeline.
// ---------------------------------------------------------------------------

export async function reviewPatch(finding: Finding, patchedCode: string): Promise<Review> {
  const response = await getClient().beta.messages.create({
    model: MODEL,
    max_tokens: 3072,
    betas: BETAS,
    system:
      'You are an adversarial cryptography security reviewer. You did NOT write the patch you are reviewing; your only job is to find real flaws in it before it reaches production at a bank. Be rigorous but do not invent problems.',
    messages: [
      {
        role: 'user',
        content: `A code-migration agent proposed this hybrid post-quantum patch. Attack it.

ORIGINAL (${finding.file}, ${finding.language}):
${finding.fullCode}

PROPOSED PATCH:
${patchedCode}

Look specifically for: downgrade paths (legacy protocol versions or cipher suites still enabled), missing dual-verification (verifier not requiring BOTH classical and post-quantum results during the hybrid window), private key material logged/returned/exposed, breaking changes to the callable surface, incorrect algorithm parameters or library usage, and backward-compatibility breaks with existing counterparties. Report only real, defensible findings with severity high/medium/low. If the patch is sound, say so.`,
      },
    ],
    output_format: {
      type: 'json_schema',
      schema: {
        type: 'object',
        properties: {
          verdict: { type: 'string', enum: ['approved', 'approved_with_notes', 'needs_revision'] },
          summary: { type: 'string' },
          issues: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                severity: { type: 'string', enum: ['high', 'medium', 'low'] },
                title: { type: 'string' },
                detail: { type: 'string' },
              },
              required: ['severity', 'title', 'detail'],
              additionalProperties: false,
            },
          },
        },
        required: ['verdict', 'summary', 'issues'],
        additionalProperties: false,
      },
    },
  });
  const parsed = JSON.parse(firstText(response)) as {
    verdict: 'approved' | 'approved_with_notes' | 'needs_revision';
    summary: string;
    issues: ReviewIssue[];
  };
  return {
    engine: 'claude',
    verdict: parsed.verdict === 'needs_revision' ? 'revised' : parsed.verdict,
    summary: parsed.summary,
    issues: parsed.issues,
    checksRun: 6,
  };
}

/** One bounded revision round: regenerate the patch with the reviewer's findings attached. */
export async function revisePatch(finding: Finding, patchedCode: string, issues: ReviewIssue[]): Promise<RemediationResult> {
  const response = await getClient().beta.messages.create({
    model: MODEL,
    max_tokens: 8192,
    betas: BETAS,
    system:
      'You are a cryptography migration assistant. Fix the specific reviewer findings in your patch without rewriting unrelated code.',
    messages: [
      {
        role: 'user',
        content: `Your hybrid post-quantum patch for ${finding.file} was reviewed by an independent security reviewer who found these issues:

${issues.map((i) => `- [${i.severity}] ${i.title}: ${i.detail}`).join('\n')}

ORIGINAL FILE:
${finding.fullCode}

YOUR PREVIOUS PATCH:
${patchedCode}

Produce a corrected FULL patched file that resolves every issue while keeping the hybrid (classical + NIST post-quantum) approach and the original callable surface. Also return the updated change list and algorithm label.`,
      },
    ],
    output_format: {
      type: 'json_schema',
      schema: {
        type: 'object',
        properties: {
          patched_code: { type: 'string' },
          changes: { type: 'array', items: { type: 'string' } },
          new_algorithm: { type: 'string' },
        },
        required: ['patched_code', 'changes', 'new_algorithm'],
        additionalProperties: false,
      },
    },
  });
  const parsed = JSON.parse(firstText(response)) as { patched_code: string; changes: string[]; new_algorithm: string };
  return { patchedCode: parsed.patched_code, changes: parsed.changes, newAlgorithm: parsed.new_algorithm };
}

// ---------------------------------------------------------------------------
// Adversarial hardening LOOP — the core differentiator.
//
// A blue-team agent (generator) and a red-team agent (reviewer) go back and
// forth: the reviewer attacks the patch, the generator rewrites it to close
// every flaw, the reviewer attacks the new version — round after round —
// until the reviewer can no longer find a defensible flaw, or a safety cap is
// hit. Each round is one full LLM round-trip, so it is deliberately bounded.
// ---------------------------------------------------------------------------

const MAX_ROUNDS = 3;

export async function hardenPatchLive(
  finding: Finding,
  initial: RemediationResult
): Promise<{ patch: RemediationResult; review: Review }> {
  let patch = initial;
  const rounds: ReviewRound[] = [];

  for (let i = 1; i <= MAX_ROUNDS; i++) {
    const review = await reviewPatch(finding, patch.patchedCode);
    rounds.push({
      round: i,
      verdict: review.verdict,
      issueCount: review.issues.length,
      issues: review.issues,
      summary: review.summary,
    });

    // Converged: the attacker approves, or found nothing actionable to revise.
    if (review.verdict !== 'revised' || review.issues.length === 0) break;

    // Still flawed and we have budget left → generator rewrites and we re-attack.
    if (i < MAX_ROUNDS) {
      patch = await revisePatch(finding, patch.patchedCode, review.issues);
    }
  }

  const last = rounds[rounds.length - 1];
  const converged = last.verdict !== 'revised' || last.issueCount === 0;
  const totalFound = rounds.reduce((n, r) => n + r.issueCount, 0);

  const summary = converged
    ? rounds.length === 1
      ? 'An independent red-team agent attacked the patch and found no defensible flaws on the first pass.'
      : `An independent red-team agent attacked the patch over ${rounds.length} rounds. It surfaced ${totalFound} flaw${totalFound === 1 ? '' : 's'}; the generator rewrote the patch after each round until the reviewer could no longer break it.`
    : `After ${MAX_ROUNDS} hardening rounds, ${last.issueCount} issue${last.issueCount === 1 ? '' : 's'} remained unresolved — this finding is flagged for a human engineer rather than auto-approved.`;

  return {
    patch,
    review: {
      engine: 'claude',
      verdict: converged ? (last.verdict === 'revised' ? 'approved_with_notes' : last.verdict) : 'revised',
      summary,
      issues: last.issues,
      checksRun: rounds.length,
      rounds,
    },
  };
}

// ---------------------------------------------------------------------------
// Migration plan — one agent pass over the whole scan
// ---------------------------------------------------------------------------

export async function generatePlanLive(scan: Scan): Promise<{ summary: string; steps: { order: number; title: string; detail: string; files: string[]; coordination?: string }[] }> {
  const findingsBrief = scan.findings
    .map(
      (f) =>
        `- ${f.file} (lines ${f.lineStart}-${f.lineEnd}): ${f.algorithm}, ${f.usageType}, risk ${f.risk}, status ${f.status}\n  context excerpt:\n${f.snippet
          .split('\n')
          .slice(0, 12)
          .join('\n')}`
    )
    .join('\n\n');
  const response = await getClient().beta.messages.create({
    model: MODEL,
    max_tokens: 4096,
    betas: BETAS,
    system:
      'You are a post-quantum migration planner for enterprise engineering leadership. Produce concrete, dependency-aware rollout plans. Key exchange migrates first (harvest-now-decrypt-later); externally-verified signatures need counterparty coordination; tokens need all verifiers updated before enforcement.',
    messages: [
      {
        role: 'user',
        content: `Create an ordered migration plan for this codebase scan. Findings:

${findingsBrief}

Return 3-6 steps. Each step: a title, a 2-3 sentence rationale an engineering leader can act on, the affected files, and an optional coordination warning (external parties, re-certification, verifier rollout ordering) when the code context implies one.`,
      },
    ],
    output_format: {
      type: 'json_schema',
      schema: {
        type: 'object',
        properties: {
          summary: { type: 'string' },
          steps: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                order: { type: 'integer' },
                title: { type: 'string' },
                detail: { type: 'string' },
                files: { type: 'array', items: { type: 'string' } },
                coordination: { type: 'string' },
              },
              required: ['order', 'title', 'detail', 'files'],
              additionalProperties: false,
            },
          },
        },
        required: ['summary', 'steps'],
        additionalProperties: false,
      },
    },
  });
  return JSON.parse(firstText(response));
}

// ---------------------------------------------------------------------------
// Ask-the-agent — live Q&A grounded in one finding
// ---------------------------------------------------------------------------

export async function askAgent(finding: Finding, question: string): Promise<string> {
  const a = finding.analysis;
  const response = await getClient().beta.messages.create({
    model: MODEL,
    max_tokens: 1024,
    betas: BETAS,
    system:
      'You are the Recrypt migration agent answering a security-conscious engineering leader during a review. Answer only from the provided finding context and established post-quantum cryptography facts (NIST FIPS 203/204/205, hybrid/composite patterns, CNSA 2.0 timelines). Be direct, under 150 words, no headers or bullet lists unless asked.',
    messages: [
      {
        role: 'user',
        content: `FINDING CONTEXT
File: ${finding.file} · ${finding.algorithm} · ${finding.usageType} · risk ${finding.risk} · confidence ${finding.confidence}%

ORIGINAL CODE:
${finding.fullCode.slice(0, 6000)}

${a ? `PROPOSED PATCH (${a.newAlgorithm}):\n${a.patchedCode.slice(0, 6000)}\n\nCHANGES: ${a.changes.join('; ')}` : 'No patch generated yet.'}

QUESTION: ${question.slice(0, 500)}`,
      },
    ],
  });
  return firstText(response);
}
