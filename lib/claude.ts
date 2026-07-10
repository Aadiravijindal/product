import Anthropic from '@anthropic-ai/sdk';
import type { Classification, Finding } from './types';

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
  if (!client) client = new Anthropic({ timeout: 60_000, maxRetries: 1 });
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
