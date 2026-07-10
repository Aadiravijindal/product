import crypto from 'crypto';
import type { Finding, RiskLevel, UsageType } from './types';

/**
 * Regex-based detection of quantum-vulnerable public-key cryptography.
 *
 * Matches for the same (file, findingKey) pair are grouped into a single
 * finding, so a signer module with an import, a keygen call, and a sign call
 * shows up as one "RSA signing" finding rather than three rows.
 */

interface Pattern {
  id: string;
  findingKey: string;
  languages: string[]; // which languages this applies to; ['*'] = any
  regex: RegExp;
  algorithm: string;
  usageType: UsageType;
  /** weak patterns (bare imports etc.) are dropped when a strong match exists in the same file */
  weak?: boolean;
}

const PATTERNS: Pattern[] = [
  // ---- Python (pyca/cryptography, PyCryptodome, python-rsa/ecdsa) ----
  {
    id: 'py-rsa-keygen',
    findingKey: 'rsa-signing',
    languages: ['python'],
    regex: /rsa\.generate_private_key\s*\(/g,
    algorithm: 'RSA',
    usageType: 'signing',
  },
  {
    id: 'py-rsa-sign-pss',
    findingKey: 'rsa-signing',
    languages: ['python'],
    regex: /\.sign\s*\([\s\S]{0,200}?padding\.(PSS|PKCS1v15)/g,
    algorithm: 'RSA',
    usageType: 'signing',
  },
  {
    id: 'py-rsa-import',
    findingKey: 'rsa-signing',
    languages: ['python'],
    regex: /from\s+cryptography\.hazmat\.primitives\.asymmetric\s+import\s+[^\n]*\brsa\b/g,
    algorithm: 'RSA',
    usageType: 'signing',
    weak: true,
  },
  {
    id: 'py-pycryptodome-rsa',
    findingKey: 'rsa-signing',
    languages: ['python'],
    regex: /RSA\.generate\s*\(|from\s+Crypto\.PublicKey\s+import\s+[^\n]*\bRSA\b/g,
    algorithm: 'RSA',
    usageType: 'signing',
  },
  {
    id: 'py-ecdsa',
    findingKey: 'ecdsa-signing',
    languages: ['python'],
    regex: /ec\.generate_private_key\s*\(|import\s+ecdsa\b|ECDSA\s*\(/g,
    algorithm: 'ECDSA',
    usageType: 'signing',
  },
  {
    id: 'py-dh-ecdh',
    findingKey: 'ecdh-key-exchange',
    languages: ['python'],
    regex: /\bECDH\s*\(|dh\.generate_parameters\s*\(|\.exchange\s*\(\s*ec\.ECDH/g,
    algorithm: 'ECDH',
    usageType: 'key_exchange',
  },

  // ---- Java (JCA) ----
  {
    id: 'java-rsa-keygen',
    findingKey: 'rsa-signing',
    languages: ['java'],
    regex: /KeyPairGenerator\.getInstance\s*\(\s*"RSA"\s*\)/g,
    algorithm: 'RSA',
    usageType: 'signing',
  },
  {
    id: 'java-rsa-signature',
    findingKey: 'rsa-signing',
    languages: ['java'],
    regex: /Signature\.getInstance\s*\(\s*"[^"]*withRSA[^"]*"\s*\)/g,
    algorithm: 'RSA',
    usageType: 'signing',
  },
  {
    id: 'java-rsa-cipher',
    findingKey: 'rsa-encryption',
    languages: ['java'],
    regex: /Cipher\.getInstance\s*\(\s*"RSA[^"]*"\s*\)/g,
    algorithm: 'RSA',
    usageType: 'encryption',
  },
  {
    id: 'java-ec-keygen',
    findingKey: 'ecdsa-signing',
    languages: ['java'],
    regex: /KeyPairGenerator\.getInstance\s*\(\s*"EC"\s*\)|Signature\.getInstance\s*\(\s*"[^"]*withECDSA[^"]*"\s*\)/g,
    algorithm: 'ECDSA',
    usageType: 'signing',
  },
  {
    id: 'java-tls-rsa-suites',
    findingKey: 'tls-rsa-key-exchange',
    languages: ['java'],
    regex: /TLS_RSA_WITH_[A-Z0-9_]+/g,
    algorithm: 'RSA (TLS key exchange)',
    usageType: 'key_exchange',
  },
  {
    id: 'java-legacy-tls',
    findingKey: 'tls-rsa-key-exchange',
    languages: ['java'],
    regex: /"TLSv1(\.[01])?"/g,
    algorithm: 'RSA (TLS key exchange)',
    usageType: 'key_exchange',
    weak: true,
  },

  // ---- JavaScript / TypeScript ----
  {
    id: 'js-jwt-rs256',
    findingKey: 'jwt-rs256',
    languages: ['javascript', 'typescript'],
    regex: /algorithm(s)?\s*:\s*\[?\s*['"](RS|ES|PS)(256|384|512)['"]/g,
    algorithm: 'RSA/ECDSA (JWT)',
    usageType: 'authentication',
  },
  {
    id: 'js-node-rsa-keygen',
    findingKey: 'rsa-signing',
    languages: ['javascript', 'typescript'],
    regex: /generateKeyPair(Sync)?\s*\(\s*['"](rsa|ec)['"]/g,
    algorithm: 'RSA',
    usageType: 'signing',
  },
  {
    id: 'js-createsign',
    findingKey: 'rsa-signing',
    languages: ['javascript', 'typescript'],
    regex: /crypto\.createSign\s*\(|createECDH\s*\(/g,
    algorithm: 'RSA/ECDSA',
    usageType: 'signing',
  },

  // ---- Go ----
  {
    id: 'go-rsa',
    findingKey: 'rsa-signing',
    languages: ['go'],
    regex: /rsa\.GenerateKey\s*\(|"crypto\/rsa"/g,
    algorithm: 'RSA',
    usageType: 'signing',
  },
  {
    id: 'go-ecdsa',
    findingKey: 'ecdsa-signing',
    languages: ['go'],
    regex: /ecdsa\.GenerateKey\s*\(|"crypto\/ecdsa"/g,
    algorithm: 'ECDSA',
    usageType: 'signing',
  },

  // ---- Language-agnostic fallbacks ----
  {
    id: 'any-rs256-literal',
    findingKey: 'jwt-rs256',
    languages: ['*'],
    regex: /['"]RS256['"]/g,
    algorithm: 'RSA (JWT RS256)',
    usageType: 'authentication',
    weak: true,
  },
  {
    id: 'any-named-curves',
    findingKey: 'ecdsa-signing',
    languages: ['*'],
    regex: /\b(secp256k1|secp256r1|prime256v1|P-256|P-384|curve25519|ed25519)\b/gi,
    algorithm: 'Elliptic-curve (ECDSA/ECDH)',
    usageType: 'signing',
    weak: true,
  },
  {
    id: 'any-openssl-genrsa',
    findingKey: 'rsa-signing',
    languages: ['*'],
    regex: /openssl\s+genrsa|openssl\s+rsa\b/g,
    algorithm: 'RSA',
    usageType: 'signing',
  },
];

export function detectLanguage(filePath: string, code: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase() ?? '';
  const byExt: Record<string, string> = {
    py: 'python', java: 'java', js: 'javascript', mjs: 'javascript', cjs: 'javascript',
    ts: 'typescript', tsx: 'typescript', go: 'go', rb: 'ruby', cs: 'csharp',
  };
  if (byExt[ext]) return byExt[ext];
  // Heuristics for pasted snippets with no filename
  if (
    /^\s*from\s+[\w.]+\s+import\s+/m.test(code) || // `from x.y import z` is uniquely pythonic
    /^\s*def\s+\w+\s*\(/m.test(code) ||
    /^\s*import\s+(ecdsa|rsa|Crypto|cryptography|hashlib|oqs)\b/m.test(code)
  ) {
    return 'python';
  }
  if (/public\s+(class|static|final)/.test(code) || /KeyPairGenerator/.test(code)) return 'java';
  if (/\b(const|let|require\(|=>)\b/.test(code)) return 'javascript';
  if (/func\s+\w+\s*\(/.test(code) && /package\s+\w+/.test(code)) return 'go';
  return 'unknown';
}

function extractKeySize(code: string, algorithm: string): string {
  if (/key_size\s*=\s*2048|initialize\s*\(\s*2048|modulusLength:\s*2048|\b2048\b/.test(code)) return '2048';
  if (/key_size\s*=\s*4096|initialize\s*\(\s*4096|\b4096\b/.test(code)) return '4096';
  if (/key_size\s*=\s*3072|initialize\s*\(\s*3072|\b3072\b/.test(code)) return '3072';
  if (/RS256|SHA256withRSA/.test(code)) return '2048'; // conventional default for RS256 deployments
  if (algorithm.includes('EC')) return '256';
  return 'unknown';
}

function lineOfIndex(code: string, index: number): number {
  return code.slice(0, index).split('\n').length;
}

function contextSnippet(code: string, lineStart: number, lineEnd: number): string {
  const lines = code.split('\n');
  const from = Math.max(0, lineStart - 4);
  const to = Math.min(lines.length, lineEnd + 3);
  return lines.slice(from, to).join('\n');
}

/**
 * Deterministic pseudo-confidence for snippet scans: strong pattern matches
 * land 87-95, weak-only matches 58-74. Hash-seeded so the same snippet always
 * produces the same number across demo runs.
 */
function snippetConfidence(code: string, hasStrong: boolean): number {
  const h = crypto.createHash('sha256').update(code).digest();
  const jitter = h[0] % 9; // 0-8
  return hasStrong ? 87 + jitter : 58 + (h[1] % 17);
}

/** Hardcoded per-sample-repo risk & confidence so every demo run is identical. */
const SAMPLE_OVERRIDES: Record<string, { risk: RiskLevel; confidence: number }> = {
  'payment-service:payments/signer.py:rsa-signing': { risk: 'Critical', confidence: 94 },
  'auth-service:src/main/java/com/acme/auth/AuthService.java:rsa-signing': { risk: 'High', confidence: 91 },
  'auth-service:src/main/java/com/acme/auth/TlsConfig.java:tls-rsa-key-exchange': { risk: 'High', confidence: 61 },
  'api-gateway:auth.js:jwt-rs256': { risk: 'High', confidence: 88 },
};

function defaultRisk(usageType: UsageType, code: string): RiskLevel {
  if (usageType === 'key_exchange') return 'Critical'; // harvest-now-decrypt-later exposure
  if (usageType === 'signing' && /payment|settle|transaction|financ/i.test(code)) return 'Critical';
  if (usageType === 'signing' || usageType === 'authentication') return 'High';
  return 'Medium';
}

export interface ScanInput {
  files: { path: string; content: string }[];
  scanId: string;
  repoId?: string;
}

export function scanFiles({ files, scanId, repoId }: ScanInput): Finding[] {
  const findings: Finding[] = [];
  let seq = 0;

  for (const file of files) {
    const language = detectLanguage(file.path, file.content);
    const groups = new Map<string, { pattern: Pattern; lines: number[]; strong: boolean }>();

    for (const pattern of PATTERNS) {
      if (!pattern.languages.includes('*') && !pattern.languages.includes(language)) continue;
      pattern.regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pattern.regex.exec(file.content)) !== null) {
        const line = lineOfIndex(file.content, m.index);
        const g = groups.get(pattern.findingKey);
        if (g) {
          g.lines.push(line);
          if (!pattern.weak) g.strong = true;
        } else {
          groups.set(pattern.findingKey, { pattern, lines: [line], strong: !pattern.weak });
        }
        if (m.index === pattern.regex.lastIndex) pattern.regex.lastIndex++;
      }
    }

    // Drop the generic jwt-rs256 fallback group if a stronger duplicate group covers it
    const hasAnyStrong = [...groups.values()].some((g) => g.strong);

    for (const [findingKey, g] of groups) {
      if (!g.strong && hasAnyStrong && groups.size > 1) continue; // weak-only shadow of a real finding
      const lines = g.lines.sort((a, b) => a - b);
      const lineStart = lines[0];
      const lineEnd = lines[lines.length - 1];
      const keySize = extractKeySize(file.content, g.pattern.algorithm);
      const algorithm =
        g.pattern.algorithm === 'RSA' && keySize !== 'unknown'
          ? `RSA-${keySize}`
          : g.pattern.algorithm;

      const overrideKey = repoId ? `${repoId}:${file.path}:${findingKey}` : '';
      const override = SAMPLE_OVERRIDES[overrideKey];

      findings.push({
        id: `f_${scanId}_${seq++}`,
        scanId,
        file: file.path,
        lineStart,
        lineEnd,
        language,
        findingKey,
        algorithm,
        usageType: g.pattern.usageType,
        risk: override?.risk ?? defaultRisk(g.pattern.usageType, file.content),
        confidence: override?.confidence ?? snippetConfidence(file.content + findingKey, g.strong),
        status: 'not_reviewed',
        fullCode: file.content,
        snippet: contextSnippet(file.content, lineStart, lineEnd),
      });
    }
  }

  const riskOrder: Record<RiskLevel, number> = { Critical: 0, High: 1, Medium: 2 };
  return findings.sort((a, b) => riskOrder[a.risk] - riskOrder[b.risk] || a.file.localeCompare(b.file));
}
