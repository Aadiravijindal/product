export type RiskLevel = 'Critical' | 'High' | 'Medium';
export type FindingStatus = 'not_reviewed' | 'migrated' | 'rejected' | 'escalated';
export type UsageType = 'signing' | 'key_exchange' | 'encryption' | 'authentication';

export interface TestResult {
  name: string;
  passed: boolean;
  detail: string;
  real: boolean; // true when the check actually executed cryptography, false for static checks
  /** raw cryptographic evidence (key/signature/ciphertext excerpts) produced during the test run */
  evidence?: string;
}

export interface Classification {
  algorithm: string;
  key_size: string;
  usage_type: string;
  explanation: string;
}

export interface Analysis {
  engine: 'claude' | 'builtin';
  engineNote?: string;
  classification: Classification;
  patchedCode: string;
  changes: string[];
  newAlgorithm: string;
  tests: TestResult[];
  generatedAt: string;
}

export interface Finding {
  id: string;
  scanId: string;
  file: string;
  lineStart: number;
  lineEnd: number;
  language: string;
  findingKey: string;
  algorithm: string;
  usageType: UsageType;
  risk: RiskLevel;
  confidence: number;
  status: FindingStatus;
  reviewer?: string;
  reviewedAt?: string;
  fullCode: string;
  snippet: string;
  analysis?: Analysis;
  analysisError?: string;
}

export interface Scan {
  id: string;
  source: { type: 'repo'; repoId: string; repoName: string } | { type: 'snippet'; label: string };
  createdAt: string;
  findings: Finding[];
  stats?: { files: number; patterns: number; durationMs: number };
}

export interface SampleRepoMeta {
  id: string;
  name: string;
  language: string;
  description: string;
  fileCount: number;
}
