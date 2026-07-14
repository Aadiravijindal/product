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

export interface ReviewIssue {
  severity: 'high' | 'medium' | 'low';
  title: string;
  detail: string;
  resolved?: boolean;
}

/** One pass of the red-team/blue-team loop: the attacker's verdict on the current patch. */
export interface ReviewRound {
  round: number;
  verdict: 'approved' | 'approved_with_notes' | 'revised';
  issueCount: number;
  issues: ReviewIssue[];
  summary: string;
}

export interface Review {
  engine: 'claude' | 'builtin';
  verdict: 'approved' | 'approved_with_notes' | 'revised';
  summary: string;
  issues: ReviewIssue[];
  checksRun: number;
  /** the full attack→harden→re-attack history; last entry is the final state */
  rounds?: ReviewRound[];
}

export interface HndlAssessment {
  label: string;   // e.g. "Migrate by 2028" or "Already exposed"
  detail: string;  // the Mosca-style reasoning, one sentence
  urgent: boolean;
}

export interface Analysis {
  engine: 'claude' | 'builtin';
  engineNote?: string;
  classification: Classification;
  patchedCode: string;
  changes: string[];
  newAlgorithm: string;
  tests: TestResult[];
  /** independent adversarial review of the generated patch */
  review?: Review;
  /** SHA-256 over original code + patch + test evidence — the tamper-evident proof bundle */
  digest?: string;
  /** harvest-now-decrypt-later exposure window (Mosca-style) */
  hndl?: HndlAssessment;
  generatedAt: string;
}

export interface PlanStep {
  order: number;
  title: string;
  detail: string;
  files: string[];
  coordination?: string;
}

export interface MigrationPlan {
  engine: 'claude' | 'builtin';
  summary: string;
  steps: PlanStep[];
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
  plan?: MigrationPlan;
}

export interface SampleRepoMeta {
  id: string;
  name: string;
  language: string;
  description: string;
  fileCount: number;
}
