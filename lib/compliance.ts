import type { Finding, Scan, UsageType } from './types';

/**
 * Compliance mapping — turn each crypto finding into the specific regulatory
 * controls it touches, and roll the scan up into an auditor-facing readiness
 * report per framework. This is the "prove it to my auditor / board" layer:
 * findings are meaningless to a compliance officer until they map to PCI / DORA /
 * FFIEC / CNSA / the federal mandate.
 *
 * Mappings are grounded in the published requirements; deadlines follow the
 * NIST/CNSA 2.0 and US federal PQC timelines. This is guidance, not legal advice.
 */

export interface ComplianceControl {
  framework: string;
  control: string;
  requirement: string;
  deadline?: string;
}

// Controls that apply to every quantum-vulnerable public-key usage.
const BASE: ComplianceControl[] = [
  { framework: 'NIST PQC', control: 'FIPS 203 / 204 / 205', requirement: 'Adopt NIST-standardized post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA).', deadline: 'standards final Aug 2024' },
  { framework: 'US Federal', control: 'NSM-10 / OMB M-23-02 / EO 14412', requirement: 'Inventory and migrate vulnerable cryptography to post-quantum.', deadline: '2030–2031' },
];

const BY_USAGE: Record<UsageType, ComplianceControl[]> = {
  key_exchange: [
    { framework: 'CNSA 2.0', control: 'Key establishment', requirement: 'Transition key establishment to ML-KEM; hybrid during migration.', deadline: 'begin now · 2030' },
    { framework: 'PCI DSS 4.0', control: 'Req. 4.2', requirement: 'Strong cryptography for cardholder data in transit; account for harvest-now-decrypt-later.', deadline: 'in force' },
    { framework: 'DORA', control: 'Art. 9 (ICT protection)', requirement: 'Encryption of data in transit resilient to evolving threats.', deadline: 'in force (EU)' },
    { framework: 'FFIEC', control: 'Security · Encryption', requirement: 'Protect data in transit with current, non-deprecated cryptography.', deadline: 'in force' },
  ],
  signing: [
    { framework: 'CNSA 2.0', control: 'Digital signatures', requirement: 'Transition software/firmware and general signing to ML-DSA.', deadline: '2030 · exclusive 2033' },
    { framework: 'PCI DSS 4.0', control: 'Req. 6.2 / 3.6', requirement: 'Secure cryptographic key and signature management.', deadline: 'in force' },
    { framework: 'DORA', control: 'Art. 9', requirement: 'Integrity controls for critical ICT assets.', deadline: 'in force (EU)' },
  ],
  authentication: [
    { framework: 'CNSA 2.0', control: 'Authentication / signatures', requirement: 'Token and assertion signing must move to ML-DSA (hybrid during migration).', deadline: '2030–2031' },
    { framework: 'PCI DSS 4.0', control: 'Req. 8 / 4.2', requirement: 'Strong cryptography protecting authentication material and sessions.', deadline: 'in force' },
    { framework: 'DORA', control: 'Art. 9', requirement: 'Authentication resilient against cryptographic compromise.', deadline: 'in force (EU)' },
  ],
  encryption: [
    { framework: 'PCI DSS 4.0', control: 'Req. 3.5', requirement: 'Render stored account data unreadable with strong cryptography.', deadline: 'in force' },
    { framework: 'DORA', control: 'Art. 9', requirement: 'Encryption of data at rest.', deadline: 'in force (EU)' },
    { framework: 'FFIEC', control: 'Security · Encryption', requirement: 'Protect sensitive data at rest with current cryptography.', deadline: 'in force' },
  ],
};

export function controlsFor(finding: Finding): ComplianceControl[] {
  return [...BASE, ...(BY_USAGE[finding.usageType] ?? [])];
}

export interface FrameworkStatus {
  name: string;
  applicableFindings: number;
  migratedFindings: number;
  ready: boolean;
}

export interface ComplianceReport {
  format: 'recrypt-compliance';
  version: number;
  generatedAt: string;
  system: string;
  scanId: string;
  summary: string;
  frameworks: FrameworkStatus[];
  findings: {
    file: string;
    lines: [number, number];
    algorithm: string;
    usageType: string;
    status: string;
    migratedTo: string | null;
    equivalenceTests: string | null;
    proofDigest: string | null;
    controls: ComplianceControl[];
  }[];
}

export function buildComplianceReport(scan: Scan): ComplianceReport {
  const migratedStatuses = new Set(['migrated']);

  const frameworkNames = ['NIST PQC', 'US Federal', 'CNSA 2.0', 'PCI DSS 4.0', 'DORA', 'FFIEC'];
  const frameworks: FrameworkStatus[] = frameworkNames.map((name) => {
    const applicable = scan.findings.filter((f) => controlsFor(f).some((c) => c.framework === name));
    const migrated = applicable.filter((f) => migratedStatuses.has(f.status));
    return {
      name,
      applicableFindings: applicable.length,
      migratedFindings: migrated.length,
      ready: applicable.length > 0 && migrated.length === applicable.length,
    };
  }).filter((f) => f.applicableFindings > 0);

  const total = scan.findings.length;
  const migrated = scan.findings.filter((f) => migratedStatuses.has(f.status)).length;

  return {
    format: 'recrypt-compliance',
    version: 1,
    generatedAt: new Date().toISOString(),
    system: scan.source.type === 'repo' || scan.source.type === 'github' ? scan.source.repoName : scan.source.type === 'cbom' ? scan.source.label : 'pasted-snippet',
    scanId: scan.id,
    summary: `${total} quantum-vulnerable usage(s) mapped to ${frameworks.length} framework(s); ${migrated}/${total} migrated to NIST post-quantum algorithms with equivalence evidence.`,
    frameworks,
    findings: scan.findings.map((f) => ({
      file: f.file,
      lines: [f.lineStart, f.lineEnd],
      algorithm: f.algorithm,
      usageType: f.usageType,
      status: f.status,
      migratedTo: f.analysis?.newAlgorithm ?? null,
      equivalenceTests: f.analysis?.tests?.length
        ? `${f.analysis.tests.filter((t) => t.passed).length}/${f.analysis.tests.length} passed`
        : null,
      proofDigest: f.analysis?.digest ?? null,
      controls: controlsFor(f),
    })),
  };
}
