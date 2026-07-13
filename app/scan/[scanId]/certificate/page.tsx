'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { TopBar } from '@/components/ui';
import type { Scan } from '@/lib/types';

export default function Certificate() {
  const { scanId } = useParams<{ scanId: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`/api/scan/${scanId}`)
      .then(async (r) => {
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || 'not found');
        setScan(d.scan);
      })
      .catch((e) => setError(e.message));
  }, [scanId]);

  if (error) {
    return (
      <div className="shell">
        <TopBar />
        <div className="empty-state section">
          <div className="big">Scan not found</div>
          <p>{error}</p>
          <Link className="btn" href="/">← Start a new scan</Link>
        </div>
      </div>
    );
  }
  if (!scan) {
    return (
      <div className="shell">
        <TopBar />
        <div className="loading-panel"><div className="spinner" />Generating certificate…</div>
      </div>
    );
  }

  const total = scan.findings.length;
  const migrated = scan.findings.filter((f) => f.status === 'migrated');
  const flagged = scan.findings.filter((f) => f.status === 'escalated' || (f.status === 'not_reviewed' && f.confidence < 85)).length;
  const testsPassed = migrated.reduce((n, f) => n + (f.analysis?.tests.filter((t) => t.passed).length ?? 0), 0);
  const sourceName = scan.source.type === 'repo' ? scan.source.repoName : scan.source.label;
  const reviewers = [...new Set(migrated.map((f) => f.reviewer).filter(Boolean))];

  return (
    <div className="shell">
      <TopBar scanId={scan.id} active="dashboard" />
      <div className="cert-actions">
        <Link className="btn" href={`/scan/${scan.id}/dashboard`}>← Dashboard</Link>
        <button className="btn btn-primary" onClick={() => window.print()}>Print / Save as PDF</button>
      </div>

      <div className="cert-page">
        <div className="cert-brand">⬡ Recrypt</div>
        <h1>Post-Quantum Migration Certificate</h1>
        <p className="cert-line"><b>Certificate ID:</b> RC-{scan.id.toUpperCase()}</p>
        <p className="cert-line"><b>System assessed:</b> {sourceName}</p>
        <p className="cert-line"><b>Date generated:</b> {new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })}</p>

        <div className="cert-summary">
          {total} cryptographic usage{total === 1 ? '' : 's'} identified · {migrated.length} migrated to NIST-standard
          post-quantum algorithms (ML-DSA / ML-KEM, hybrid) · {flagged} flagged for manual review ·{' '}
          {testsPassed} equivalence tests passed on approved migrations.
        </div>

        <table>
          <thead>
            <tr>
              <th>Finding</th>
              <th>Algorithm before</th>
              <th>Algorithm after</th>
              <th>Equivalence tests</th>
              <th>Proof digest</th>
              <th>Decision</th>
              <th>Reviewer</th>
            </tr>
          </thead>
          <tbody>
            {scan.findings.map((f) => {
              const t = f.analysis?.tests ?? [];
              const passed = t.filter((x) => x.passed).length;
              return (
                <tr key={f.id}>
                  <td>{f.file}:{f.lineStart}</td>
                  <td>{f.algorithm}</td>
                  <td>{f.status === 'migrated' ? f.analysis?.newAlgorithm ?? '—' : '— (not migrated)'}</td>
                  <td>{t.length === 0 ? 'not run' : `${passed}/${t.length} passed`}</td>
                  <td style={{ fontFamily: 'var(--mono)', fontSize: 10.5 }}>{f.analysis?.digest ? f.analysis.digest.slice(0, 16) + '…' : '—'}</td>
                  <td>
                    {f.status === 'migrated' ? 'Approved & migrated'
                      : f.status === 'escalated' ? 'Escalated for engineering review'
                      : f.status === 'rejected' ? 'Rejected'
                      : 'Pending review'}
                  </td>
                  <td>{f.reviewer ?? '—'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>

        <p className="cert-line">
          Reviewed and approved by: <b>{reviewers.length ? reviewers.join(', ') : '—'}</b>
        </p>
        <p className="cert-line">
          Each migrated finding carries a SHA-256 proof digest over the original code, the applied patch, and the
          executed test evidence. In the production version these digests are HSM-signed for third-party audit submission.
        </p>
        <p className="cert-line">
          Equivalence testing executed real cryptographic operations: classical RSA-PSS / ECDH via the platform crypto
          library, and ML-DSA-65 (FIPS 204) / ML-KEM-768 (FIPS 203) via audited post-quantum implementations.
        </p>

        <div className="cert-footer">
          This certificate reflects migration activity performed in Recrypt. Cryptographic signing of this document for
          third-party audit submission is available in the full production version.
        </div>
      </div>
    </div>
  );
}
