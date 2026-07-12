'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { StatusBadge, TopBar } from '@/components/ui';
import type { Scan } from '@/lib/types';

/**
 * Quantum exposure score: 100 = fully migrated. Unmigrated findings deduct by
 * severity (Critical 30, High 18, Medium 8), floored at 4. Deterministic and
 * explainable — the kind of number a CISO can put in a board slide.
 */
function exposureScore(scan: Scan): { score: number; grade: string; cls: string } {
  const penalty: Record<string, number> = { Critical: 30, High: 18, Medium: 8 };
  let score = 100;
  for (const f of scan.findings) {
    if (f.status !== 'migrated') score -= penalty[f.risk] ?? 8;
  }
  score = Math.max(4, score);
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';
  const cls = score >= 90 ? 'score-good' : score >= 55 ? 'score-mid' : 'score-bad';
  return { score, grade, cls };
}

function ProgressRing({ done, total }: { done: number; total: number }) {
  const r = 52;
  const c = 2 * Math.PI * r;
  const frac = total === 0 ? 0 : done / total;
  return (
    <svg className="ring" width="130" height="130" viewBox="0 0 130 130">
      <circle cx="65" cy="65" r={r} fill="none" stroke="var(--border)" strokeWidth="10" />
      <circle
        cx="65" cy="65" r={r} fill="none"
        stroke="var(--accent)" strokeWidth="10" strokeLinecap="round"
        strokeDasharray={`${c * frac} ${c}`}
        transform="rotate(-90 65 65)"
      />
      <text x="65" y="72" textAnchor="middle" fill="var(--text)" fontSize="24" fontWeight="800">
        {Math.round(frac * 100)}%
      </text>
    </svg>
  );
}

export default function Dashboard() {
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
        <div className="loading-panel"><div className="spinner" />Loading…</div>
      </div>
    );
  }

  const total = scan.findings.length;
  const migrated = scan.findings.filter((f) => f.status === 'migrated');
  const escalated = scan.findings.filter((f) => f.status === 'escalated').length;
  const reviewed = scan.findings.filter((f) => f.status !== 'not_reviewed');
  const approvedWithTests = migrated.filter((f) => f.analysis?.tests?.length);
  const approvedAllPassed = approvedWithTests.filter((f) => f.analysis!.tests.every((t) => t.passed));
  const passRate =
    approvedWithTests.length === 0 ? null : Math.round((approvedAllPassed.length / approvedWithTests.length) * 100);
  const sourceName = scan.source.type === 'repo' ? scan.source.repoName : scan.source.label;

  return (
    <div className="shell">
      <TopBar scanId={scan.id} active="dashboard" />
      <h1>Migration dashboard — {sourceName}</h1>
      <p className="sub">The number your board actually wants to see.</p>

      <div className="dash-grid">
        <div className="section big-stat">
          <ProgressRing done={migrated.length} total={total} />
          <div className="num">
            {migrated.length} of {total}
          </div>
          <div className="cap">crypto usages migrated to NIST post-quantum (hybrid)</div>
        </div>
        <div className="section">
          {(() => {
            const { score, grade, cls } = exposureScore(scan);
            return (
              <div className="stat-row score-row">
                <span>Quantum exposure score</span>
                <b className={cls}>
                  {score}/100 <span className="score-grade">{grade}</span>
                </b>
              </div>
            );
          })()}
          <div className="stat-row"><span>Findings identified</span><b>{total}</b></div>
          <div className="stat-row"><span>Migrated (hybrid ML-DSA / ML-KEM)</span><b>{migrated.length}</b></div>
          <div className="stat-row"><span>Flagged for manual review / escalated</span><b>{escalated}</b></div>
          <div className="stat-row">
            <span>Approved migrations passing equivalence tests</span>
            <b>{passRate === null ? '—' : `${passRate}%`}</b>
          </div>
          <div className="stat-row"><span>Awaiting review</span><b>{total - reviewed.length}</b></div>
          <div style={{ marginTop: 18, display: 'flex', gap: 12 }}>
            <Link className="btn btn-primary" href={`/scan/${scan.id}/certificate`}>
              Generate Compliance Certificate
            </Link>
            <Link className="btn" href={`/scan/${scan.id}`}>Back to findings</Link>
          </div>
        </div>
      </div>

      <div className="section">
        <h2>Migration history</h2>
        {reviewed.length === 0 ? (
          <p className="sub" style={{ margin: 0 }}>No review decisions yet — open a finding and approve, escalate, or reject it.</p>
        ) : (
          <table className="findings">
            <thead>
              <tr>
                <th>Date</th>
                <th>File</th>
                <th>Algorithm before → after</th>
                <th>Decision</th>
                <th>Reviewer</th>
              </tr>
            </thead>
            <tbody>
              {reviewed.map((f) => (
                <tr key={f.id} style={{ cursor: 'default' }}>
                  <td>{f.reviewedAt ? new Date(f.reviewedAt).toLocaleString() : '—'}</td>
                  <td className="mono">{f.file}</td>
                  <td className="mono" style={{ fontSize: 12.5 }}>
                    {f.algorithm} → {f.analysis?.newAlgorithm ?? '—'}
                  </td>
                  <td><StatusBadge status={f.status} /></td>
                  <td>{f.reviewer ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
