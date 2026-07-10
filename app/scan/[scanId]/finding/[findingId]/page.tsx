'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { RiskBadge, TopBar, getReviewer, usageLabel } from '@/components/ui';
import { sideBySideDiff } from '@/lib/diff';
import type { Finding } from '@/lib/types';

const THRESHOLD = 85;

export default function FindingDetail() {
  const { scanId, findingId } = useParams<{ scanId: string; findingId: string }>();
  const router = useRouter();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [phase, setPhase] = useState<'loading' | 'analyzing' | 'ready' | 'error'>('loading');
  const [error, setError] = useState<string | null>(null);
  const [acting, setActing] = useState(false);

  const analyze = useCallback(async () => {
    setPhase('analyzing');
    setError(null);
    try {
      const res = await fetch(`/api/scan/${scanId}/findings/${findingId}/analyze`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'analysis failed');
      setFinding(data.finding);
      setPhase('ready');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Analysis failed');
      setPhase('error');
    }
  }, [scanId, findingId]);

  useEffect(() => {
    fetch(`/api/scan/${scanId}`)
      .then(async (r) => {
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || 'not found');
        const f: Finding | undefined = d.scan.findings.find((x: Finding) => x.id === findingId);
        if (!f) throw new Error('finding not found');
        setFinding(f);
        if (f.analysis) setPhase('ready');
        else void analyze();
      })
      .catch((e) => {
        setError(e.message);
        setPhase('error');
      });
  }, [scanId, findingId, analyze]);

  const diffRows = useMemo(() => {
    if (!finding?.analysis) return [];
    return sideBySideDiff(finding.fullCode, finding.analysis.patchedCode);
  }, [finding]);

  const act = async (action: 'approve' | 'reject' | 'escalate') => {
    setActing(true);
    try {
      const res = await fetch(`/api/scan/${scanId}/findings/${findingId}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, reviewer: getReviewer() }),
      });
      if (!res.ok) throw new Error('action failed');
      router.push(`/scan/${scanId}`);
    } catch {
      setError('Could not record the decision — please retry.');
      setActing(false);
    }
  };

  if (phase === 'error') {
    return (
      <div className="shell">
        <TopBar scanId={scanId} />
        <div className="empty-state section">
          <div className="big">The remediation agent hit a snag</div>
          <p>{error}</p>
          <button className="btn btn-primary" onClick={() => void analyze()}>Retry analysis</button>{' '}
          <Link className="btn" href={`/scan/${scanId}`}>← Back to results</Link>
        </div>
      </div>
    );
  }

  if (!finding || phase === 'loading' || phase === 'analyzing' || !finding.analysis) {
    return (
      <div className="shell">
        <TopBar scanId={scanId} />
        <div className="loading-panel">
          <div className="spinner" />
          <div style={{ fontSize: 16, marginBottom: 10 }}>Remediation agent working…</div>
          <div className="loading-steps">
            classify finding → generate hybrid patch → run equivalence tests
          </div>
        </div>
      </div>
    );
  }

  const a = finding.analysis;
  const conf = finding.confidence;
  const aboveThreshold = conf >= THRESHOLD;
  const allTestsPassed = a.tests.every((t) => t.passed);

  return (
    <div className="shell">
      <TopBar scanId={scanId} active="results" />
      <h1 style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <span style={{ fontFamily: 'var(--mono)', fontSize: 21 }}>{finding.file}:{finding.lineStart}</span>
        <span className="badge badge-algo">{finding.algorithm} · {usageLabel(finding.usageType)}</span>
        <RiskBadge risk={finding.risk} />
      </h1>
      <p className="sub">
        <Link href={`/scan/${scanId}`}>← Back to scan results</Link>
      </p>

      {a.engineNote && <div className="notice">{a.engineNote}</div>}

      <div className="section">
        <h2>
          What we found
          <span className="engine-tag">
            {a.engine === 'claude' ? 'analysis: Claude API (live)' : 'analysis: built-in remediation library'}
          </span>
        </h2>
        <p className="explain">{a.classification.explanation}</p>
        <div className="kv">
          <div>Algorithm<b>{a.classification.algorithm}</b></div>
          <div>Key size<b>{a.classification.key_size}</b></div>
          <div>Usage<b>{usageLabel(a.classification.usage_type)}</b></div>
          <div>Proposed replacement<b>{a.newAlgorithm}</b></div>
        </div>
      </div>

      <div className="section">
        <h2>Proposed fix</h2>
        <div className="diff-wrap">
          <div className="diff-titles">
            <div className="t-old">Current (vulnerable)</div>
            <div className="t-new">Proposed (hybrid quantum-safe)</div>
          </div>
          <table className="diff">
            <tbody>
              {diffRows.map((row, i) => (
                <tr key={i}>
                  <td className={`no l ${row.type === 'del' || row.type === 'change' ? 'cell-del' : ''}`}>{row.leftNo ?? ''}</td>
                  <td className={`l ${row.type === 'del' || row.type === 'change' ? 'cell-del' : ''}`}>{row.left ?? ''}</td>
                  <td className={`no ${row.type === 'add' || row.type === 'change' ? 'cell-add' : ''}`}>{row.rightNo ?? ''}</td>
                  <td className={row.type === 'add' || row.type === 'change' ? 'cell-add' : ''}>{row.right ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <ul className="changes">
          {a.changes.map((c, i) => (
            <li key={i}>{c}</li>
          ))}
        </ul>
      </div>

      <div className="section">
        <h2>Confidence</h2>
        <div className="meter-outer">
          <div className={`meter-fill ${aboveThreshold ? '' : 'low'}`} style={{ width: `${conf}%` }} />
          <div className="meter-threshold" style={{ left: `${THRESHOLD}%` }} />
        </div>
        <div className={`meter-label ${aboveThreshold ? 'ok' : 'warn'}`}>
          {aboveThreshold
            ? `${conf}% confident — high confidence, eligible for auto-review`
            : `${conf}% confident — below the ${THRESHOLD}% threshold, requires manual review before approval`}
        </div>
      </div>

      <div className="section">
        <h2>
          Equivalence tests
          <span className="engine-tag">executed live on this host — real RSA/ECDH + real FIPS 203/204</span>
        </h2>
        {a.tests.map((t, i) => (
          <div className="test-line" key={i}>
            <span className={`test-ico ${t.passed ? 'pass' : 'fail'}`}>{t.passed ? '✓' : '✗'}</span>
            <span>
              {t.name}
              <span className="test-detail">{t.detail}</span>
            </span>
          </div>
        ))}
      </div>

      <div className="action-bar">
        <button
          className="btn btn-primary"
          disabled={acting || finding.status === 'migrated'}
          title={!aboveThreshold ? 'Below the confidence threshold — approving records a manual review decision' : undefined}
          onClick={() => void act('approve')}
        >
          {finding.status === 'migrated' ? 'Migrated ✓' : allTestsPassed ? 'Approve & Migrate' : 'Approve anyway'}
        </button>
        <button className="btn" disabled={acting} onClick={() => void act('escalate')}>
          Escalate to Engineer
        </button>
        <button className="btn-link" disabled={acting} onClick={() => void act('reject')}>
          Reject
        </button>
        {!aboveThreshold && (
          <span style={{ color: 'var(--high)', fontSize: 13 }}>
            ⚠ Under threshold — not eligible for auto-approval; a human decision is recorded.
          </span>
        )}
      </div>
    </div>
  );
}
