'use client';

import { useCallback, useEffect, useState } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { RiskBadge, StatusBadge, TopBar, usageLabel } from '@/components/ui';
import type { Finding, Scan } from '@/lib/types';

function rowStatus(f: Finding, analyzing: boolean) {
  if (analyzing) return <span className="badge badge-status-analyzing">Agent running…</span>;
  if (f.status === 'not_reviewed' && f.analysis) return <span className="badge badge-status-ready">Ready for review</span>;
  return <StatusBadge status={f.status} />;
}

export default function ScanResults() {
  const { scanId } = useParams<{ scanId: string }>();
  const router = useRouter();
  const searchParams = useSearchParams();
  const justReviewed = searchParams.get('just');
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState<Set<string>>(new Set());
  const [batchRunning, setBatchRunning] = useState(false);

  const load = useCallback(() => {
    fetch(`/api/scan/${scanId}`)
      .then(async (r) => {
        const d = await r.json();
        if (!r.ok) throw new Error(d.error || 'not found');
        setScan(d.scan);
      })
      .catch((e) => setError(e.message));
  }, [scanId]);

  useEffect(load, [load]);
  useEffect(() => {
    if (scan) window.localStorage.setItem('recrypt.lastScan', JSON.stringify({ id: scan.id, name: scan.source.type === 'repo' ? scan.source.repoName : 'pasted snippet' }));
  }, [scan]);

  const analyzeAll = async () => {
    if (!scan) return;
    const pending = scan.findings.filter((f) => !f.analysis);
    if (pending.length === 0) return;
    setBatchRunning(true);
    setAnalyzing(new Set(pending.map((f) => f.id)));
    await Promise.allSettled(
      pending.map(async (f) => {
        await fetch(`/api/scan/${scan.id}/findings/${f.id}/analyze`, { method: 'POST' });
        setAnalyzing((prev) => {
          const next = new Set(prev);
          next.delete(f.id);
          return next;
        });
      })
    );
    setBatchRunning(false);
    load();
  };

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
        <div className="loading-panel"><div className="spinner" />Loading scan…</div>
      </div>
    );
  }

  const counts = { Critical: 0, High: 0, Medium: 0 };
  for (const f of scan.findings) counts[f.risk]++;
  const sourceName = scan.source.type === 'repo' ? scan.source.repoName : scan.source.label;
  const pendingAnalysis = scan.findings.filter((f) => !f.analysis).length;

  if (scan.findings.length === 0) {
    return (
      <div className="shell">
        <TopBar scanId={scan.id} active="results" />
        <h1>Scan results — {sourceName}</h1>
        <div className="empty-state section">
          <div className="big">No quantum-vulnerable cryptography detected in this snippet</div>
          <p>
            We looked for RSA, ECDSA/ECDH, and quantum-vulnerable JWT and TLS configurations across Python, Java,
            JavaScript, and Go. If you expected a hit, try including the imports or key-generation calls — or use one
            of the sample repos.
          </p>
          <Link className="btn" href="/">← Back</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="shell">
      <TopBar scanId={scan.id} active="results" />
      <h1>Scan results — {sourceName}</h1>
      <p className="sub">
        This is the CBOM view your discovery tool already gives you. Click a finding to open the remediation agent
        {pendingAnalysis > 1 ? ', or run the agent across everything at once.' : '.'}
      </p>

      <div className="summary-strip">
        <span><b>{scan.findings.length}</b> finding{scan.findings.length === 1 ? '' : 's'}</span>
        <span><span className="dot dot-critical" /><b>{counts.Critical}</b> Critical</span>
        <span><span className="dot dot-high" /><b>{counts.High}</b> High</span>
        <span><span className="dot dot-medium" /><b>{counts.Medium}</b> Medium</span>
        {scan.stats && (
          <span className="scan-stats">
            {scan.stats.files} file{scan.stats.files === 1 ? '' : 's'} · {scan.stats.patterns} detection patterns ·{' '}
            {scan.stats.durationMs < 1 ? '<1' : Math.round(scan.stats.durationMs)} ms
          </span>
        )}
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 10 }}>
          {pendingAnalysis > 0 && (
            <button className="btn btn-primary" disabled={batchRunning} onClick={() => void analyzeAll()}>
              {batchRunning ? `Agent running (${analyzing.size} left)…` : `Analyze all (${pendingAnalysis})`}
            </button>
          )}
          <a className="btn" href={`/api/scan/${scan.id}/export`} download>Export CBOM</a>
          <Link className="btn" href={`/scan/${scan.id}/dashboard`}>Dashboard →</Link>
        </span>
      </div>

      <table className="findings">
        <thead>
          <tr>
            <th>File</th>
            <th>Line(s)</th>
            <th>Algorithm detected</th>
            <th>Usage type</th>
            <th>Risk</th>
            <th>Confidence</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {scan.findings.map((f) => (
            <tr
              key={f.id}
              className={f.id === justReviewed ? 'row-pulse' : ''}
              onClick={() => router.push(`/scan/${scan.id}/finding/${f.id}`)}
            >
              <td className="mono">{f.file}</td>
              <td className="mono">{f.lineStart === f.lineEnd ? f.lineStart : `${f.lineStart}–${f.lineEnd}`}</td>
              <td><span className="badge badge-algo">{f.algorithm}</span></td>
              <td>{usageLabel(f.usageType)}</td>
              <td><RiskBadge risk={f.risk} /></td>
              <td className={f.confidence < 85 ? 'conf-low' : 'conf-ok'}>{f.confidence}%</td>
              <td>{rowStatus(f, analyzing.has(f.id))}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
