'use client';

import { useCallback, useEffect, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { RiskBadge, StatusBadge, TopBar, usageLabel } from '@/components/ui';
import type { Scan } from '@/lib/types';

export default function ScanResults() {
  const { scanId } = useParams<{ scanId: string }>();
  const router = useRouter();
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);

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
      <p className="sub">This is the CBOM view your discovery tool already gives you. Click a finding to open the remediation agent.</p>

      <div className="summary-strip">
        <span><b>{scan.findings.length}</b> finding{scan.findings.length === 1 ? '' : 's'}</span>
        <span><span className="dot dot-critical" /><b>{counts.Critical}</b> Critical</span>
        <span><span className="dot dot-high" /><b>{counts.High}</b> High</span>
        <span><span className="dot dot-medium" /><b>{counts.Medium}</b> Medium</span>
        <span style={{ marginLeft: 'auto' }}>
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
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {scan.findings.map((f) => (
            <tr key={f.id} onClick={() => router.push(`/scan/${scan.id}/finding/${f.id}`)}>
              <td className="mono">{f.file}</td>
              <td className="mono">{f.lineStart === f.lineEnd ? f.lineStart : `${f.lineStart}–${f.lineEnd}`}</td>
              <td><span className="badge badge-algo">{f.algorithm}</span></td>
              <td>{usageLabel(f.usageType)}</td>
              <td><RiskBadge risk={f.risk} /></td>
              <td><StatusBadge status={f.status} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
