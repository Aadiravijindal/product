'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

interface Repo {
  id: string; name: string; team: string; language: string;
  critical: number; high: number; medium: number; migrated: number;
  lastScanDaysAgo: number; live?: boolean; scanId?: string;
}
interface RealRun {
  id: string; scanId: string; source: string; startedAt: string; finishedAt: string;
  requested: number; completed: number; engine: string; flawsCaught: number;
  roundsHistogram: { one: number; two: number }; testsPassed: number; testsRun: number;
}
interface SimRun {
  id: string; startedAt: string; finishedAt: string; requested: number; prsOpened: number;
  merged: number; roundsHistogram: { one: number; two: number }; flawsCaught: number; note: string;
}
interface AuditRow { at: string; actor: string; action: string; target: string }
interface Payload {
  owner: string;
  summary: {
    repos: number; open: number; migrated: number; critical: number;
    totalUsages: number; migratedPct: number; exposureScore: number;
    trend: number[]; deadlineYear: number; onTrack: boolean;
  };
  repos: Repo[];
  fixRuns: { real: RealRun[]; simulated: SimRun[] };
  policies: { id: string; rule: string; scope: string; status: string; blockedThisMonth: number }[];
  exceptions: { id: string; rule: string; repo: string; reason: string; approvedBy: string; expires: string }[];
  audit: { real: AuditRow[]; seed: AuditRow[] };
}

type Tab = 'overview' | 'repos' | 'runs' | 'policy' | 'counterparties' | 'audit';

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'repos', label: 'Repositories' },
  { id: 'runs', label: 'Fix runs' },
  { id: 'policy', label: 'Policy gate' },
  { id: 'counterparties', label: 'Counterparties' },
  { id: 'audit', label: 'Audit trail' },
];

const COUNTERPARTIES = [
  { name: 'First National Bank (settlement API)', artifact: 'RS256 request signatures', theirSide: 'Verifier upgrade scheduled Q4 2026', state: 'waiting', blocking: 'legacy-soap-bridge enforcement' },
  { name: 'CardNet (ISO 8583 bridge)', artifact: 'TLS 1.2 RSA session', theirSide: 'Hybrid X25519MLKEM768 pilot agreed', state: 'in-progress', blocking: '—' },
  { name: 'Mobile apps ≤ v4.2 (kiosk fleet)', artifact: 'JWT verification', theirSide: 'Forced upgrade window opens Sep 1', state: 'in-progress', blocking: 'pol-4 enforcement on api-gateway' },
  { name: 'AuditCo (evidence webhook)', artifact: 'ML-DSA-65 detached signatures', theirSide: 'Verifying hybrid since June', state: 'done', blocking: '—' },
];

export default function PlatformConsole() {
  const router = useRouter();
  const [data, setData] = useState<Payload | null>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [scanning, setScanning] = useState<string | null>(null);
  const [fixRunning, setFixRunning] = useState(false);
  const [fixRunMsg, setFixRunMsg] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/platform/fleet')
      .then((r) => {
        if (r.status === 401) { router.replace('/platform/login'); return null; }
        return r.json();
      })
      .then((d) => { if (d) setData(d); })
      .catch(() => router.replace('/platform/login'));
  }, [router]);

  const scanLive = async (repoId: string) => {
    setScanning(repoId);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ repoId }),
      });
      const d = await res.json();
      if (res.ok) router.push(`/scan/${d.scanId}`);
      else setScanning(null);
    } catch { setScanning(null); }
  };

  const startRealFixRun = async () => {
    setFixRunning(true);
    setFixRunMsg(null);
    try {
      const scanRes = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ repoId: 'infra-configs' }),
      });
      const scanD = await scanRes.json();
      if (!scanRes.ok) throw new Error(scanD.error || 'scan failed');
      const runRes = await fetch(`/api/scan/${scanD.scanId}/fixrun`, { method: 'POST' });
      const runD = await runRes.json();
      if (!runRes.ok) throw new Error(runD.error || 'fix run failed');
      setFixRunMsg(
        `Done: ${runD.run.completed}/${runD.run.requested} findings remediated, ${runD.run.testsPassed}/${runD.run.testsRun} proofs passed. Recorded below.`
      );
      const fresh = await fetch('/api/platform/fleet').then((r) => r.json());
      setData(fresh);
    } catch (e) {
      setFixRunMsg(e instanceof Error ? e.message : 'Fix run failed.');
    } finally {
      setFixRunning(false);
    }
  };

  const logout = async () => {
    await fetch('/api/platform/login', { method: 'DELETE' });
    router.push('/platform/login');
  };

  const teams = useMemo(() => {
    if (!data) return [];
    const m = new Map<string, { open: number; migrated: number }>();
    for (const r of data.repos) {
      const t = m.get(r.team) ?? { open: 0, migrated: 0 };
      t.open += r.critical + r.high + r.medium;
      t.migrated += r.migrated;
      m.set(r.team, t);
    }
    return [...m.entries()].sort((a, b) => b[1].open - a[1].open);
  }, [data]);

  if (!data) {
    return (
      <div className="shell">
        <div className="loading-panel"><div className="spinner" /><div>Loading console…</div></div>
      </div>
    );
  }

  const s = data.summary;

  return (
    <div className="shell platform-shell">
      <div className="topbar">
        <div className="brand">
          <Link href="/platform"><span className="logo-mark">⬡</span> Recrypt</Link>
          <span className="brand-sub">Enterprise Console</span>
        </div>
        <nav>
          <Link href="/">Scanner</Link>
          <a onClick={logout} style={{ cursor: 'pointer' }}>Sign out</a>
        </nav>
      </div>

      <div className="preview-banner">
        Product-preview build. The three <span className="live-dot" /> connected repos run the
        real scan → red-team loop → proof pipeline end-to-end; the rest of the fleet is a
        representative simulation of an org-wide deployment.
      </div>

      <div className="platform-tabs">
        {TABS.map((t) => (
          <button key={t.id} className={`platform-tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
        <span className="platform-owner">{data.owner}</span>
      </div>

      {tab === 'overview' && (
        <>
          <div className="stat-row">
            <div className="stat-card">
              <div className="stat-num">{s.exposureScore}<span className="stat-sub">/100</span></div>
              <div className="stat-label">Quantum exposure score</div>
              <div className="stat-note ok">▲ {s.exposureScore - s.trend[s.trend.length - 2]} this quarter</div>
            </div>
            <div className="stat-card">
              <div className="stat-num">{s.migratedPct}%</div>
              <div className="stat-label">Migrated ({s.migrated} of {s.totalUsages} usages)</div>
              <div className="stat-note">{s.repos} repositories under continuous scan</div>
            </div>
            <div className="stat-card">
              <div className="stat-num warn">{s.critical}</div>
              <div className="stat-label">Open critical findings</div>
              <div className="stat-note">key exchange &amp; payment signing first</div>
            </div>
            <div className="stat-card">
              <div className="stat-num">{s.deadlineYear}</div>
              <div className="stat-label">Federal deadline</div>
              <div className={`stat-note ${s.onTrack ? 'ok' : 'warn'}`}>{s.onTrack ? 'On track at current pace' : 'Behind pace — accelerate'}</div>
            </div>
          </div>

          <div className="section">
            <h2>Exposure score — last 8 quarters</h2>
            <div className="trend-bars">
              {s.trend.map((v, i) => (
                <div className="trend-col" key={i}>
                  <div className="trend-bar" style={{ height: `${v}%` }} title={`${v}/100`} />
                  <div className="trend-cap">{v}</div>
                </div>
              ))}
            </div>
            <p className="explain" style={{ fontSize: 13.5 }}>
              Score = migration coverage weighted by open-critical pressure. The acceleration in
              recent quarters is the overnight fix runs landing.
            </p>
          </div>

          <div className="section">
            <h2>Risk by team</h2>
            <table className="findings">
              <thead><tr><th>Team</th><th>Open findings</th><th>Migrated</th><th>Progress</th></tr></thead>
              <tbody>
                {teams.map(([team, t]) => {
                  const pct = t.open + t.migrated === 0 ? 0 : Math.round((t.migrated / (t.open + t.migrated)) * 100);
                  return (
                    <tr key={team}>
                      <td>{team}</td>
                      <td>{t.open}</td>
                      <td>{t.migrated}</td>
                      <td>
                        <div className="mini-meter"><div className="mini-fill" style={{ width: `${pct}%` }} /></div>
                        <span className="mini-pct">{pct}%</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {tab === 'repos' && (
        <div className="section">
          <h2>Repositories under continuous scan</h2>
          <p className="explain" style={{ fontSize: 13.5 }}>
            Rows marked <span className="live-dot" /> live are wired to the real pipeline — scanning
            one runs actual detection, the two-agent hardening loop, and real ML-DSA/ML-KEM proofs.
          </p>
          <table className="findings">
            <thead><tr><th>Repository</th><th>Team</th><th>Lang</th><th>Critical</th><th>High</th><th>Medium</th><th>Migrated</th><th>Last scan</th><th></th></tr></thead>
            <tbody>
              {data.repos.map((r) => (
                <tr key={r.id} className={r.live ? 'live-row' : ''}>
                  <td className="mono">{r.live && <span className="live-dot" />}{r.name}</td>
                  <td>{r.team}</td>
                  <td>{r.language}</td>
                  <td className={r.critical > 0 ? 'sev-crit' : ''}>{r.critical}</td>
                  <td className={r.high > 0 ? 'sev-high' : ''}>{r.high}</td>
                  <td>{r.medium}</td>
                  <td>{r.migrated}</td>
                  <td>{r.lastScanDaysAgo === 0 ? 'today' : `${r.lastScanDaysAgo}d ago`}</td>
                  <td>
                    {r.live ? (
                      <span style={{ display: 'inline-flex', gap: 6 }}>
                        {r.scanId && (
                          <button className="btn btn-small" onClick={() => router.push(`/scan/${r.scanId}`)}>Open</button>
                        )}
                        <button className="btn btn-small btn-primary" disabled={scanning !== null || r.id.startsWith('real-')} onClick={() => scanLive(r.id)}>
                          {scanning === r.id ? 'Scanning…' : 'Scan now →'}
                        </button>
                      </span>
                    ) : (
                      <span className="sim-tag">simulated</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'runs' && (
        <div className="section">
          <h2>Fix runs</h2>
          <p className="explain" style={{ fontSize: 13.5 }}>
            A fix run executes the full pipeline — generate, red-team attack rounds, rewrite, real
            equivalence proofs — across a batch of findings with bounded parallelism, and records
            honest stats. Runs below marked <span className="live-dot" /> real executed on this deployment.
          </p>

          <div className="run-card run-live">
            <div className="run-head"><b>Start a real fix run now</b></div>
            <p className="explain" style={{ fontSize: 13.5 }}>
              Scans a connected repo and batch-runs the real pipeline across every finding —
              detection, hardening loop, ML-DSA/ML-KEM proofs — then records the run here.
            </p>
            <button className="btn btn-primary" disabled={fixRunning || scanning !== null} onClick={startRealFixRun}>
              {fixRunning ? 'Running the pipeline…' : 'Run on infra-configs →'}
            </button>
            {fixRunMsg && <p className="explain" style={{ fontSize: 13.5, marginTop: 10 }}>{fixRunMsg}</p>}
          </div>

          {data.fixRuns.real.map((run) => (
            <div className="run-card" key={run.id} style={{ borderColor: 'rgba(45,212,167,0.35)' }}>
              <div className="run-head">
                <b className="mono"><span className="live-dot" />{run.id} · {run.source}</b>
                <span>{new Date(run.startedAt).toLocaleString()} → {new Date(run.finishedAt).toLocaleTimeString()} · engine: {run.engine}</span>
              </div>
              <div className="run-stats">
                <span><b>{run.completed}</b>/{run.requested} findings remediated</span>
                <span><b>{run.flawsCaught}</b> flaws caught by the red team</span>
                <span><b>{run.roundsHistogram.one}</b> clean round 1 · <b>{run.roundsHistogram.two}</b> needed round 2</span>
                <span><b>{run.testsPassed}</b>/{run.testsRun} equivalence proofs passed</span>
              </div>
              <button className="btn btn-small" onClick={() => router.push(`/scan/${run.scanId}/dashboard`)}>Open run dashboard →</button>
            </div>
          ))}

          <h2 style={{ marginTop: 26 }}>Representative overnight runs <span className="sim-tag">simulated</span></h2>
          {data.fixRuns.simulated.map((run) => (
            <div className="run-card" key={run.id}>
              <div className="run-head">
                <b className="mono">{run.id}</b>
                <span>{new Date(run.startedAt).toLocaleString()} → {new Date(run.finishedAt).toLocaleTimeString()}</span>
              </div>
              <div className="run-stats">
                <span><b>{run.requested}</b> findings</span>
                <span><b>{run.prsOpened}</b> PRs opened</span>
                <span><b>{run.merged}</b> merged</span>
                <span><b>{run.flawsCaught}</b> flaws caught by the red team</span>
                <span><b>{run.roundsHistogram.one}</b> clean on round 1 · <b>{run.roundsHistogram.two}</b> needed round 2</span>
              </div>
              <p className="explain" style={{ fontSize: 13.5, marginBottom: 0 }}>{run.note}</p>
            </div>
          ))}
        </div>
      )}

      {tab === 'counterparties' && (
        <div className="section">
          <h2>Counterparty rollout tracker <span className="sim-tag">representative</span></h2>
          <p className="explain" style={{ fontSize: 13.5 }}>
            Hybrid crypto only fully protects you when both sides upgrade. This tracks every external
            party that verifies your signatures or terminates your TLS, what they still need to do,
            and which enforcement steps are blocked on them — the sequencing nobody automates today.
          </p>
          <table className="findings">
            <thead><tr><th>Counterparty</th><th>Shared crypto artifact</th><th>Their side</th><th>State</th><th>Blocking</th></tr></thead>
            <tbody>
              {COUNTERPARTIES.map((c) => (
                <tr key={c.name}>
                  <td>{c.name}</td>
                  <td className="mono">{c.artifact}</td>
                  <td>{c.theirSide}</td>
                  <td><span className={`badge ${c.state === 'done' ? 'verdict-approved' : c.state === 'in-progress' ? 'verdict-approved_with_notes' : 'verdict-revised'}`}>{c.state}</span></td>
                  <td>{c.blocking}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="explain" style={{ fontSize: 13.5 }}>
            Enforcement ordering is derived from the migration plan: verifiers upgrade before signers
            enforce, key exchange migrates before deadlines, and no policy flips to
            &ldquo;enforcing&rdquo; while a counterparty above is still in &ldquo;waiting.&rdquo;
          </p>
        </div>
      )}

      {tab === 'policy' && (
        <>
          <div className="section">
            <h2>Crypto policy gate</h2>
            <p className="explain" style={{ fontSize: 13.5 }}>
              Enforced on every pull request across the org. New quantum-vulnerable crypto cannot merge;
              exceptions require CISO sign-off and expire automatically.
            </p>
            <table className="findings">
              <thead><tr><th>Rule</th><th>Scope</th><th>Status</th><th>Blocked this month</th></tr></thead>
              <tbody>
                {data.policies.map((p) => (
                  <tr key={p.id}>
                    <td>{p.rule}</td>
                    <td>{p.scope}</td>
                    <td><span className={`badge ${p.status === 'enforcing' ? 'verdict-approved' : 'verdict-approved_with_notes'}`}>{p.status}</span></td>
                    <td>{p.blockedThisMonth}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="section">
            <h2>Active exceptions</h2>
            <table className="findings">
              <thead><tr><th>Repository</th><th>Rule</th><th>Reason</th><th>Approved by</th><th>Expires</th></tr></thead>
              <tbody>
                {data.exceptions.map((e) => (
                  <tr key={e.id}>
                    <td className="mono">{e.repo}</td>
                    <td className="mono">{e.rule}</td>
                    <td>{e.reason}</td>
                    <td>{e.approvedBy}</td>
                    <td>{e.expires}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="explain" style={{ fontSize: 13.5 }}>
              The same gate ships today as a CI script — <code>npm run gate</code> — and a GitHub
              Actions workflow in this repo.
            </p>
          </div>
        </>
      )}

      {tab === 'audit' && (
        <div className="section">
          <h2>Audit trail</h2>
          <p className="explain" style={{ fontSize: 13.5 }}>
            Every agent action, human decision, policy block, and proof bundle — timestamped and
            attributable. Rows marked <span className="live-dot" /> happened for real on this
            deployment; the rest are representative.
          </p>
          <table className="findings">
            <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th></tr></thead>
            <tbody>
              {data.audit.real.map((a, i) => (
                <tr key={`r${i}`}>
                  <td><span className="live-dot" />{new Date(a.at).toLocaleString()}</td>
                  <td className="mono">{a.actor}</td>
                  <td>{a.action}</td>
                  <td className="mono">{a.target}</td>
                </tr>
              ))}
              {data.audit.seed.map((a, i) => (
                <tr key={`s${i}`} style={{ opacity: 0.65 }}>
                  <td>{new Date(a.at).toLocaleString()}</td>
                  <td className="mono">{a.actor}</td>
                  <td>{a.action}</td>
                  <td className="mono">{a.target}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="footnote">
        Enterprise Console preview · continuous org scanning, SSO/roles, and customer-repo PR
        automation are the funded roadmap — the pipeline underneath (detection, two-agent hardening,
        real FIPS 203/204 proofs, policy gate, compliance packs) runs for real in this build.
      </p>
    </div>
  );
}
