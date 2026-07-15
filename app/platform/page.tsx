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
interface WatchRow {
  key: string; label: string; kind: string; addedAt: string; lastScanAt: string;
  lastScanId: string; lastFindingCount: number; newSinceLast: string[];
}
interface PolicyRow { id: string; rule: string; scope: string; status: string; blockedThisMonth: number }
interface GateResult {
  verdict: string; wouldMerge: boolean;
  violations: { line: number; algorithm: string; usageType: string; ruleId: string; rule: string; action: string }[];
}
const UNPATCHABLE = [
  { asset: 'HSM cluster (payments signing)', why: 'Firmware only supports old crypto', plan: 'Vendor quantum-safe firmware — mid 2027', due: '2027-06-30' },
  { asset: '40 branch VPN appliances', why: 'Crypto is baked into the hardware', plan: 'Replace 10 per quarter', due: '2027-12-31' },
  { asset: 'Legacy mainframe link', why: "Can't be rebuilt; crypto lives in a vendor module", plan: 'Wrap it in a quantum-safe tunnel', due: '2026-12-15' },
];
interface Payload {
  owner: string;
  session: { email: string; role: string };
  team: { email: string; role: string }[];
  integrations: { github: boolean; slack: boolean; liveAI: boolean; redis: boolean };
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

type Tab = 'overview' | 'code' | 'fix' | 'rules' | 'activity' | 'settings';

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'code', label: 'Your code' },
  { id: 'fix', label: 'Auto-fix' },
  { id: 'rules', label: 'Rules' },
  { id: 'activity', label: 'Activity' },
  { id: 'settings', label: 'Settings' },
];

const COUNTERPARTIES = [
  { name: 'First National Bank', artifact: 'Signed API requests', theirSide: 'Upgrading late 2026', state: 'waiting' },
  { name: 'CardNet payment bridge', artifact: 'TLS connection', theirSide: 'Quantum-safe pilot agreed', state: 'in-progress' },
  { name: 'Mobile apps (older versions)', artifact: 'Login tokens', theirSide: 'Forced update opens Sep 1', state: 'in-progress' },
  { name: 'AuditCo webhook', artifact: 'Signatures', theirSide: 'Already upgraded', state: 'done' },
];

export default function PlatformConsole() {
  const router = useRouter();
  const [data, setData] = useState<Payload | null>(null);
  const [tab, setTab] = useState<Tab>('overview');
  const [scanning, setScanning] = useState<string | null>(null);
  const [fixRunning, setFixRunning] = useState(false);
  const [fixRunMsg, setFixRunMsg] = useState<string | null>(null);
  const [watchlist, setWatchlist] = useState<WatchRow[]>([]);
  const [watchBusy, setWatchBusy] = useState(false);
  const [policyRules, setPolicyRules] = useState<PolicyRow[]>([]);
  const [gateCode, setGateCode] = useState('');
  const [gateResult, setGateResult] = useState<GateResult | null>(null);
  const [gateBusy, setGateBusy] = useState(false);
  const [drill, setDrill] = useState<{ analyses: number; testsRun: number; testsPassed: number; regressions: number } | null>(null);
  const [drillBusy, setDrillBusy] = useState(false);
  const [targets, setTargets] = useState<{ id: string; label: string; kind: string; note: string }[]>([]);
  const [target, setTarget] = useState('ml-dsa-87');
  const [remig, setRemig] = useState<{ label: string; applicable: number; proven: number; failed: number; sampleEvidence: string } | null>(null);
  const [remigBusy, setRemigBusy] = useState(false);

  const refreshWatch = () => fetch('/api/watch').then((r) => r.json()).then((d) => setWatchlist(d.watchlist ?? [])).catch(() => {});
  const refreshPolicy = () => fetch('/api/policy').then((r) => r.json()).then((d) => setPolicyRules(d.rules ?? [])).catch(() => {});

  useEffect(() => {
    refreshWatch();
    refreshPolicy();
    fetch('/api/remigrate').then((r) => r.json()).then((d) => setTargets(d.targets ?? [])).catch(() => {});
  }, []);

  const runRemigration = async () => {
    setRemigBusy(true);
    setRemig(null);
    try {
      const r = await fetch('/api/remigrate', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target }) });
      if (r.ok) setRemig(await r.json());
    } catch { /* noop */ }
    setRemigBusy(false);
  };

  const watchRepo = async (repoId: string) => {
    setWatchBusy(true);
    await fetch('/api/watch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ repoId }) }).catch(() => {});
    await refreshWatch();
    setWatchBusy(false);
  };
  const unwatch = async (key: string) => {
    await fetch(`/api/watch?key=${encodeURIComponent(key)}`, { method: 'DELETE' }).catch(() => {});
    refreshWatch();
  };
  const rescanAll = async () => {
    setWatchBusy(true);
    await fetch('/api/watch/tick').catch(() => {});
    await refreshWatch();
    setWatchBusy(false);
  };
  const togglePolicy = async (id: string, enforcing: boolean) => {
    await fetch('/api/policy', { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id, enforcing }) }).catch(() => {});
    refreshPolicy();
  };
  const checkGate = async () => {
    setGateBusy(true);
    setGateResult(null);
    try {
      const r = await fetch('/api/policy/check', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ code: gateCode }) });
      setGateResult(await r.json());
    } catch { /* noop */ }
    setGateBusy(false);
  };
  const runDrill = async () => {
    setDrillBusy(true);
    try {
      const r = await fetch('/api/reverify', { method: 'POST' });
      if (r.ok) setDrill(await r.json());
    } catch { /* noop */ }
    setDrillBusy(false);
  };

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
        `Done — fixed ${runD.run.completed} of ${runD.run.requested} spots, and all ${runD.run.testsPassed} safety checks passed. It's in the list below.`
      );
      const fresh = await fetch('/api/platform/fleet').then((r) => r.json());
      setData(fresh);
    } catch (e) {
      setFixRunMsg(e instanceof Error ? e.message : 'Something went wrong — try again.');
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
        <div className="loading-panel"><div className="spinner" /><div>Loading…</div></div>
      </div>
    );
  }

  const s = data.summary;
  const liveRepos = data.repos.filter((r) => r.live);
  const nextStep =
    s.critical > 0
      ? `Fix your ${s.critical} most urgent issue${s.critical === 1 ? '' : 's'} first — head to Auto-fix.`
      : s.migratedPct < 100
        ? 'Keep going — run Auto-fix on your remaining repositories.'
        : "You're fully migrated. Keep watching for anything new.";

  return (
    <div className="shell platform-shell">
      <div className="topbar">
        <div className="brand">
          <Link href="/platform"><span className="logo-mark">⬡</span> Recrypt</Link>
          <span className="brand-sub">Dashboard</span>
        </div>
        <nav>
          <Link href="/">Scan new code</Link>
          <span className="role-chip">{data.session.role}</span>
          <a onClick={logout} style={{ cursor: 'pointer' }}>Sign out</a>
        </nav>
      </div>

      <div className="platform-tabs">
        {TABS.map((t) => (
          <button key={t.id} className={`platform-tab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
        <span className="platform-owner">{data.owner}</span>
      </div>

      {/* ---------------- OVERVIEW ---------------- */}
      {tab === 'overview' && (
        <>
          <div className="tab-intro">
            <h1>Your quantum-safety, at a glance</h1>
            <p>Where your company stands on moving off crypto that quantum computers will break.</p>
          </div>

          <div className="headline-card">
            <div className="headline-big">You&rsquo;re <b>{s.migratedPct}%</b> quantum-safe</div>
            <div className={`headline-sub ${s.onTrack ? 'ok' : 'warn'}`}>
              {s.onTrack ? '✓ On track' : '⚠ Behind pace'} for the {s.deadlineYear} deadline
            </div>
            <div className="next-step">👉 {nextStep}</div>
          </div>

          <div className="stat-row">
            <div className="stat-card">
              <div className="stat-num">{s.exposureScore}<span className="stat-sub">/100</span></div>
              <div className="stat-label">Safety score</div>
              <div className="stat-note ok">▲ {s.exposureScore - s.trend[s.trend.length - 2]} this quarter (higher is safer)</div>
            </div>
            <div className="stat-card">
              <div className="stat-num">{s.migrated}<span className="stat-sub">/{s.totalUsages}</span></div>
              <div className="stat-label">Vulnerable spots fixed</div>
              <div className="stat-note">across {s.repos} repositories</div>
            </div>
            <div className="stat-card">
              <div className="stat-num warn">{s.critical}</div>
              <div className="stat-label">Urgent issues left</div>
              <div className="stat-note">payments &amp; logins — fix these first</div>
            </div>
            <div className="stat-card">
              <div className="stat-num">{s.deadlineYear}</div>
              <div className="stat-label">Deadline</div>
              <div className={`stat-note ${s.onTrack ? 'ok' : 'warn'}`}>{s.onTrack ? 'on track' : 'accelerate'}</div>
            </div>
          </div>

          <div className="section">
            <h2>Progress over time</h2>
            <p className="explain soft">Your safety score, quarter by quarter. It climbs as you fix more.</p>
            <div className="trend-bars">
              {s.trend.map((v, i) => (
                <div className="trend-col" key={i}>
                  <div className="trend-bar" style={{ height: `${v}%` }} title={`${v}/100`} />
                  <div className="trend-cap">{v}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="section">
            <h2>Which teams need attention</h2>
            <p className="explain soft">Teams with the most unfixed crypto are at the top.</p>
            <div className="tbl-wrap">
              <table className="findings">
                <thead><tr><th>Team</th><th>Still to fix</th><th>Fixed</th><th>Progress</th></tr></thead>
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
          </div>
        </>
      )}

      {/* ---------------- YOUR CODE ---------------- */}
      {tab === 'code' && (
        <>
          <div className="tab-intro">
            <h1>Your code</h1>
            <p>Every repository we check for vulnerable crypto. Hit <b>Watch</b> to keep one checked automatically, forever.</p>
          </div>

          <div className="section">
            <div className="section-head">
              <h2>Always watching</h2>
              <button className="btn btn-small" disabled={watchBusy} onClick={rescanAll}>
                {watchBusy ? 'Checking…' : 'Check them all now'}
              </button>
            </div>
            <p className="explain soft">
              These repos get re-checked automatically every day. If new vulnerable crypto shows up, it&rsquo;s flagged here the same day.
            </p>
            {watchlist.length === 0 ? (
              <div className="empty-inline">Nothing watched yet — click <b>Watch</b> on a repo below to start.</div>
            ) : (
              <div className="tbl-wrap">
                <table className="findings">
                  <thead><tr><th>Repository</th><th>Last checked</th><th>Issues found</th><th>Anything new?</th><th></th></tr></thead>
                  <tbody>
                    {watchlist.map((w) => (
                      <tr key={w.key}>
                        <td className="mono"><span className="live-dot" />{w.label}</td>
                        <td>{w.lastScanAt ? new Date(w.lastScanAt).toLocaleDateString() : '—'}</td>
                        <td>{w.lastFindingCount}</td>
                        <td>{w.newSinceLast.length > 0 ? <span className="sev-crit">⚠ {w.newSinceLast.length} new</span> : <span style={{ color: 'var(--accent)' }}>✓ nothing new</span>}</td>
                        <td style={{ display: 'flex', gap: 6 }}>
                          {w.lastScanId && <button className="btn btn-small" onClick={() => router.push(`/scan/${w.lastScanId}`)}>View</button>}
                          <button className="btn btn-small" onClick={() => unwatch(w.key)}>Stop</button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="section">
            <h2>All repositories</h2>
            <p className="explain soft">
              <b>Check now</b> runs a full scan and fix. <b>Watch</b> keeps it checked automatically. Green dot = a real repo you can run live.
            </p>
            <div className="tbl-wrap">
              <table className="findings">
                <thead><tr><th>Repository</th><th>Team</th><th>Urgent</th><th>High</th><th>Fixed</th><th></th></tr></thead>
                <tbody>
                  {data.repos.map((r) => (
                    <tr key={r.id} className={r.live ? 'live-row' : ''}>
                      <td className="mono">{r.live && <span className="live-dot" />}{r.name}</td>
                      <td>{r.team}</td>
                      <td className={r.critical > 0 ? 'sev-crit' : ''}>{r.critical}</td>
                      <td className={r.high > 0 ? 'sev-high' : ''}>{r.high}</td>
                      <td>{r.migrated}</td>
                      <td>
                        {r.live ? (
                          <span style={{ display: 'inline-flex', gap: 6 }}>
                            {r.scanId && <button className="btn btn-small" onClick={() => router.push(`/scan/${r.scanId}`)}>View</button>}
                            {!r.id.startsWith('real-') && (
                              <>
                                <button className="btn btn-small btn-primary" disabled={scanning !== null} onClick={() => scanLive(r.id)}>
                                  {scanning === r.id ? 'Checking…' : 'Check now'}
                                </button>
                                {!watchlist.some((w) => w.key === r.id) && (
                                  <button className="btn btn-small" disabled={watchBusy} onClick={() => watchRepo(r.id)}>Watch</button>
                                )}
                              </>
                            )}
                          </span>
                        ) : (
                          <span className="sim-tag">example</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* ---------------- AUTO-FIX ---------------- */}
      {tab === 'fix' && (
        <>
          <div className="tab-intro">
            <h1>Auto-fix</h1>
            <p>Let the AI fix a whole repo at once — it fixes every vulnerable spot, double-checks its own work, proves it, and gets it ready for your team to review.</p>
          </div>

          <div className="cta-card">
            <div>
              <div className="cta-title">Fix a repository now</div>
              <div className="cta-sub">Runs the full fix across every issue, then shows you the results.</div>
            </div>
            <button className="btn btn-primary" disabled={fixRunning || scanning !== null} onClick={startRealFixRun}>
              {fixRunning ? 'Fixing…' : 'Fix a repo →'}
            </button>
          </div>
          {fixRunMsg && <div className="callout" style={{ marginBottom: 18 }}>{fixRunMsg}</div>}

          {data.fixRuns.real.length > 0 && (
            <div className="section">
              <h2>Fixes you&rsquo;ve run</h2>
              {data.fixRuns.real.map((run) => (
                <div className="run-card" key={run.id} style={{ borderColor: 'var(--accent-line)' }}>
                  <div className="run-head">
                    <b><span className="live-dot" />{run.source}</b>
                    <span>{new Date(run.startedAt).toLocaleString()}</span>
                  </div>
                  <div className="run-stats">
                    <span><b>{run.completed}</b> spots fixed</span>
                    <span><b>{run.flawsCaught}</b> mistakes the AI caught in itself</span>
                    <span><b>{run.testsPassed}/{run.testsRun}</b> safety checks passed</span>
                  </div>
                  <button className="btn btn-small" onClick={() => router.push(`/scan/${run.scanId}/dashboard`)}>See details →</button>
                </div>
              ))}
            </div>
          )}

          <div className="section">
            <h2>Example: a typical overnight run <span className="sim-tag">example</span></h2>
            <p className="explain soft">This is what a big nightly fix looks like across many repos at once.</p>
            {data.fixRuns.simulated.map((run) => (
              <div className="run-card" key={run.id}>
                <div className="run-head">
                  <b>{new Date(run.startedAt).toLocaleDateString()} overnight run</b>
                  <span>{run.requested} issues</span>
                </div>
                <div className="run-stats">
                  <span><b>{run.prsOpened}</b> fixes opened</span>
                  <span><b>{run.merged}</b> approved &amp; merged</span>
                  <span><b>{run.flawsCaught}</b> mistakes caught &amp; corrected</span>
                </div>
                <p className="explain soft" style={{ marginBottom: 0 }}>{run.note}</p>
              </div>
            ))}
          </div>
        </>
      )}

      {/* ---------------- RULES ---------------- */}
      {tab === 'rules' && (
        <>
          <div className="tab-intro">
            <h1>Rules</h1>
            <p>Stop new vulnerable crypto from ever getting into your code. These run automatically on every change your team makes.</p>
          </div>

          <div className="section">
            <h2>Your rules</h2>
            <p className="explain soft">Click a status to turn a rule on (blocks) or set it to warn-only.</p>
            <div className="tbl-wrap">
              <table className="findings">
                <thead><tr><th>Rule</th><th>Applies to</th><th>Status</th><th>Blocked this month</th></tr></thead>
                <tbody>
                  {(policyRules.length > 0 ? policyRules : data.policies).map((p) => (
                    <tr key={p.id}>
                      <td>{p.rule}</td>
                      <td>{p.scope}</td>
                      <td>
                        <button
                          className={`badge ${p.status === 'enforcing' ? 'verdict-approved' : 'verdict-approved_with_notes'}`}
                          style={{ cursor: 'pointer' }}
                          onClick={() => togglePolicy(p.id, p.status !== 'enforcing')}
                          title="Click to switch between blocking and warn-only"
                        >
                          {p.status === 'enforcing' ? 'blocking' : 'warn only'}
                        </button>
                      </td>
                      <td>{p.blockedThisMonth}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="section">
            <h2>Try it out</h2>
            <p className="explain soft">Paste some code and see whether your rules would let it through.</p>
            <textarea
              className="code-input"
              style={{ minHeight: 84 }}
              placeholder={'const token = jwt.sign(payload, key, { algorithm: "RS256" });'}
              value={gateCode}
              onChange={(e) => setGateCode(e.target.value)}
            />
            <div style={{ marginTop: 12, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
              <button className="btn btn-primary" disabled={gateBusy || gateCode.trim().length === 0} onClick={checkGate}>
                {gateBusy ? 'Checking…' : 'Check this code'}
              </button>
              {gateResult && (
                <span className={`badge ${gateResult.verdict === 'pass' ? 'verdict-approved' : gateResult.verdict === 'warn' ? 'verdict-approved_with_notes' : 'verdict-revised'}`}>
                  {gateResult.verdict === 'pass' ? '✓ Allowed' : gateResult.verdict === 'warn' ? '⚠ Allowed with a warning' : '✕ Blocked'}
                </span>
              )}
            </div>
            {gateResult && gateResult.violations.length > 0 && (
              <div style={{ marginTop: 12 }}>
                {gateResult.violations.map((v, i) => (
                  <div className="review-issue" key={i}>
                    <span className={`badge ${v.action === 'BLOCK' ? 'sev-high' : 'sev-medium'}`}>{v.action === 'BLOCK' ? 'blocked' : 'warning'}</span>
                    <span>Line {v.line}: <b>{v.algorithm}</b> isn&rsquo;t quantum-safe — {v.rule}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}

      {/* ---------------- ACTIVITY ---------------- */}
      {tab === 'activity' && (
        <>
          <div className="tab-intro">
            <h1>Activity</h1>
            <p>A complete, timestamped log of everything — every scan, fix, and decision. This is what you hand your auditor.</p>
          </div>
          <div className="section">
            <div className="tbl-wrap">
              <table className="findings">
                <thead><tr><th>When</th><th>Who / what</th><th>What happened</th><th>Where</th></tr></thead>
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
                    <tr key={`s${i}`} style={{ opacity: 0.6 }}>
                      <td>{new Date(a.at).toLocaleString()}</td>
                      <td className="mono">{a.actor}</td>
                      <td>{a.action}</td>
                      <td className="mono">{a.target}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* ---------------- SETTINGS ---------------- */}
      {tab === 'settings' && (
        <>
          <div className="tab-intro">
            <h1>Settings</h1>
            <p>Connections, your team, and the advanced tools.</p>
          </div>

          <div className="section">
            <h2>Connections</h2>
            <p className="explain soft">What&rsquo;s hooked up. Each turns on by adding one setting — no code needed.</p>
            <div className="tbl-wrap">
              <table className="findings">
                <thead><tr><th>Connection</th><th>Status</th><th>What it does</th></tr></thead>
                <tbody>
                  <tr><td>GitHub</td><td>{data.integrations.github ? <span className="badge verdict-approved">connected</span> : <span className="badge verdict-revised">off</span>}</td><td>Scan private repos and open fixes as pull requests</td></tr>
                  <tr><td>Slack alerts</td><td>{data.integrations.slack ? <span className="badge verdict-approved">connected</span> : <span className="badge verdict-revised">off</span>}</td><td>Ping your team when something new is found or fixed</td></tr>
                  <tr><td>AI engine</td><td>{data.integrations.liveAI ? <span className="badge verdict-approved">connected</span> : <span className="badge verdict-revised">off</span>}</td><td>Powers the live fixing and self-checking</td></tr>
                  <tr><td>Shared storage</td><td>{data.integrations.redis ? <span className="badge verdict-approved">connected</span> : <span className="badge verdict-approved_with_notes">basic</span>}</td><td>Keeps data consistent when hosted online</td></tr>
                </tbody>
              </table>
            </div>
          </div>

          <div className="section">
            <h2>Your team</h2>
            <p className="explain soft">Who can approve fixes. Owners and approvers can approve; viewers can only look.</p>
            <div className="tbl-wrap">
              <table className="findings">
                <thead><tr><th>Person</th><th>Role</th><th>Can approve fixes?</th></tr></thead>
                <tbody>
                  {data.team.map((m) => (
                    <tr key={m.email}>
                      <td className="mono">{m.email}{m.email === data.session.email ? ' (you)' : ''}</td>
                      <td><span className={`badge ${m.role === 'owner' ? 'verdict-approved' : m.role === 'approver' ? 'verdict-approved_with_notes' : 'verdict-revised'}`}>{m.role}</span></td>
                      <td>{m.role === 'viewer' ? 'No' : 'Yes'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <details className="advanced">
            <summary>Advanced tools</summary>

            <div className="section" style={{ marginTop: 14 }}>
              <h2>Re-check everything</h2>
              <p className="explain soft">Re-run all the safety proofs across every fix you&rsquo;ve made, to confirm nothing broke.</p>
              <div style={{ display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
                <button className="btn" disabled={drillBusy} onClick={runDrill}>
                  {drillBusy ? 'Re-checking…' : 'Re-check all fixes'}
                </button>
                {drill && (
                  <span className="explain soft">
                    {drill.testsPassed}/{drill.testsRun} checks passed ·{' '}
                    {drill.regressions === 0 ? <b style={{ color: 'var(--accent)' }}>nothing broke</b> : <b className="sev-crit">{drill.regressions} broke</b>}
                  </span>
                )}
              </div>

              <h3 style={{ marginTop: 20 }}>Upgrade to a newer algorithm</h3>
              <p className="explain soft">
                If a stronger standard comes out, switch everything to it and prove it works — with the real algorithm, in one click.
              </p>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <select className="text-input" value={target} onChange={(e) => setTarget(e.target.value)} style={{ minWidth: 280 }}>
                  {targets.map((t) => (<option key={t.id} value={t.id}>{t.label}</option>))}
                </select>
                <button className="btn" disabled={remigBusy} onClick={runRemigration}>
                  {remigBusy ? 'Proving…' : 'Switch & prove'}
                </button>
              </div>
              {remig && (
                <div className="callout" style={{ marginTop: 12 }}>
                  <b>{remig.label}:</b> proved on {remig.proven}/{remig.applicable} spots
                  {remig.failed === 0 ? <span style={{ color: 'var(--accent)' }}> · all passed ✓</span> : <span className="sev-crit"> · {remig.failed} failed</span>}
                </div>
              )}
            </div>

            <div className="section">
              <h2>Partners to coordinate with <span className="sim-tag">example</span></h2>
              <p className="explain soft">Outside companies that also need to upgrade for your fixes to fully protect you.</p>
              <div className="tbl-wrap">
                <table className="findings">
                  <thead><tr><th>Partner</th><th>What you share</th><th>Their status</th></tr></thead>
                  <tbody>
                    {COUNTERPARTIES.map((c) => (
                      <tr key={c.name}>
                        <td>{c.name}</td>
                        <td>{c.artifact}</td>
                        <td><span className={`badge ${c.state === 'done' ? 'verdict-approved' : c.state === 'in-progress' ? 'verdict-approved_with_notes' : 'verdict-revised'}`}>{c.state === 'done' ? 'done' : c.state === 'in-progress' ? 'in progress' : 'waiting'}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="section">
              <h2>Hardware we can&rsquo;t patch <span className="sim-tag">example</span></h2>
              <p className="explain soft">Devices that can&rsquo;t take a software fix get a replacement plan your auditor can read.</p>
              <div className="tbl-wrap">
                <table className="findings">
                  <thead><tr><th>Device</th><th>Why not</th><th>Plan</th><th>By</th></tr></thead>
                  <tbody>
                    {UNPATCHABLE.map((u) => (
                      <tr key={u.asset}><td>{u.asset}</td><td>{u.why}</td><td>{u.plan}</td><td className="mono">{u.due}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </details>
        </>
      )}

      <p className="footnote">
        The three green-dot repositories run the real thing end-to-end. The wider company view is
        realistic example data, so you can see how it looks at scale.
      </p>
    </div>
  );
}
