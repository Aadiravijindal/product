'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { RiskBadge, TopBar, getReviewer, usageLabel } from '@/components/ui';
import { sideBySideDiff } from '@/lib/diff';
import type { Finding } from '@/lib/types';

const THRESHOLD = 85;

function downloadPatch(finding: Finding, patchedCode: string) {
  const base = finding.file.split('/').pop() || 'patched';
  const blob = new Blob([patchedCode], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${base}.quantum-safe`;
  a.click();
  URL.revokeObjectURL(url);
}

const AGENT_STEPS = [
  'Classifying algorithm, key size, and business context…',
  'Generating hybrid post-quantum patch (ML-DSA / ML-KEM)…',
  'Adversarial review — a second agent attacks the patch…',
  'Revising if the reviewer found issues, then running real crypto proofs…',
];

function AgentProgress({ live }: { live: boolean }) {
  const [step, setStep] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    // Pace the visible steps across the expected live-pipeline duration; the
    // last step deliberately dwells (that's where the review + optional
    // revision round happens — the longest, most valuable part).
    const stepMs = live ? 7000 : 900;
    const s = setInterval(() => setStep((x) => Math.min(x + 1, AGENT_STEPS.length - 1)), stepMs);
    const e = setInterval(() => setElapsed((x) => x + 1), 1000);
    return () => { clearInterval(s); clearInterval(e); };
  }, [live]);
  return (
    <div className="loading-panel">
      <div className="spinner" />
      <div style={{ fontSize: 16, marginBottom: 14 }}>
        Remediation agent working… <span className="agent-timer">{elapsed}s</span>
      </div>
      <div className="agent-steps">
        {AGENT_STEPS.map((s, i) => (
          <div key={i} className={`agent-step ${i < step ? 'done' : i === step ? 'now' : ''}`}>
            <span className="agent-step-ico">{i < step ? '✓' : i === step ? '›' : '·'}</span> {s}
          </div>
        ))}
      </div>
      {live && (
        <div className="agent-note">
          Live two-agent pipeline. Large files take ~1–2 minutes — if the reviewer
          finds a flaw, the agent rewrites the patch and re-checks it. That extra
          pass is normal and is exactly what makes the fix trustworthy.
        </div>
      )}
    </div>
  );
}

export default function FindingDetail() {
  const { scanId, findingId } = useParams<{ scanId: string; findingId: string }>();
  const router = useRouter();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [phase, setPhase] = useState<'loading' | 'analyzing' | 'ready' | 'error'>('loading');
  const [error, setError] = useState<string | null>(null);
  const [acting, setActing] = useState(false);
  const [copied, setCopied] = useState(false);
  const [claudeLive, setClaudeLive] = useState(false);
  const [question, setQuestion] = useState('');
  const [qa, setQa] = useState<{ q: string; a: string }[]>([]);
  const [asking, setAsking] = useState(false);

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
    fetch('/api/repos').then((r) => r.json()).then((d) => setClaudeLive(Boolean(d.claude))).catch(() => {});
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

  const copyPatch = async (code: string) => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch { /* clipboard unavailable (non-secure context) */ }
  };

  const ask = async () => {
    const q = question.trim();
    if (!q || asking) return;
    setAsking(true);
    setQuestion('');
    try {
      const res = await fetch(`/api/scan/${scanId}/findings/${findingId}/ask`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q }),
      });
      const data = await res.json();
      setQa((prev) => [...prev, { q, a: res.ok ? data.answer : data.error || 'The agent could not answer — retry.' }]);
    } catch {
      setQa((prev) => [...prev, { q, a: 'The agent could not answer — retry.' }]);
    }
    setAsking(false);
  };

  const act = async (action: 'approve' | 'reject' | 'escalate') => {
    setActing(true);
    try {
      const res = await fetch(`/api/scan/${scanId}/findings/${findingId}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, reviewer: getReviewer() }),
      });
      if (!res.ok) throw new Error('action failed');
      router.push(`/scan/${scanId}?just=${findingId}`);
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
        <AgentProgress live={claudeLive} />
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
        {a.hndl && (
          <div className={`hndl ${a.hndl.urgent ? 'hndl-urgent' : ''}`}>
            <span className="hndl-label">{a.hndl.urgent ? '⏱ ' : '📅 '}{a.hndl.label}</span>
            <span className="hndl-detail">{a.hndl.detail}</span>
          </div>
        )}
      </div>

      <div className="section">
        <h2>
          Proposed fix
          <span style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
            <button className="btn btn-sm" onClick={() => downloadPatch(finding, a.patchedCode)}>Download patched file</button>
            <button className="btn btn-sm" onClick={() => void copyPatch(a.patchedCode)}>{copied ? 'Copied ✓' : 'Copy patch'}</button>
          </span>
        </h2>
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

      {a.review && (
        <div className="section">
          <h2>
            Independent security review
            <span className={`badge verdict-${a.review.verdict}`}>
              {a.review.verdict === 'approved' ? 'Approved' : a.review.verdict === 'approved_with_notes' ? 'Approved with notes' : 'Revised after review'}
            </span>
            <span className="engine-tag">
              {a.review.engine === 'claude'
                ? 'adversarial reviewer: separate Claude agent (did not write the patch)'
                : `policy checklist: ${a.review.checksRun} static checks`}
            </span>
          </h2>
          <p className="explain" style={{ fontSize: 14 }}>{a.review.summary}</p>
          {a.review.issues.length > 0 && (
            <div style={{ marginTop: 10 }}>
              {a.review.issues.map((iss, i) => (
                <div className="review-issue" key={i}>
                  <span className={`badge sev-${iss.severity}`}>{iss.severity}</span>
                  <span>
                    <b>{iss.title}</b>{iss.resolved ? ' — resolved in the revised patch ✓' : ''}
                    <span className="test-detail">{iss.detail}</span>
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

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
        {a.digest && (
          <div className="digest-line">
            Proof bundle SHA-256 <span title="Hash over original code + patch + test evidence. In production this digest is HSM-signed for third-party audit.">ⓘ</span>:{' '}
            <code>{a.digest}</code>
          </div>
        )}
        {a.tests.map((t, i) => (
          <div className="test-line" key={i}>
            <span className={`test-ico ${t.passed ? 'pass' : 'fail'}`}>{t.passed ? '✓' : '✗'}</span>
            <span style={{ flex: 1 }}>
              {t.name}
              <span className="test-detail">{t.detail}</span>
              {t.evidence && (
                <details className="evidence">
                  <summary>View cryptographic evidence</summary>
                  <pre>{t.evidence}</pre>
                </details>
              )}
            </span>
          </div>
        ))}
        <p className="tests-scope">
          These checks execute the real NIST ML-DSA-65 / ML-KEM-768 algorithms and confirm the
          patched function surface is unchanged, so no caller breaks. Compiling the generated patch
          into your own build and test suite is the final production step.
        </p>
      </div>

      {claudeLive && (
        <div className="section">
          <h2>Ask the agent<span className="engine-tag">live — grounded in this finding&apos;s code and patch</span></h2>
          {qa.map((x, i) => (
            <div key={i} className="qa-pair">
              <div className="qa-q">{x.q}</div>
              <div className="qa-a">{x.a}</div>
            </div>
          ))}
          {asking && <div className="qa-a qa-thinking">Thinking…</div>}
          <div style={{ display: 'flex', gap: 10, marginTop: qa.length ? 12 : 0 }}>
            <input
              className="text-input"
              style={{ flex: 1 }}
              placeholder={'e.g. "Why hybrid instead of pure ML-DSA?" or "What breaks for our downstream verifiers?"'}
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void ask(); }}
            />
            <button className="btn" disabled={asking || question.trim().length === 0} onClick={() => void ask()}>Ask</button>
          </div>
        </div>
      )}

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
