'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { TopBar } from '@/components/ui';
import type { SampleRepoMeta } from '@/lib/types';

const LANG_ICONS: Record<string, string> = { Python: '🐍', Java: '☕', 'Node.js': '🟢' };

export default function Home() {
  const router = useRouter();
  const [repos, setRepos] = useState<SampleRepoMeta[]>([]);
  const [claude, setClaude] = useState<boolean | null>(null);
  const [snippet, setSnippet] = useState('');
  const [reviewer, setReviewer] = useState('');
  const [scanning, setScanning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastScan, setLastScan] = useState<{ id: string; name: string } | null>(null);

  useEffect(() => {
    fetch('/api/repos')
      .then((r) => r.json())
      .then((d) => {
        setRepos(d.repos);
        setClaude(d.claude);
      })
      .catch(() => setError('Could not load sample repos.'));
    setReviewer(window.localStorage.getItem('recrypt.reviewer') || '');
    try {
      const last = window.localStorage.getItem('recrypt.lastScan');
      if (last) setLastScan(JSON.parse(last));
    } catch { /* ignore corrupt localStorage */ }
  }, []);

  const saveReviewer = (name: string) => {
    setReviewer(name);
    window.localStorage.setItem('recrypt.reviewer', name);
  };

  const startScan = async (body: { repoId?: string; code?: string }, key: string) => {
    setScanning(key);
    setError(null);
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'scan failed');
      router.push(`/scan/${data.scanId}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Scan failed — please retry.');
      setScanning(null);
    }
  };

  return (
    <div className="shell">
      <TopBar />
      <h1>Connect a codebase</h1>
      <p className="sub">
        Scan for quantum-vulnerable cryptography, generate hybrid post-quantum patches, and verify them.
        {lastScan && (
          <>
            {' · '}
            <a href={`/scan/${lastScan.id}`}>Resume last scan ({lastScan.name}) →</a>
          </>
        )}
      </p>

      {error && <div className="notice">{error}</div>}
      {claude === false && (
        <div className="notice">
          Running without a Claude API key — analysis of the sample repos uses the built-in remediation library.
          Set <code>ANTHROPIC_API_KEY</code> to enable live AI classification and patch generation for arbitrary pasted code.
        </div>
      )}

      <div className="card-grid">
        {repos.map((repo) => (
          <div className="card" key={repo.id}>
            <div className="lang">
              {LANG_ICONS[repo.language] ?? '📄'} {repo.language}
            </div>
            <div className="name">{repo.name}</div>
            <div className="desc">{repo.description}</div>
            <div className="meta">{repo.fileCount} files</div>
            <button
              className="btn btn-primary"
              disabled={scanning !== null}
              onClick={() => startScan({ repoId: repo.id }, repo.id)}
            >
              {scanning === repo.id ? 'Scanning…' : 'Scan'}
            </button>
          </div>
        ))}
      </div>

      <div className="paste-panel">
        <h2>Or paste your own code snippet</h2>
        <p className="sub" style={{ marginBottom: 12 }}>
          Runs through the exact same pipeline as the sample repos — detection, classification, hybrid patch, equivalence tests.
        </p>
        <textarea
          className="code-input"
          placeholder={'// Paste any Python, Java, JavaScript, or Go code that touches crypto…\n// e.g. jwt.sign(payload, key, { algorithm: "RS256" })'}
          value={snippet}
          onChange={(e) => setSnippet(e.target.value)}
        />
        <div style={{ display: 'flex', gap: 14, marginTop: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            className="btn btn-primary"
            disabled={scanning !== null || snippet.trim().length === 0}
            onClick={() => startScan({ code: snippet }, 'snippet')}
          >
            {scanning === 'snippet' ? 'Scanning…' : 'Scan snippet'}
          </button>
          <label style={{ marginLeft: 'auto', color: 'var(--muted)', fontSize: 13.5 }}>
            Reviewer name:{' '}
            <input
              className="text-input"
              placeholder="Demo User"
              value={reviewer}
              onChange={(e) => saveReviewer(e.target.value)}
              style={{ width: 170 }}
            />
          </label>
        </div>
      </div>

      <p className="footnote">
        Demo mode — scans local sample files and pasted snippets only. The production version connects via API to your
        existing CBOM/discovery tool (SandboxAQ, IBM, Arqit, …) and to your repos. Equivalence tests execute real
        cryptography: RSA/ECDH via the platform crypto library, ML-DSA-65 (FIPS 204) and ML-KEM-768 (FIPS 203) via
        audited post-quantum implementations.
        <br />
        Migration targets follow the NIST standards finalized August 13, 2024 (FIPS 203/204/205). US federal deadlines:
        quantum-safe key establishment by 2030, digital signatures by 2031 — cascading to contractors via CNSA 2.0.
      </p>
    </div>
  );
}
