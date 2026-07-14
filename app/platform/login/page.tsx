'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

export default function PlatformLogin() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [passcode, setPasscode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch('/api/platform/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, passcode }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || 'Sign-in failed.');
      }
      router.push('/platform');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed.');
      setBusy(false);
    }
  };

  return (
    <div className="platform-login-wrap">
      <form className="platform-login" onSubmit={submit}>
        <div className="brand" style={{ marginBottom: 6 }}>
          <span className="logo-mark">⬡</span> <b>Recrypt</b>
          <span className="brand-sub">Enterprise Console</span>
        </div>
        <p className="sub" style={{ marginTop: 0 }}>
          The org-wide platform: continuous fleet scanning, overnight fix runs,
          the crypto policy gate, and the audit trail. Owner sign-in required.
        </p>
        {error && <div className="notice">{error}</div>}
        <label className="platform-label">
          Email
          <input
            className="text-input"
            type="email"
            autoComplete="username"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
            required
          />
        </label>
        <label className="platform-label">
          Passcode
          <input
            className="text-input"
            type="password"
            autoComplete="current-password"
            value={passcode}
            onChange={(e) => setPasscode(e.target.value)}
            placeholder="••••••••"
            required
          />
        </label>
        <button className="btn btn-primary" disabled={busy} style={{ width: '100%', marginTop: 14 }}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        <p className="footnote" style={{ marginTop: 18 }}>
          The passcode is configured via the <code>PLATFORM_PASSCODE</code> environment variable —
          never stored in source. <Link href="/">← Back to the scanner</Link>
        </p>
      </form>
    </div>
  );
}
