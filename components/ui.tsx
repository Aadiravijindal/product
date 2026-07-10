'use client';

import Link from 'next/link';
import type { FindingStatus, RiskLevel } from '@/lib/types';

export function TopBar({ scanId, active }: { scanId?: string; active?: 'results' | 'dashboard' }) {
  return (
    <div className="topbar">
      <div className="brand">
        <Link href="/">
          <span className="logo-mark">⬡</span> Recrypt
        </Link>
        <span className="brand-sub">Post-Quantum Migration Agent</span>
      </div>
      <nav>
        <Link href="/">New scan</Link>
        {scanId && (
          <>
            <Link href={`/scan/${scanId}`} className={active === 'results' ? 'active' : ''}>
              Scan results
            </Link>
            <Link href={`/scan/${scanId}/dashboard`} className={active === 'dashboard' ? 'active' : ''}>
              Dashboard
            </Link>
          </>
        )}
      </nav>
    </div>
  );
}

export function RiskBadge({ risk }: { risk: RiskLevel }) {
  return <span className={`badge badge-${risk.toLowerCase()}`}>{risk}</span>;
}

const STATUS_LABELS: Record<FindingStatus, string> = {
  not_reviewed: 'Not Reviewed',
  migrated: 'Migrated ✓',
  rejected: 'Rejected',
  escalated: 'Escalated',
};

export function StatusBadge({ status }: { status: FindingStatus }) {
  return <span className={`badge badge-status-${status}`}>{STATUS_LABELS[status]}</span>;
}

export function usageLabel(usage: string): string {
  return usage.replace(/_/g, ' ');
}

export function getReviewer(): string {
  if (typeof window === 'undefined') return 'Demo User';
  return window.localStorage.getItem('recrypt.reviewer') || 'Demo User';
}
