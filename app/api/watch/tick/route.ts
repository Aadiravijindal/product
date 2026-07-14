import { NextResponse } from 'next/server';
import { appendAudit, getWatchlist, saveWatchlist } from '@/lib/store';
import { rescanEntry } from '@/lib/watch';
import { notify } from '@/lib/notify';

/**
 * GET — re-scan every watched repo and record drift. Invoked by the Vercel
 * cron (vercel.json) for true always-on monitoring, and by the console's
 * "Re-scan all" button. Deliberately unauthenticated-readable trigger with
 * no parameters: it can only refresh state that already exists.
 */
export const maxDuration = 300;

export async function GET() {
  const list = await getWatchlist();
  if (list.length === 0) return NextResponse.json({ rescanned: 0, drift: [] });

  const updated: typeof list = [];
  const drift: { label: string; newFindings: string[] }[] = [];
  for (const entry of list) {
    try {
      const next = await rescanEntry(entry);
      updated.push(next);
      if (next.newSinceLast.length > 0) {
        drift.push({ label: next.label, newFindings: next.newSinceLast });
        await appendAudit(
          'watcher',
          `DRIFT: ${next.newSinceLast.length} new quantum-vulnerable usage${next.newSinceLast.length === 1 ? '' : 's'} since last scan`,
          next.label
        );
        await notify(`:rotating_light: Recrypt drift on *${next.label}*: ${next.newSinceLast.length} new quantum-vulnerable usage(s) — ${next.newSinceLast.slice(0, 3).join(', ')}`);
      }
    } catch {
      updated.push(entry); // keep the old state; try again next tick
    }
  }
  await saveWatchlist(updated);
  if (drift.length === 0) {
    await appendAudit('watcher', `Scheduled watch tick: ${updated.length} repo(s) re-scanned, no new vulnerable crypto`, 'watchlist');
  }
  return NextResponse.json({ rescanned: updated.length, drift });
}
