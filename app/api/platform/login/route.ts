import { NextRequest, NextResponse } from 'next/server';
import { checkLogin, platformToken } from '@/lib/platform';
import { appendAudit } from '@/lib/store';

const COOKIE = 'recrypt_platform';

/** POST { email, passcode } — owner login for the Enterprise Console. */
export async function POST(req: NextRequest) {
  let body: { email?: string; passcode?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }
  if (!checkLogin(body.email ?? '', body.passcode ?? '')) {
    return NextResponse.json({ error: 'Wrong email or passcode.' }, { status: 401 });
  }
  await appendAudit(body.email!.trim().toLowerCase(), 'Console sign-in', 'enterprise-console');
  const res = NextResponse.json({ ok: true });
  res.cookies.set(COOKIE, platformToken(), {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 7,
  });
  return res;
}

/** DELETE — log out. */
export async function DELETE() {
  const res = NextResponse.json({ ok: true });
  res.cookies.set(COOKIE, '', { httpOnly: true, sameSite: 'lax', path: '/', maxAge: 0 });
  return res;
}
