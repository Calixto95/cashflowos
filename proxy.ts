import { NextResponse, type NextRequest } from 'next/server'

// 🔒 Don't edit — this keeps your robot safe.
// The passcode gate. In Next 16 this file is called `proxy.ts` (the old name
// `middleware.ts` is deprecated and would print scary warnings for beginners).
//
// It's "a lock on the door, not bank-grade auth": if APP_PASSCODE is set and the
// visitor has no valid session cookie, we bounce them to /login. If APP_PASSCODE is NOT
// set, we DON'T gate anything — the app shows a calm setup banner instead, so a
// half-configured clone never locks you out of your own HQ.
//
// The cookie must be GENUINE, not merely present: app/api/login/route.ts mints
// `nonce.HMAC(nonce, passcode)`, and we re-check that signature here. Changing
// APP_PASSCODE therefore logs everyone out.
async function isValidSession(token: string, passcode: string): Promise<boolean> {
  const dot = token.indexOf('.')
  if (dot < 1) return false
  const nonce = token.slice(0, dot)
  const sig = token.slice(dot + 1)
  if (!/^[0-9a-f]{64}$/.test(sig)) return false      // SHA-256 HMAC, as lowercase hex

  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(passcode),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  )
  const sigBytes = Uint8Array.from(sig.match(/../g)!, (h) => parseInt(h, 16))
  return crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(nonce)) // constant-time
}

export async function proxy(req: NextRequest) {
  const passcode = (process.env.APP_PASSCODE ?? '').trim()
  if (!passcode) return NextResponse.next()          // no lock installed → open door

  const session = req.cookies.get('cfo_session')?.value
  if (session && (await isValidSession(session, passcode))) return NextResponse.next()

  const url = req.nextUrl.clone()
  url.pathname = '/login'
  return NextResponse.redirect(url)
}

// The matcher protects every page EXCEPT the ones below, which must stay reachable
// without the cookie:
//   • /login, /api/login      — you can't log in through a locked login page
//   • /api/telegram           — Telegram's webhook (has its own secret-header guard)
//   • /api/cron-daily         — the daily cron (has its own fail-closed Bearer guard)
//   • /manifest.webmanifest   — the REAL PWA manifest (app/manifest.ts serves HERE);
//     /manifest.json          — belt-and-braces extra so install never silently breaks
//   • /icons/*, /favicon.ico, /_next/* — static assets the install/render needs
// A single missed exclusion here = a locked webhook on class day, so this list is tested.
export const config = {
  matcher: [
    '/((?!login|api/login|api/telegram|api/cron-daily|manifest\\.webmanifest|manifest\\.json|icons|_next|favicon\\.ico).*)',
  ],
}
