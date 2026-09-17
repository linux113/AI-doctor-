/**
 * Server-side proxy for the AI Doctor backend API.
 *
 * Why this file exists
 * --------------------
 * `next.config.js` rewrites cannot attach custom request headers - it is a
 * long-standing, still-open Next.js limitation. So when the backend's optional
 * bearer-token gate is enabled (AIDOCTOR_API_TOKEN), the token has to be
 * injected here instead, in middleware, via `NextResponse.rewrite`.
 *
 * This is also the more secure shape: the header is added on the Node server,
 * so the browser never receives, stores, or transmits the token. The dashboard
 * keeps using plain relative fetches (`/api/...`) exactly as before.
 *
 * When AIDOCTOR_API_TOKEN is unset this middleware is inert and defers to the
 * existing `next.config.js` rewrites, so local development is unchanged.
 */

import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const BACKEND_ORIGIN = process.env.AIDOCTOR_BACKEND_ORIGIN || 'http://127.0.0.1:8000';
const API_TOKEN = (process.env.AIDOCTOR_API_TOKEN || '').trim();

export function middleware(request: NextRequest) {
  // Gate disabled: let next.config.js handle the proxying.
  if (!API_TOKEN) {
    return NextResponse.next();
  }

  const requestHeaders = new Headers(request.headers);
  // Overwrite rather than append, so a client-supplied Authorization header can
  // never be forwarded to the backend or win over the server-side secret.
  requestHeaders.set('authorization', `Bearer ${API_TOKEN}`);

  const target = new URL(request.nextUrl.pathname + request.nextUrl.search, BACKEND_ORIGIN);

  return NextResponse.rewrite(target, {
    request: { headers: requestHeaders },
  });
}

export const config = {
  // Only the proxied API surface. Deliberately excludes _next/static,
  // _next/image and favicon so normal page navigation is untouched.
  matcher: ['/api/:path*', '/health'],
};
