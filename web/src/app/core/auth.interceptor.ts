import { HttpContextToken, HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { TokenStore } from './token-store.service';

/**
 * Opt-out flag: when true, this request must NOT receive an Authorization
 * header. Used by POST /api/login — it is the one endpoint that EXCHANGES
 * credentials for a token, so a stale stored token must not ride along.
 */
export const AUTH_SKIP = new HttpContextToken<boolean>(() => false);

/**
 * Task 10: attaches `Authorization: Bearer <jwt>` to every outgoing request
 * whenever the TokenStore holds a token. Registered in app.config.ts via
 * provideHttpClient(withInterceptors([authInterceptor])) — one place, so API
 * callers need no per-call options (the old `withCredentials` cookie
 * transport is gone). Requests opted out with AUTH_SKIP (login) pass through
 * untouched, as do requests made while no token is stored (e.g. before
 * login — the backend answers 401 and the UI treats that as logged-out).
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  if (req.context.get(AUTH_SKIP)) {
    return next(req);
  }
  const token = inject(TokenStore).get();
  if (!token) {
    return next(req);
  }
  return next(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
};
