import { Injectable } from '@angular/core';

/** sessionStorage key holding the control-plane bearer JWT across reloads. */
const STORAGE_KEY = 'zt_jwt';

/**
 * Task 10: in-memory + sessionStorage holder for the control-plane bearer JWT.
 * A page reload re-hydrates the token from sessionStorage so the SPA can
 * re-attach `Authorization: Bearer <jwt>` (via authInterceptor) without a
 * re-login. The token still dies when the tab closes — sessionStorage, not
 * localStorage, by design.
 *
 * Storage access is defensive: some environments (private-browsing modes,
 * sandboxed iframes) throw on sessionStorage access; the service then
 * degrades to memory-only for the lifetime of the page, which is enough to
 * keep the SPA working until the next reload.
 */
@Injectable({ providedIn: 'root' })
export class TokenStore {
  private token: string | null = null;

  constructor() {
    try {
      this.token = sessionStorage.getItem(STORAGE_KEY);
    } catch {
      this.token = null; // storage unavailable — memory-only
    }
  }

  /** The current JWT, or null when not authenticated. */
  get(): string | null {
    return this.token;
  }

  set(token: string): void {
    this.token = token;
    try {
      sessionStorage.setItem(STORAGE_KEY, token);
    } catch {
      /* memory-only */
    }
  }

  clear(): void {
    this.token = null;
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      /* memory-only */
    }
  }
}
