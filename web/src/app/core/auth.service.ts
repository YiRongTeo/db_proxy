import { computed, Injectable, signal } from '@angular/core';
import { catchError, finalize, map, Observable, of, tap } from 'rxjs';
import { firstValueFrom } from 'rxjs';
import { ApiService, LoginResponse } from './api.service';
import { TokenStore } from './token-store.service';

/**
 * UI session state. Since Task 10 the session is a bearer JWT held by the
 * TokenStore (memory + sessionStorage); this service mirrors the
 * SERVER-confirmed identity (username + role) into signals for the template
 * layer and drives the boot-time restore:
 *
 * - login(): persists the token returned by POST /api/login and mirrors
 *   username + role from the SAME response (server-normalized values win).
 * - logout(): asks the backend to denylist the token's jti, then clears the
 *   token + identity regardless of the server's answer.
 * - restoreSession(): a full page load re-hydrates the token from
 *   sessionStorage. If one is stored it is validated against GET /api/me
 *   (which also refreshes username + role); a 401 means the token is dead
 *   (expired/denylisted) and it is dropped. No stored token means logged
 *   out — `restored` flips true immediately with no pointless /api/me
 *   round-trip. `restored` is what the authGuard blocks on.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  readonly user = signal<string | null>(null);
  /** Control-plane role ('maker' | 'checker'), server-confirmed (Task 6). */
  readonly role = signal<string | null>(null);
  readonly isLoggedIn = computed(() => this.user() !== null);
  /** True once the boot-time session restore has completed (success or not). */
  readonly restored = signal(false);

  private restorePromise: Promise<void> | null = null;

  constructor(
    private api: ApiService,
    private tokens: TokenStore,
  ) {}

  login(username: string, password: string): Observable<LoginResponse> {
    return this.api.login(username, password).pipe(
      // Mirror the SERVER-confirmed username + role from the response — not
      // the arguments, which the server may normalize — and persist the JWT
      // so a page reload re-attaches it (Task 10).
      tap((res) => {
        this.user.set(res.username);
        this.role.set(res.role);
        this.tokens.set(res.token);
      }),
    );
  }

  logout(): Observable<unknown> {
    // finalize: clear the token + UI session even if the server call fails —
    // the user is leaving regardless.
    return this.api.logout().pipe(finalize(() => this.clearSession()));
  }

  private clearSession(): void {
    this.user.set(null);
    this.role.set(null);
    this.tokens.clear();
  }

  /**
   * Boot-time session restore (Task 10 — token-driven now, not cookie-driven).
   * With a stored token → GET /api/me validates it and refreshes user + role;
   * a 401 drops the dead token. Without a token → logged out: `restored`
   * flips true immediately, no pointless 401 round-trip. Idempotent:
   * concurrent callers (App ngOnInit + a guard firing mid-restore) share a
   * single request.
   */
  restoreSession(): Promise<void> {
    if (!this.restorePromise) {
      if (!this.tokens.get()) {
        this.restored.set(true);
        this.restorePromise = Promise.resolve();
      } else {
        this.restorePromise = firstValueFrom(
          this.api.me().pipe(
            tap((res) => {
              this.user.set(res.username);
              this.role.set(res.role);
            }),
            catchError((err) => {
              // 401 = the server rejected the stored token (expired or
              // denylisted) — drop it so nothing keeps riding a dead bearer.
              // Network errors keep it: the token may still be valid and the
              // next full reload can retry the restore.
              if (err?.status === 401) {
                this.tokens.clear();
              }
              return of(null);
            }),
            finalize(() => this.restored.set(true)),
            map(() => undefined),
          ),
        );
      }
    }
    return this.restorePromise;
  }
}
