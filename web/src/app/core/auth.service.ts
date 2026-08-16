import { computed, Injectable, signal } from '@angular/core';
import { catchError, finalize, map, Observable, of, tap } from 'rxjs';
import { firstValueFrom } from 'rxjs';
import { ApiService, LoginResponse } from './api.service';

/**
 * UI session state. The session itself lives in the HttpOnly `zt_session`
 * cookie; this service only mirrors who is logged in for the template layer.
 *
 * `restored` tracks the boot-time session restore (GET /api/me): the SPA never
 * validates the cookie on its own, so a full page load of a guarded route used
 * to bounce to /login even with a valid cookie. restoreSession() fixes that
 * (Task 5.7).
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  readonly user = signal<string | null>(null);
  readonly isLoggedIn = computed(() => this.user() !== null);
  /** True once the boot-time session restore has completed (success or not). */
  readonly restored = signal(false);

  private restorePromise: Promise<void> | null = null;

  constructor(private api: ApiService) {}

  login(username: string, password: string): Observable<LoginResponse> {
    return this.api.login(username, password).pipe(
      // Task 9.11: mirror the SERVER-confirmed username from the response —
      // not the argument, which the server may normalize.
      tap((res) => this.user.set(res.username)),
    );
  }

  logout(): Observable<unknown> {
    // finalize: clear the UI session even if the server call fails —
    // the user is leaving regardless.
    return this.api.logout().pipe(finalize(() => this.user.set(null)));
  }

  /**
   * Validates the HttpOnly zt_session cookie against GET /api/me exactly once
   * per app boot. 200 → the session's username is mirrored into `user`;
   * 401/network error → user stays null. Either way `restored` flips to true,
   * which is what the authGuard blocks on. Idempotent: concurrent callers
   * (App ngOnInit + a guard firing mid-restore) share a single request.
   */
  restoreSession(): Promise<void> {
    if (!this.restorePromise) {
      this.restorePromise = firstValueFrom(
        this.api.me().pipe(
          tap((res) => this.user.set(res.username)),
          catchError(() => of(null)),
          finalize(() => this.restored.set(true)),
          map(() => undefined),
        ),
      );
    }
    return this.restorePromise;
  }
}
