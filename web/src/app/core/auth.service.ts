import { computed, Injectable, signal } from '@angular/core';
import { finalize, Observable, tap } from 'rxjs';
import { ApiService, LoginResponse } from './api.service';

/**
 * UI session state. The session itself lives in the HttpOnly `zt_session`
 * cookie; this service only mirrors who is logged in for the template layer.
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  readonly user = signal<string | null>(null);
  readonly isLoggedIn = computed(() => this.user() !== null);

  constructor(private api: ApiService) {}

  login(username: string, password: string): Observable<LoginResponse> {
    return this.api.login(username, password).pipe(
      tap(() => this.user.set(username)),
    );
  }

  logout(): Observable<unknown> {
    // finalize: clear the UI session even if the server call fails —
    // the user is leaving regardless.
    return this.api.logout().pipe(finalize(() => this.user.set(null)));
  }
}
