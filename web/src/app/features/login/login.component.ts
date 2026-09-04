import { Component, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { NzAlertModule } from 'ng-zorro-antd/alert';
import { NzButtonModule } from 'ng-zorro-antd/button';
import { NzCardModule } from 'ng-zorro-antd/card';
import { NzFormModule } from 'ng-zorro-antd/form';
import { NzInputModule } from 'ng-zorro-antd/input';
import { AuthService } from '../../core/auth.service';

/**
 * Sign-in form (Task 2.8, replaces the placeholder). Submits credentials to
 * POST /api/login via AuthService; since Task 10 the returned bearer JWT is
 * held by the TokenStore (no more session cookie) and rides on every
 * subsequent REST call (authInterceptor) and the checker WS (Task 11).
 * Already-logged-in visitors bounce straight to their `returnUrl` (or their
 * role's landing page). After a successful login the visitor is sent to
 * `returnUrl` when the authGuard redirected here with one (Task 5.7) — and
 * otherwise to the role-aware landing (Task 11): checker → /checker,
 * maker → /maker.
 */
@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    FormsModule,
    NzAlertModule,
    NzButtonModule,
    NzCardModule,
    NzFormModule,
    NzInputModule,
  ],
  templateUrl: './login.component.html',
  styleUrl: './login.component.scss',
})
export class LoginComponent implements OnInit {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  readonly username = signal('');
  readonly password = signal('');
  readonly submitting = signal(false);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    if (this.auth.isLoggedIn()) {
      void this.router.navigate([this.returnUrl() ?? this.defaultLanding()]);
    }
  }

  /**
   * Role-aware landing page (Task 11): checkers land on the checker
   * dashboard, makers on the maker portal. The role is the
   * SERVER-confirmed one mirrored by AuthService from the login response /
   * /api/me (never a client-side guess); anything other than 'checker'
   * (maker, null, …) falls back to /maker.
   */
  private defaultLanding(): string {
    return this.auth.role() === 'checker' ? '/checker' : '/maker';
  }

  /**
   * returnUrl from the query string, only when it is a safe same-origin path
   * (leading '/', but not '//' which would be scheme-relative and open-redirect
   * bait).
   */
  private returnUrl(): string | null {
    const ru = this.route.snapshot.queryParamMap.get('returnUrl');
    return ru && ru.startsWith('/') && !ru.startsWith('//') ? ru : null;
  }

  submit(): void {
    if (!this.username().trim() || !this.password()) {
      this.error.set('Enter both username and password.');
      return;
    }
    this.submitting.set(true);
    this.error.set(null);
    this.auth.login(this.username().trim(), this.password()).subscribe({
      next: () => {
        this.submitting.set(false);
        void this.router.navigate([this.returnUrl() ?? this.defaultLanding()]);
      },
      error: (err) => {
        this.submitting.set(false);
        if (err.status === 401) {
          this.error.set('Invalid username or password.');
        } else {
          this.error.set(err.error?.error ?? 'Login failed — is the control plane reachable?');
        }
      },
    });
  }
}
