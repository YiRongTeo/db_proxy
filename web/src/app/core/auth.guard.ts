import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

/**
 * Route guard for the Maker portal and Checker dashboard: requires an
 * authenticated JWT principal.
 *
 * On a cold boot the stored JWT (TokenStore, re-hydrated from sessionStorage)
 * is only validated by AuthService.restoreSession() (GET /api/me); if the
 * restore has not finished yet the guard waits for it, so a full page load
 * with a valid token no longer bounces to /login (Task 5.7, token-based since
 * Task 10). With no stored token restoreSession() completes immediately
 * (`restored` flips true), and unauthenticated visitors are sent to /login
 * with the attempted URL in `returnUrl` so a successful login lands them back
 * where they were headed.
 */
export const authGuard: CanActivateFn = async (_route, state) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  if (!auth.restored()) {
    await auth.restoreSession();
  }
  if (auth.isLoggedIn()) {
    return true;
  }
  return router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });
};
