import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { ApiService } from './api.service';
import { AuthService } from './auth.service';
import { TokenStore } from './token-store.service';
import { authGuard } from './auth.guard';

@Component({ template: '', standalone: true })
class StubCmp {}

/**
 * Task 10: the guard logic is unchanged (restore-then-check), but the restore
 * path is token-driven — with a stored JWT the guard waits for GET /api/me;
 * with no token the restore completes instantly and the visitor is bounced to
 * /login without any /api/me round-trip.
 */
describe('authGuard', () => {
  let api: {
    me: ReturnType<typeof vi.fn>;
    login: ReturnType<typeof vi.fn>;
    logout: ReturnType<typeof vi.fn>;
  };
  let tokens: TokenStore;

  beforeEach(() => {
    api = {
      me: vi.fn(() => of({ username: 'admin', role: 'maker' })),
      login: vi.fn(),
      logout: vi.fn(),
    };
    TestBed.configureTestingModule({
      providers: [
        provideRouter([
          { path: 'maker', component: StubCmp, canActivate: [authGuard] },
          { path: 'login', component: StubCmp },
        ]),
        { provide: ApiService, useValue: api },
      ],
    });
    tokens = TestBed.inject(TokenStore);
    tokens.clear();
    tokens.set('guard-jwt'); // a stored token: restore validates via /api/me
  });

  it('lets a restored session through', async () => {
    const auth = TestBed.inject(AuthService);
    await auth.restoreSession(); // boot restore already done (e.g. App ngOnInit)

    const router = TestBed.inject(Router);
    expect(await router.navigate(['/maker'])).toBe(true);
    expect(router.url).toBe('/maker');
  });

  it('waits for the boot restore when it has not finished yet (full page load with a stored token)', async () => {
    const router = TestBed.inject(Router);
    // restored() is still false here — the guard itself must await /api/me.
    expect(TestBed.inject(AuthService).restored()).toBe(false);

    expect(await router.navigate(['/maker'])).toBe(true);

    expect(api.me).toHaveBeenCalled();
    expect(router.url).toBe('/maker');
  });

  it('redirects to /login with returnUrl when the stored token is rejected (401)', async () => {
    api.me.mockReturnValue(throwError(() => ({ status: 401 })));
    const router = TestBed.inject(Router);

    expect(await router.navigate(['/maker'])).toBe(true);

    expect(router.url.startsWith('/login')).toBe(true);
    expect(router.url).toContain('returnUrl');
    expect(router.url).toContain(encodeURIComponent('/maker'));
  });

  it('redirects to /login immediately when NO token is stored (no /api/me round-trip)', async () => {
    tokens.clear(); // logged out — nothing to restore
    const router = TestBed.inject(Router);

    expect(await router.navigate(['/maker'])).toBe(true);

    expect(api.me).not.toHaveBeenCalled();
    expect(router.url.startsWith('/login')).toBe(true);
    expect(router.url).toContain('returnUrl');
    expect(router.url).toContain(encodeURIComponent('/maker'));
  });
});
