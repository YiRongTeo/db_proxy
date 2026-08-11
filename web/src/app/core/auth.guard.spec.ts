import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { ApiService } from './api.service';
import { AuthService } from './auth.service';
import { authGuard } from './auth.guard';

@Component({ template: '', standalone: true })
class StubCmp {}

describe('authGuard', () => {
  let api: {
    me: ReturnType<typeof vi.fn>;
    login: ReturnType<typeof vi.fn>;
    logout: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    api = {
      me: vi.fn(() => of({ username: 'admin' })),
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
  });

  it('lets a restored session through', async () => {
    const auth = TestBed.inject(AuthService);
    await auth.restoreSession(); // boot restore already done (e.g. App ngOnInit)

    const router = TestBed.inject(Router);
    expect(await router.navigate(['/maker'])).toBe(true);
    expect(router.url).toBe('/maker');
  });

  it('waits for the boot restore when it has not finished yet (full page load with a valid cookie)', async () => {
    const router = TestBed.inject(Router);
    // restored() is still false here — the guard itself must await /api/me.
    expect(TestBed.inject(AuthService).restored()).toBe(false);

    expect(await router.navigate(['/maker'])).toBe(true);

    expect(api.me).toHaveBeenCalled();
    expect(router.url).toBe('/maker');
  });

  it('redirects to /login with returnUrl when there is no session', async () => {
    api.me.mockReturnValue(throwError(() => ({ status: 401 })));
    const router = TestBed.inject(Router);

    expect(await router.navigate(['/maker'])).toBe(true);

    expect(router.url.startsWith('/login')).toBe(true);
    expect(router.url).toContain('returnUrl');
    expect(router.url).toContain(encodeURIComponent('/maker'));
  });
});
