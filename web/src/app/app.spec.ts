import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { of, throwError } from 'rxjs';
import { App } from './app';
import { ApiService } from './core/api.service';
import { AuthService } from './core/auth.service';
import { TokenStore } from './core/token-store.service';

describe('App', () => {
  let api: {
    me: ReturnType<typeof vi.fn>;
    login: ReturnType<typeof vi.fn>;
    logout: ReturnType<typeof vi.fn>;
  };

  beforeEach(async () => {
    api = {
      me: vi.fn(() => of({ username: 'admin', role: 'maker' })),
      login: vi.fn(() =>
        of({ token: 'jwt-admin', username: 'admin', role: 'maker', expires_in: 28800 }),
      ),
      logout: vi.fn(() => of(null)),
    };
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideRouter([]), { provide: ApiService, useValue: api }],
    }).compileComponents();
    // A stored JWT (sessionStorage re-hydrated by TokenStore): the boot-time
    // restore validates it against /api/me, exactly like a page reload with a
    // live session (Task 10).
    const tokens = TestBed.inject(TokenStore);
    tokens.clear();
    tokens.set('boot-jwt');
  });

  it('should create the app', () => {
    const fixture = TestBed.createComponent(App);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  it('renders the app shell with a router outlet', () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('router-outlet')).not.toBeNull();
  });

  it('kicks off the boot-time token restore and flips restored', async () => {
    const auth = TestBed.inject(AuthService);
    expect(auth.restored()).toBe(false);

    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(api.me).toHaveBeenCalled();
    expect(auth.restored()).toBe(true);
    // The restore mirrors the server-confirmed identity, role included (Task 6).
    expect(auth.user()).toBe('admin');
    expect(auth.role()).toBe('maker');
  });

  it('shows the top nav with Maker/Checker links, username and Logout when logged in', async () => {
    const auth = TestBed.inject(AuthService);
    auth.user.set('admin');

    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    const el = fixture.nativeElement as HTMLElement;
    const links = Array.from(el.querySelectorAll('header.topnav a')).map((a) =>
      (a as HTMLElement).textContent?.trim(),
    );
    expect(links).toContain('Maker');
    expect(links).toContain('Checker');
    expect(el.querySelector('.topnav-user')?.textContent?.trim()).toBe('admin');
    expect(el.querySelector('.topnav-logout')).not.toBeNull();
  });

  it('hides the top nav when logged out (stored token rejected)', async () => {
    api.me.mockReturnValue(throwError(() => ({ status: 401 })));

    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('header.topnav')).toBeNull();
    // The 401 killed the dead token — nothing rides a rejected bearer.
    expect(TestBed.inject(TokenStore).get()).toBeNull();
  });

  it('logout clears the session and navigates to /login', async () => {
    const auth = TestBed.inject(AuthService);
    auth.user.set('admin');
    const router = TestBed.inject(Router);
    const nav = vi.spyOn(router, 'navigate').mockResolvedValue(true);

    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    await fixture.whenStable();

    fixture.componentInstance.logout();
    await fixture.whenStable();

    expect(api.logout).toHaveBeenCalled();
    expect(auth.isLoggedIn()).toBe(false);
    expect(TestBed.inject(TokenStore).get()).toBeNull(); // JWT cleared too
    expect(nav).toHaveBeenCalledWith(['/login']);
  });
});
