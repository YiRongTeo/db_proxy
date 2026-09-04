import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { ApiService } from './api.service';
import { AuthService } from './auth.service';
import { TokenStore } from './token-store.service';

/**
 * Task 10: AuthService is token-driven. login() persists the JWT returned by
 * POST /api/login and mirrors the server-confirmed username + role;
 * restoreSession() only calls GET /api/me when a token is stored (and drops
 * it on 401); logout() clears token + identity even when the server call
 * fails; with no stored token the restore completes immediately.
 */
describe('AuthService (Task 10: bearer JWT transport)', () => {
  let api: {
    me: ReturnType<typeof vi.fn>;
    login: ReturnType<typeof vi.fn>;
    logout: ReturnType<typeof vi.fn>;
  };
  let auth: AuthService;
  let tokens: TokenStore;

  const loginResponse = {
    token: 'jwt-abc',
    username: 'alice',
    role: 'maker',
    expires_in: 28800,
  };

  beforeEach(() => {
    api = {
      me: vi.fn(),
      login: vi.fn(),
      logout: vi.fn(),
    };
    TestBed.configureTestingModule({
      providers: [{ provide: ApiService, useValue: api }],
    });
    auth = TestBed.inject(AuthService);
    tokens = TestBed.inject(TokenStore);
    tokens.clear();
  });

  describe('restoreSession', () => {
    it('with a stored token validates it via /api/me and mirrors username + role', async () => {
      tokens.set('jwt-abc');
      api.me.mockReturnValue(of({ username: 'admin', role: 'maker' }));
      expect(auth.restored()).toBe(false);

      await auth.restoreSession();

      expect(api.me).toHaveBeenCalled();
      expect(auth.user()).toBe('admin');
      expect(auth.role()).toBe('maker');
      expect(auth.isLoggedIn()).toBe(true);
      expect(auth.restored()).toBe(true);
      // The valid token survives the restore.
      expect(tokens.get()).toBe('jwt-abc');
    });

    it('drops the stored token and keeps user null when /api/me rejects it (401)', async () => {
      tokens.set('jwt-dead');
      api.me.mockReturnValue(throwError(() => ({ status: 401 })));

      await auth.restoreSession();

      expect(auth.user()).toBeNull();
      expect(auth.role()).toBeNull();
      expect(auth.isLoggedIn()).toBe(false);
      expect(auth.restored()).toBe(true);
      expect(tokens.get()).toBeNull(); // dead bearer is gone
    });

    it('keeps user null but RETAINS the token on network errors', async () => {
      tokens.set('jwt-abc');
      api.me.mockReturnValue(throwError(() => ({ status: 0 })));

      await auth.restoreSession();

      expect(auth.user()).toBeNull();
      expect(auth.isLoggedIn()).toBe(false);
      expect(auth.restored()).toBe(true);
      // Transient failure — the token may still be valid; next boot retries.
      expect(tokens.get()).toBe('jwt-abc');
    });

    it('with NO stored token skips /api/me and flips restored immediately', async () => {
      expect(tokens.get()).toBeNull();

      await auth.restoreSession();

      expect(api.me).not.toHaveBeenCalled(); // no pointless 401 round-trip
      expect(auth.user()).toBeNull();
      expect(auth.isLoggedIn()).toBe(false);
      expect(auth.restored()).toBe(true);
    });

    it('is idempotent: concurrent callers share one /api/me request', async () => {
      tokens.set('jwt-abc');
      api.me.mockReturnValue(of({ username: 'admin', role: 'maker' }));

      await Promise.all([auth.restoreSession(), auth.restoreSession()]);

      expect(api.me).toHaveBeenCalledTimes(1);
      expect(auth.restored()).toBe(true);
      expect(auth.user()).toBe('admin');
    });
  });

  describe('login / logout', () => {
    it('login stores the JWT and mirrors the SERVER-confirmed username + role', () => {
      api.login.mockReturnValue(of(loginResponse)); // server normalizes 'Alice ' → 'alice'

      auth.login('Alice ', 'pw').subscribe();

      expect(api.login).toHaveBeenCalledWith('Alice ', 'pw');
      expect(auth.user()).toBe('alice'); // res.username wins over the argument
      expect(auth.role()).toBe('maker');
      expect(auth.isLoggedIn()).toBe(true);
      expect(tokens.get()).toBe('jwt-abc'); // persisted for page-reload restore
    });

    it('logout clears the token + identity even when the server call fails', () => {
      auth.user.set('admin');
      auth.role.set('maker');
      tokens.set('jwt-abc');
      api.logout.mockReturnValue(throwError(() => ({ status: 500 })));

      auth.logout().subscribe({ error: () => undefined });

      expect(auth.user()).toBeNull();
      expect(auth.role()).toBeNull();
      expect(auth.isLoggedIn()).toBe(false);
      expect(tokens.get()).toBeNull();
    });

    it('logout clears the token + identity after a successful denylist call', () => {
      auth.user.set('admin');
      auth.role.set('maker');
      tokens.set('jwt-abc');
      api.logout.mockReturnValue(of({ ok: 'true' }));

      auth.logout().subscribe();

      expect(api.logout).toHaveBeenCalled();
      expect(auth.user()).toBeNull();
      expect(auth.role()).toBeNull();
      expect(tokens.get()).toBeNull();
    });
  });
});
