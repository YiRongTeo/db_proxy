import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { ApiService } from './api.service';
import { AuthService } from './auth.service';

describe('AuthService.restoreSession', () => {
  let api: {
    me: ReturnType<typeof vi.fn>;
    login: ReturnType<typeof vi.fn>;
    logout: ReturnType<typeof vi.fn>;
  };
  let auth: AuthService;

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
  });

  it('mirrors the session username into user and flips restored on 200', async () => {
    api.me.mockReturnValue(of({ username: 'admin' }));
    expect(auth.restored()).toBe(false);

    await auth.restoreSession();

    expect(api.me).toHaveBeenCalled();
    expect(auth.user()).toBe('admin');
    expect(auth.isLoggedIn()).toBe(true);
    expect(auth.restored()).toBe(true);
  });

  it('keeps user null and still flips restored on 401', async () => {
    api.me.mockReturnValue(throwError(() => ({ status: 401 })));

    await auth.restoreSession();

    expect(auth.user()).toBeNull();
    expect(auth.isLoggedIn()).toBe(false);
    expect(auth.restored()).toBe(true);
  });

  it('keeps user null and still flips restored on network errors', async () => {
    api.me.mockReturnValue(throwError(() => ({ status: 0 })));

    await auth.restoreSession();

    expect(auth.user()).toBeNull();
    expect(auth.restored()).toBe(true);
  });

  it('is idempotent: concurrent callers share one /api/me request', async () => {
    api.me.mockReturnValue(of({ username: 'admin' }));

    await Promise.all([auth.restoreSession(), auth.restoreSession()]);

    expect(api.me).toHaveBeenCalledTimes(1);
    expect(auth.restored()).toBe(true);
    expect(auth.user()).toBe('admin');
  });

  // ---- Task 9.11: review remediation (auth loop + normalized username) --------

  it('login mirrors the SERVER-confirmed username into user, not the typed argument', () => {
    api.login.mockReturnValue(of({ username: 'alice' })); // server normalizes 'Alice ' → 'alice'

    auth.login('Alice ', 'pw').subscribe();

    expect(api.login).toHaveBeenCalledWith('Alice ', 'pw');
    expect(auth.user()).toBe('alice'); // res.username wins over the argument
    expect(auth.isLoggedIn()).toBe(true);
  });

  it('logout clears the UI session even when the server call fails', () => {
    auth.user.set('admin');
    api.logout.mockReturnValue(throwError(() => ({ status: 500 })));

    auth.logout().subscribe({ error: () => undefined });

    expect(auth.user()).toBeNull();
    expect(auth.isLoggedIn()).toBe(false);
  });
});
