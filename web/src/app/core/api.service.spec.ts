import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import {
  HttpTestingController,
  provideHttpClientTesting,
} from '@angular/common/http/testing';
import { ApiService } from './api.service';
import { authInterceptor } from './auth.interceptor';
import { TokenStore } from './token-store.service';

/**
 * Task 10: ApiService rides on the authInterceptor — every authed call must
 * carry `Authorization: Bearer <token>` and nothing may use the cookie
 * transport (`withCredentials`) anymore. POST /api/login is the exception:
 * it exchanges credentials FOR the token, so its header stays clean even when
 * a (stale) token is already stored.
 */
describe('ApiService (Task 10: Bearer JWT transport)', () => {
  let service: ApiService;
  let http: HttpTestingController;
  let tokens: TokenStore;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        // Register the real interceptor so the assertions exercise the same
        // wiring the app uses (app.config.ts).
        provideHttpClient(withInterceptors([authInterceptor])),
        provideHttpClientTesting(),
      ],
    });
    service = TestBed.inject(ApiService);
    http = TestBed.inject(HttpTestingController);
    tokens = TestBed.inject(TokenStore);
    tokens.clear();
    tokens.set('test-jwt-123'); // an authenticated session by default
  });

  afterEach(() => http.verify());

  it('sessions() GETs /api/sessions with Authorization: Bearer and returns the directory', () => {
    const directory = [
      {
        session_id: 'sess-1',
        username: 'alice',
        db_user: 'app',
        db_type: 'mysql',
        db: 'appdb',
        started_at: '2026-08-11T08:00:00Z',
        last_seen: '2026-08-11T08:05:00Z',
      },
    ];
    service.sessions().subscribe((list) => expect(list).toEqual(directory));

    const req = http.expectOne('/api/sessions');
    expect(req.request.method).toBe('GET');
    expect(req.request.headers.get('Authorization')).toBe('Bearer test-jwt-123');
    expect(req.request.withCredentials).toBe(false); // cookie era is gone
    req.flush(directory);
  });

  it('me() GETs /api/me with the bearer header', () => {
    service.me().subscribe((res) =>
      expect(res).toEqual({ username: 'admin', role: 'maker' }),
    );

    const req = http.expectOne('/api/me');
    expect(req.request.method).toBe('GET');
    expect(req.request.headers.get('Authorization')).toBe('Bearer test-jwt-123');
    req.flush({ username: 'admin', role: 'maker' });
  });

  it('dbPresets() GETs /api/db-presets with the bearer header', () => {
    service.dbPresets().subscribe();
    const req = http.expectOne('/api/db-presets');
    expect(req.request.headers.get('Authorization')).toBe('Bearer test-jwt-123');
    req.flush([]);
  });

  it('requestToken() POSTs /api/token with the bearer header and the payload', () => {
    const payload = {
      username: 'alice',
      db_user: 'app',
      db_ip: '10.0.0.5',
      db_port: '3306',
      db_type: 'mysql' as const,
    };
    service.requestToken(payload).subscribe();
    const req = http.expectOne('/api/token');
    expect(req.request.headers.get('Authorization')).toBe('Bearer test-jwt-123');
    expect(req.request.body).toEqual(payload);
    req.flush({ token: 'db-token', host: 'h', port: 'p', expires_in: 300 });
  });

  it('logout() POSTs /api/logout with the bearer header (the jti denylist needs it)', () => {
    service.logout().subscribe();
    const req = http.expectOne('/api/logout');
    expect(req.request.method).toBe('POST');
    expect(req.request.headers.get('Authorization')).toBe('Bearer test-jwt-123');
    req.flush({ ok: 'true' });
  });

  it('login() POSTs /api/login with NO Authorization header even when a token is stored', () => {
    // A stale token may still sit in the store (e.g. an expired one) when the
    // user hits the login page — the credentials exchange must not carry it.
    service.login('admin', 's3cret').subscribe((res) =>
      expect(res).toEqual({
        token: 'jwt-new',
        username: 'admin',
        role: 'maker',
        expires_in: 28800,
      }),
    );

    const req = http.expectOne('/api/login');
    expect(req.request.method).toBe('POST');
    expect(req.request.headers.has('Authorization')).toBe(false);
    expect(req.request.body).toEqual({ username: 'admin', password: 's3cret' });
    req.flush({ token: 'jwt-new', username: 'admin', role: 'maker', expires_in: 28800 });
  });

  it('sends no Authorization header on authed calls while no token is stored', () => {
    tokens.clear(); // logged out: the interceptor must pass the request through bare
    service.me().subscribe();
    const req = http.expectOne('/api/me');
    expect(req.request.headers.has('Authorization')).toBe(false);
    req.flush({ username: 'admin', role: 'maker' });
  });

  it('killSession posts {session_id, mode:"query"} for a query kill', () => {
    service
      .killSession('sess-9', 'query')
      .subscribe((res) => expect(res).toEqual({ killed: 'queued' }));

    const req = http.expectOne('/api/kill');
    expect(req.request.method).toBe('POST');
    expect(req.request.headers.get('Authorization')).toBe('Bearer test-jwt-123');
    expect(req.request.withCredentials).toBe(false);
    expect(req.request.body).toEqual({ session_id: 'sess-9', mode: 'query' });
    req.flush({ killed: 'queued' });
  });

  it('killSession posts {session_id, mode:"connection"} for a connection kill', () => {
    service.killSession('sess-9', 'connection').subscribe();

    const req = http.expectOne('/api/kill');
    expect(req.request.headers.get('Authorization')).toBe('Bearer test-jwt-123');
    expect(req.request.body).toEqual({ session_id: 'sess-9', mode: 'connection' });
    req.flush({ killed: 'queued' });
  });
});
