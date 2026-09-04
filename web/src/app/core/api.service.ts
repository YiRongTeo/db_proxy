import { HttpClient, HttpContext } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { AUTH_SKIP } from './auth.interceptor';

/**
 * Wire contract shared with the Control Plane (internal/models, internal/config).
 * JSON field names mirror the Go structs exactly — do not rename.
 */

/** One selectable database target in the Maker portal (internal/config.DBPreset). */
export interface DbPreset {
  name: string;
  db_type: string;
  db_user: string;
  db_ip: string;
  db_port: string;
}

/** Response of POST /api/token (internal/models.TokenResponse). */
export interface TokenResponse {
  token: string;
  host: string;
  port: string;
  expires_in: number; // seconds
}

/** Payload of POST /api/token (internal/models.TokenPayload). */
export interface TokenRequest {
  username: string;
  db_user: string;
  db_ip: string;
  db_port: string;
  db_type: 'mysql' | 'postgres' | 'mssql' | 'oracle';
  ticket_id?: string;
}

/**
 * Response of POST /api/login (Task 6/10): the JWT the SPA must attach as
 * `Authorization: Bearer <token>` on every subsequent call, plus the
 * server-confirmed identity (username may be normalized by the server).
 */
export interface LoginResponse {
  token: string;
  username: string;
  role: string;
  expires_in?: number; // seconds (auth.jwt.ttl_seconds)
}

/** Response of GET /api/me (Task 5.7 route; role added Task 6). */
export interface MeResponse {
  username: string;
  role: string;
}

/**
 * One live data-plane session directory entry (internal/store.SessionInfo —
 * Task 8.4). ThreadID is intentionally not exposed; snake_case EXACT.
 * status (Task 8.11): "pending" = token issued, maker not connected yet;
 * "active" = data plane connected; absent on pre-8.11 records.
 */
export interface SessionInfo {
  session_id: string;
  username: string;
  db_user: string;
  db_type: string;
  db: string;
  started_at: string;
  last_seen: string;
  status?: string; // pending | active (Task 8.11)
}

/**
 * One live query event streamed over /ws/checker
 * (internal/models.QueryEvent — ts is RFC3339 as marshalled by Go's time.Time).
 */
export interface QueryEvent {
  id: string;
  ts: string;
  kind: string; // query | prepare | execute | use
  username: string;
  ticket_id?: string;
  db_user: string;
  db_ip: string;
  db_port: string;
  db_type: string; // mysql | postgres | mssql | oracle
  sql: string;
  client_addr: string;
  // Phase 6 enhancement fields (internal/models.QueryEvent — omitempty, may be absent).
  stmt_type?: string; // select | insert | update | delete | other
  session_id?: string; // data-plane session id (kill target; NOT the token)
  status?: string; // ok | error (from the DB response)
  error?: string;
  columns?: string[];
  rows?: string[][];
  truncated?: boolean;
  // Phase 8 enhancement fields (internal/models.QueryEvent — omitempty, may be absent).
  action?: string; // issued|started|ended — session lifecycle events (kind=session; issued = Task 8.11)
  db?: string; // client-requested target database
}

/**
 * Thin typed wrapper over the Control Plane REST API.
 * Auth (Task 10): every request carries `Authorization: Bearer <jwt>` via the
 * registered authInterceptor (TokenStore-backed), so no per-call options are
 * needed. POST /api/login is the one exception — it EXCHANGES credentials for
 * the token, so it opts out of the header via the AUTH_SKIP request context.
 * The cookie era (`zt_session` / withCredentials) is gone.
 */
@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(private http: HttpClient) {}

  /** POST /api/login — credentials for a JWT. No auth header (AUTH_SKIP). */
  login(username: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(
      '/api/login',
      { username, password },
      { context: new HttpContext().set(AUTH_SKIP, true) },
    );
  }

  /**
   * POST /api/logout — the bearer IS required here: the backend denylists the
   * presented token's jti (Task 6), so the interceptor attaches it normally.
   */
  logout(): Observable<unknown> {
    return this.http.post('/api/logout', null);
  }

  /** GET /api/me — validates the bearer token and returns {username, role} (Task 5.7/6). */
  me(): Observable<MeResponse> {
    return this.http.get<MeResponse>('/api/me');
  }

  dbPresets(): Observable<DbPreset[]> {
    return this.http.get<DbPreset[]>('/api/db-presets');
  }

  requestToken(payload: TokenRequest): Observable<TokenResponse> {
    return this.http.post<TokenResponse>('/api/token', payload);
  }

  /** GET /api/sessions — live data-plane session directory (Task 8.4). */
  sessions(): Observable<SessionInfo[]> {
    return this.http.get<SessionInfo[]>('/api/sessions');
  }

  /**
   * POST /api/kill — queue a data-plane session kill (202 when accepted).
   * mode selects the kill scope (Task 8.3): 'query' aborts the in-flight
   * query only; 'connection' terminates the whole backend session. The 202
   * body is unused by the UI (Task 9.11: no KillResponse type needed).
   */
  killSession(sessionId: string, mode: 'query' | 'connection'): Observable<unknown> {
    return this.http.post('/api/kill', { session_id: sessionId, mode });
  }
}
