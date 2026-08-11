import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';

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
  db_type: 'mysql' | 'postgres';
  ticket_id?: string;
}

/** Response of POST /api/login. */
export interface LoginResponse {
  username: string;
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
  db_type: string; // mysql | postgres
  sql: string;
  client_addr: string;
}

/**
 * Thin typed wrapper over the Control Plane REST API.
 * Session is carried by the HttpOnly `zt_session` cookie (SameSite=Lax,
 * same-origin), so all calls use relative URLs with credentials included.
 */
@Injectable({ providedIn: 'root' })
export class ApiService {
  constructor(private http: HttpClient) {}

  login(username: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(
      '/api/login',
      { username, password },
      { withCredentials: true },
    );
  }

  logout(): Observable<unknown> {
    return this.http.post('/api/logout', null, { withCredentials: true });
  }

  /** GET /api/me — validates the session cookie and returns the session user (Task 5.7). */
  me(): Observable<LoginResponse> {
    return this.http.get<LoginResponse>('/api/me', { withCredentials: true });
  }

  dbPresets(): Observable<DbPreset[]> {
    return this.http.get<DbPreset[]>('/api/db-presets', { withCredentials: true });
  }

  requestToken(payload: TokenRequest): Observable<TokenResponse> {
    return this.http.post<TokenResponse>('/api/token', payload, { withCredentials: true });
  }
}
