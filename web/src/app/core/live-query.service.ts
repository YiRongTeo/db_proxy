import { Injectable, OnDestroy, signal } from '@angular/core';
import { webSocket, WebSocketSubject, WebSocketSubjectConfig } from 'rxjs/webSocket';
import { QueryEvent } from './api.service';
import { TokenStore } from './token-store.service';

/**
 * Checker-dashboard live feed. Monitor-only: connects to
 * ws://<origin>/ws/checker?channel=<channel>&access_token=<jwt> (Task 11:
 * browsers cannot set WebSocket handshake headers, so the bearer JWT held by
 * the TokenStore rides as the access_token query param — the Task 9 backend
 * accepts it as a fallback after the Authorization header) and buffers
 * decoded QueryEvents in a 500-entry ring buffer. With no stored token the
 * feed stays disconnected instead of dialing a handshake the server would
 * reject as anonymous.
 *
 * NOTE (testability): rxjs 7.8.2's WebSocketSubject honors the `WebSocketCtor`
 * config key (it constructs the socket with `new WebSocketCtor(url)`); the
 * `webSocketFactory` config key does not exist in this version. The
 * `socketCtor` field below is the test seam wired through `WebSocketCtor`.
 *
 * Task 8.15 seam: `connectState` is the ACCURATE socket state, driven by real
 * socket events (openObserver / error / complete), never by optimism. The
 * legacy `connected` signal keeps its documented optimistic semantics
 * (true right after connect()) for tests and any remaining consumers — the
 * one exception since Task 11 is connect() with no stored JWT, which returns
 * early (nothing dialed) and leaves `connected` false. The
 * checker toolbar is driven by `connectState` (Task 9.11), and `connected`
 * is explicitly cleared in disconnect() — previously it could only flip
 * false via the socket's error/complete callbacks, which rxjs 7.8 never fires
 * for a socket closed before it opened (AnonymousSubject.complete() is a
 * no-op while the destination is still the pre-open ReplaySubject), leaving
 * the tag stale "live" after Stop during the handshake. A generation counter
 * additionally guards every callback so a LATE error/complete/open from a
 * superseded socket (channel switch) can never clobber the new socket's state.
 */
@Injectable({ providedIn: 'root' })
export class LiveQueryService implements OnDestroy {
  constructor(private readonly tokens: TokenStore) {}

  private socket: WebSocketSubject<QueryEvent> | null = null;

  /** Bumped on every connect/disconnect; callbacks from older sockets are ignored. */
  private generation = 0;

  readonly events = signal<QueryEvent[]>([]);

  /** Legacy optimistic socket flag (true right after connect(), see class doc). */
  readonly connected = signal(false);

  /** Real socket state (Task 8.15): driven by socket events, not connect() optimism. */
  readonly connectState = signal<'closed' | 'open' | 'error'>('closed');

  /**
   * Close code + reason of the last socket close (2026-08-17 separation of
   * duties): captured from the raw CloseEvent via closeObserver so the UI
   * can surface policy-violation rejections (1008 — e.g. a maker trying to
   * watch their own session) distinctly from a plain disconnect. Cleared on
   * every connect/disconnect.
   */
  readonly lastClose = signal<{ code: number; reason: string } | null>(null);

  private limit = 500; // ring-buffer cap

  /** Test seam: custom WebSocket constructor (defaults to the global WebSocket). */
  socketCtor?: new (url: string) => WebSocket;

  connect(channel: string) {
    this.disconnect();
    // Task 11: the Task 9 backend requires an authenticated WS (requireJWTWS
    // — Authorization header first, access_token query fallback), and
    // browsers cannot set WebSocket handshake headers, so the bearer JWT
    // from the TokenStore rides on the URL. No token → stay in the
    // disconnected state (disconnect() above already reset the signals)
    // instead of dialing a feed the server would reject.
    const token = this.tokens.get();
    if (!token) {
      this.connected.set(false);
      this.connectState.set('closed');
      return;
    }
    const gen = ++this.generation;
    const url =
      `${location.origin.replace(/^http/, 'ws')}/ws/checker` +
      `?channel=${encodeURIComponent(channel)}&access_token=${encodeURIComponent(token)}`;
    // Task 9.11: no withCredentials key — rxjs 7.8.2 ignores it at runtime.
    // The cookie rationale is gone since Task 11: the WS is authenticated by
    // the access_token query param above, not by a session cookie.
    const config: WebSocketSubjectConfig<QueryEvent> = {
      url,
      // The real "socket opened" notification (rxjs fires openObserver.next
      // from its onopen handler). The subscription's next() only sees messages,
      // so without this the service could never tell open from connecting.
      openObserver: {
        next: () => {
          if (gen !== this.generation) return; // superseded socket — ignore
          this.connectState.set('open');
        },
      },
      // Raw CloseEvent capture (2026-08-17): the subscription's error path
      // loses the close code in rxjs 7.8, so the closeObserver is the
      // version-safe way to surface policy-violation rejections (1008).
      closeObserver: {
        next: (e: CloseEvent) => {
          if (gen !== this.generation) return; // superseded socket — ignore
          this.lastClose.set({ code: e.code, reason: e.reason ?? '' });
        },
      },
    };
    if (this.socketCtor) {
      config.WebSocketCtor = this.socketCtor;
    }
    this.socket = webSocket<QueryEvent>(config);
    this.socket.subscribe({
      // Dedupe by event.id: the data plane dual-publishes each QueryEvent
      // (queries:<username> AND queries:ticket:<ticket_id>), so channel=*
      // (pattern `queries:*`) delivers every event twice with identical ids.
      // Keep the FIRST occurrence (the copies are identical); the ring cap
      // still applies below. Linear scan is fine — the buffer is ≤500.
      next: (e) =>
        this.events.update((a) => {
          if (a.some((x) => x.id === e.id)) return a;
          return [...a.slice(-this.limit + 1), e];
        }),
      error: () => {
        if (gen !== this.generation) return;
        this.connected.set(false);
        this.connectState.set('error');
      },
      complete: () => {
        if (gen !== this.generation) return;
        this.connected.set(false);
        this.connectState.set('closed');
      },
    });
    this.connected.set(true);
  }

  disconnect() {
    this.generation++; // supersede any in-flight callbacks from the old socket
    const socket = this.socket;
    this.socket = null;
    socket?.complete(); // spec: complete on navigation away (no leaks)
    // Explicit state flip — the socket's complete/error callbacks may never
    // fire (pre-open close is a no-op in rxjs 7.8; see class doc), so the
    // signals must not depend on them for the disconnect path.
    this.connected.set(false);
    this.connectState.set('closed');
    this.lastClose.set(null);
  }

  ngOnDestroy() { this.disconnect(); }
}
