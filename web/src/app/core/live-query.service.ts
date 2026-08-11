import { Injectable, OnDestroy, signal } from '@angular/core';
import { webSocket, WebSocketSubject, WebSocketSubjectConfig } from 'rxjs/webSocket';
import { QueryEvent } from './api.service';

/**
 * Checker-dashboard live feed. Monitor-only: connects to
 * ws://<origin>/ws/checker?channel=<channel> (HttpOnly session cookie is sent
 * automatically for same-origin WebSockets) and buffers decoded QueryEvents
 * in a 500-entry ring buffer.
 *
 * NOTE (testability): rxjs 7.8.2's WebSocketSubject honors the `WebSocketCtor`
 * config key (it constructs the socket with `new WebSocketCtor(url)`); the
 * `webSocketFactory` config key does not exist in this version. The
 * `socketCtor` field below is the test seam wired through `WebSocketCtor`.
 */
@Injectable({ providedIn: 'root' })
export class LiveQueryService implements OnDestroy {
  private socket: WebSocketSubject<QueryEvent> | null = null;
  readonly events = signal<QueryEvent[]>([]);
  readonly connected = signal(false);
  private limit = 500; // ring-buffer cap

  /** Test seam: custom WebSocket constructor (defaults to the global WebSocket). */
  socketCtor?: new (url: string) => WebSocket;

  connect(channel: string) {
    this.disconnect();
    const url = `${location.origin.replace(/^http/, 'ws')}/ws/checker?channel=${encodeURIComponent(channel)}`;
    // rxjs 7.8.2 ignores withCredentials at runtime (cookies ride along on
    // same-origin WebSockets automatically) and its type omits the key; keep it
    // per the service contract and widen the type so the intent is explicit.
    const config: WebSocketSubjectConfig<QueryEvent> & { withCredentials: boolean } = { url, withCredentials: true };
    if (this.socketCtor) {
      config.WebSocketCtor = this.socketCtor;
    }
    this.socket = webSocket<QueryEvent>(config);
    this.socket.subscribe({
      next: (e) => this.events.update((a) => [...a.slice(-this.limit + 1), e]),
      error: () => this.connected.set(false),
      complete: () => this.connected.set(false),
    });
    this.connected.set(true);
  }

  disconnect() {
    this.socket?.complete(); // spec: complete on navigation away (no leaks)
    this.socket = null;
  }

  ngOnDestroy() { this.disconnect(); }
}
