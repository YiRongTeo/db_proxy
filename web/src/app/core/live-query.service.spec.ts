import { TestBed } from '@angular/core/testing';
import { QueryEvent } from './api.service';
import { LiveQueryService } from './live-query.service';

/**
 * Fake WebSocket wired through the LiveQueryService.socketCtor seam
 * (rxjs 7.8.2's WebSocketSubject constructs sockets via `new WebSocketCtor(url)`
 * and drives them through onopen/onmessage/onerror/onclose — see
 * node_modules/rxjs/.../dom/WebSocketSubject.js `_connectSocket`).
 */
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];

  readyState = 1; // OPEN — rxjs only sends/closes when open
  binaryType = 'blob';
  onopen: ((ev: Event) => void) | null = null;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onerror: ((ev: Event) => void) | null = null;
  onclose: ((ev: CloseEvent) => void) | null = null;
  sent: string[] = [];

  constructor(public url: string) {
    FakeWebSocket.instances.push(this);
  }

  send(data: string) {
    this.sent.push(data);
  }

  close() {
    this.readyState = 3; // CLOSED
    this.onclose?.({ wasClean: true, code: 1000, reason: '' } as CloseEvent);
  }

  open() {
    this.onopen?.({} as Event);
  }

  emit(event: QueryEvent) {
    this.onmessage?.({ data: JSON.stringify(event) } as MessageEvent);
  }
}

function event(id: string): QueryEvent {
  return {
    id,
    ts: '2026-08-11T08:00:00Z',
    kind: 'query',
    username: 'alice',
    db_user: 'app',
    db_ip: '10.0.0.5',
    db_port: '3306',
    db_type: 'mysql',
    sql: `SELECT ${id}`,
    client_addr: '10.0.0.99',
  };
}

describe('LiveQueryService', () => {
  let service: LiveQueryService;

  beforeEach(() => {
    FakeWebSocket.instances = [];
    TestBed.configureTestingModule({});
    service = TestBed.inject(LiveQueryService);
    service.socketCtor = FakeWebSocket as unknown as new (url: string) => WebSocket;
  });

  it('appends QueryEvents to the ring buffer and caps it at 500', () => {
    service.connect('alice');
    const fake = FakeWebSocket.instances[0];
    expect(fake).toBeDefined();
    expect(service.connected()).toBe(true);
    expect(fake.url).toMatch(/^ws:\/\/.+\/ws\/checker\?channel=alice$/);

    fake.open(); // rxjs wires the destination inside onopen

    for (let i = 1; i <= 505; i++) {
      fake.emit(event(`e${i}`));
    }

    const events = service.events();
    expect(events.length).toBe(500); // ring-buffer cap
    expect(events[0].id).toBe('e6'); // oldest evicted once past the cap
    expect(events[499].id).toBe('e505'); // newest retained, fields intact
    expect(events[499].sql).toBe('SELECT e505');
    expect(events[499].username).toBe('alice');
    expect(service.connected()).toBe(true);
  });

  it('dedupes duplicate event ids (dual-publish on channel=*) and keeps the first copy', () => {
    service.connect('alice');
    const fake = FakeWebSocket.instances[0];
    fake.open();

    const dup = event('dup-1');
    fake.emit(dup);
    fake.emit(dup); // identical id — second copy must be dropped

    const other = event('other-1');
    fake.emit(other); // different id still appends

    const events = service.events();
    expect(events.length).toBe(2);
    expect(events.map((e) => e.id)).toEqual(['dup-1', 'other-1']);
    expect(events[0].sql).toBe('SELECT dup-1'); // first occurrence kept, fields intact
  });

  it('ring cap (500) still holds when duplicates are interleaved: 505 emits, 5 dupes → 500 unique', () => {
    service.connect('alice');
    const fake = FakeWebSocket.instances[0];
    fake.open();

    for (let i = 1; i <= 500; i++) {
      fake.emit(event(`e${i}`));
    }
    for (let i = 1; i <= 5; i++) {
      fake.emit(event(`e${i}`)); // 5 duplicate re-deliveries → 505 total emits
    }

    const events = service.events();
    expect(events.length).toBe(500); // ring-buffer cap still holds
    expect(new Set(events.map((e) => e.id)).size).toBe(500); // no duplicate ids
    expect(events[0].id).toBe('e1'); // nothing evicted — all 500 unique
    expect(events[499].id).toBe('e500');
  });

  it('disconnect() completes the socket (no leak) and reconnect opens a fresh one', () => {
    service.connect('alice');
    const first = FakeWebSocket.instances[0];
    first.open();
    service.disconnect();

    expect(first.readyState).toBe(3); // socket closed via complete()
    expect(service.connected()).toBe(false);

    service.connect('bob');
    const second = FakeWebSocket.instances[1];
    expect(second).not.toBe(first);
    expect(second.url).toMatch(/channel=bob$/);
    expect(service.connected()).toBe(true);
  });
});
