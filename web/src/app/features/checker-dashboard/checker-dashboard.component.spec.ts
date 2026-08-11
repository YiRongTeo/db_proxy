import { TestBed } from '@angular/core/testing';
import { QueryEvent } from '../../core/api.service';
import { LiveQueryService } from '../../core/live-query.service';
import { CheckerDashboardComponent } from './checker-dashboard.component';

/** Fake WebSocket wired through the LiveQueryService.socketCtor seam (see live-query.service.spec.ts). */
class FakeWebSocket {
  static instances: FakeWebSocket[] = [];

  readyState = 1;
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
    this.readyState = 3;
    this.onclose?.({ wasClean: true, code: 1000, reason: '' } as CloseEvent);
  }

  open() {
    this.onopen?.({} as Event);
  }

  emit(event: QueryEvent) {
    this.onmessage?.({ data: JSON.stringify(event) } as MessageEvent);
  }
}

function event(overrides: Partial<QueryEvent> = {}): QueryEvent {
  return {
    id: 'evt-1',
    ts: '2026-08-11T08:00:00Z',
    kind: 'query',
    username: 'alice',
    db_user: 'app',
    db_ip: '10.0.0.5',
    db_port: '3306',
    db_type: 'mysql',
    sql: 'SELECT 1',
    client_addr: '10.0.0.99',
    ...overrides,
  };
}

describe('CheckerDashboardComponent', () => {
  let service: LiveQueryService;

  beforeEach(() => {
    FakeWebSocket.instances = [];
    TestBed.configureTestingModule({
      imports: [CheckerDashboardComponent],
      providers: [LiveQueryService],
    });
    service = TestBed.inject(LiveQueryService);
    service.socketCtor = FakeWebSocket as unknown as new (url: string) => WebSocket;
  });

  it('auto-connects to the default * channel on init and shows the live tag', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();

    const fake = FakeWebSocket.instances[0];
    expect(fake).toBeDefined();
    expect(fake.url).toMatch(/\/ws\/checker\?channel=\*$/); // '*' is not escaped by encodeURIComponent
    expect(service.connected()).toBe(true);

    const tag = fixture.nativeElement.querySelector('.ant-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toContain('live');
  });

  it('renders one row per event with kind tag, target and monospace SQL', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    const fake = FakeWebSocket.instances[0];
    fake.open();

    fake.emit(event({ kind: 'execute', ticket_id: 'OPS-1234', sql: 'SELECT * FROM users;\n-- multi-line' }));
    fake.emit(event({ id: 'evt-2', kind: 'prepare', username: 'bob', db_type: 'postgres', sql: 'PREPARE p AS SELECT 2' }));
    await fixture.whenStable();
    fixture.detectChanges();

    const rows = fixture.nativeElement.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);

    const first = rows[0] as HTMLElement;
    expect(first.textContent).toContain('execute');
    expect(first.textContent).toContain('OPS-1234');
    expect(first.textContent).toContain('app@10.0.0.5:3306');
    expect(first.querySelector('.cell-sql')?.textContent).toContain('SELECT * FROM users;');

    const kinds = fixture.nativeElement.querySelectorAll('tbody .ant-tag');
    expect((kinds[0] as HTMLElement).textContent?.trim()).toBe('execute');
    expect((kinds[1] as HTMLElement).textContent?.trim()).toBe('prepare');
  });

  it('Stop disconnects and flips the status tag to disconnected', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open(); // rxjs only closes fully-opened sockets
    expect(service.connected()).toBe(true);

    fixture.componentInstance.stop();
    fixture.detectChanges();

    expect(service.connected()).toBe(false);
    const tag = fixture.nativeElement.querySelector('.ant-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toContain('disconnected');
  });

  it('reconnecting from the form channel switches the feed and resets the buffer', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    fixture.componentInstance.channel.set('bob');
    fixture.componentInstance.connect();
    fixture.detectChanges();

    const second = FakeWebSocket.instances[1];
    expect(second).toBeDefined();
    expect(second.url).toMatch(/channel=bob$/);
    expect(service.events().length).toBe(0); // fresh ring buffer
  });

  it('destroys without leaking the socket', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    const fake = FakeWebSocket.instances[0];
    fake.open();

    fixture.destroy();

    expect(fake.readyState).toBe(3); // socket closed via disconnect()
    expect(service.connected()).toBe(false);
  });

  it('maps kinds to tag colors and formats targets', () => {
    const comp = TestBed.createComponent(CheckerDashboardComponent).componentInstance;
    expect(comp.kindColor('query')).toBe('blue');
    expect(comp.kindColor('prepare')).toBe('purple');
    expect(comp.kindColor('execute')).toBe('orange');
    expect(comp.kindColor('use')).toBe('cyan');
    expect(comp.kindColor('unknown')).toBe('default');
    expect(comp.target(event())).toBe('app@10.0.0.5:3306');
  });
});
