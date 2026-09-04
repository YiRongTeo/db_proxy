import { Component, signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { of, throwError } from 'rxjs';
import { ApiService, QueryEvent, SessionInfo } from '../../core/api.service';
import { AuthService } from '../../core/auth.service';
import { LiveQueryService } from '../../core/live-query.service';
import { NzMessageService } from 'ng-zorro-antd/message';
import { TokenStore } from '../../core/token-store.service';
import { CheckerDashboardComponent } from './checker-dashboard.component';

/** JWT seeded into the real TokenStore so LiveQueryService dials (Task 11). */
const TEST_JWT = 'jwt-token-123';

/** Landing route for the 401 → /login navigation assertions (Task 9.11). */
@Component({ template: '', standalone: true })
class StubCmp {}

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

  fail() {
    this.onerror?.({} as Event);
  }

  /** Server-side rejection close (2026-08-17): 1008 policy violation by default. */
  reject(code = 1008, reason = '') {
    this.readyState = 3;
    this.onclose?.({ wasClean: false, code, reason } as CloseEvent);
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

/** One session-directory record as GET /api/sessions returns it (Task 8.4). */
function session(overrides: Partial<SessionInfo> = {}): SessionInfo {
  return {
    session_id: 'sess-abc123',
    username: 'alice',
    db_user: 'app',
    db_type: 'mysql',
    db: 'appdb',
    started_at: '2026-08-11T08:00:00Z',
    last_seen: '2026-08-11T08:05:00Z',
    ...overrides,
  };
}

/** A kind=session lifecycle event as published by the control/data planes (Task 8.2/8.11). */
function lifecycle(
  action: 'started' | 'issued' | 'ended',
  sid: string,
  overrides: Partial<QueryEvent> = {},
): QueryEvent {
  return {
    id: `life-${action}-${sid}`,
    // Task 9.11: issued events feed the pending-override started_at, which is
    // age-pruned against the token TTL — so lifecycle ts must be "now".
    ts: new Date().toISOString(),
    kind: 'session',
    action,
    username: 'alice',
    db_user: 'app',
    db_ip: '', // lifecycle events carry no target address — the UI must cope
    db_port: '',
    db_type: 'mysql',
    db: 'appdb',
    sql: '',
    client_addr: '10.0.0.99',
    session_id: sid,
    ...overrides,
  };
}

/** Find a row's button by its visible text (view/kill query/kill connection). */
function buttonByText(row: HTMLElement, text: string): HTMLButtonElement {
  const btn = Array.from(row.querySelectorAll('button')).find(
    (b) => b.textContent?.trim() === text,
  );
  if (!btn) throw new Error(`no button "${text}" in row`);
  return btn as HTMLButtonElement;
}

/** Open the named row's nz-popconfirm and click its OK (confirm) button. */
async function confirmKill(fixture: ComponentFixture<CheckerDashboardComponent>, label: string) {
  const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
  const trigger = Array.from(row.querySelectorAll('button[nz-popconfirm]')).find(
    (b) => b.textContent?.trim() === label,
  ) as HTMLButtonElement;
  trigger.click();
  fixture.detectChanges();
  await fixture.whenStable();
  const ok = document.querySelectorAll('.ant-popover-buttons button')[1] as HTMLButtonElement;
  ok.click();
  await fixture.whenStable();
  fixture.detectChanges();
}

/** Open the toolbar kill-connection popconfirm and click its OK (confirm) button. */
async function confirmToolbarKill(fixture: ComponentFixture<CheckerDashboardComponent>) {
  const trigger = fixture.nativeElement.querySelector('.kill-connection-btn') as HTMLButtonElement;
  trigger.click();
  fixture.detectChanges();
  await fixture.whenStable();
  const ok = document.querySelectorAll('.ant-popover-buttons button')[1] as HTMLButtonElement;
  ok.click();
  await fixture.whenStable();
  fixture.detectChanges();
}

/** Open the session selector dropdown and return its option elements. */
async function openSelectorOptions(
  fixture: ComponentFixture<CheckerDashboardComponent>,
): Promise<HTMLElement[]> {
  const selector = fixture.nativeElement.querySelector(
    '.session-select .ant-select-selector',
  ) as HTMLElement;
  selector.click();
  fixture.detectChanges();
  await fixture.whenStable();
  // The CDK overlay + virtual-scroll option container render on a macrotask
  // tick — whenStable alone is not enough for the items to appear.
  await new Promise((r) => setTimeout(r, 20));
  return Array.from(document.querySelectorAll('.ant-select-item-option')) as HTMLElement[];
}

/** Open the session selector dropdown and return the visible option labels. */
async function selectorOptions(fixture: ComponentFixture<CheckerDashboardComponent>): Promise<string[]> {
  const options = await openSelectorOptions(fixture);
  return options.map((o) => o.textContent?.trim() ?? '');
}

/** Wait out the lifecycle-driven directory-refresh debounce (Task 9.11). */
function flushRefresh(): Promise<void> {
  return new Promise((r) => setTimeout(r, 300));
}

describe('CheckerDashboardComponent', () => {
  let service: LiveQueryService;
  let api: {
    killSession: ReturnType<typeof vi.fn>;
    sessions: ReturnType<typeof vi.fn>;
  };
  let auth: {
    user: ReturnType<typeof signal>;
    logout: ReturnType<typeof vi.fn>;
  };
  let message: { success: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    FakeWebSocket.instances = [];
    api = {
      killSession: vi.fn(() => of({ killed: 'queued' })),
      sessions: vi.fn(() => of([])),
    };
    auth = {
      user: signal<string | null>(null),
      logout: vi.fn(() => of(null)),
    };
    message = { success: vi.fn(), error: vi.fn() };
    TestBed.configureTestingModule({
      imports: [CheckerDashboardComponent],
      providers: [
        provideRouter([{ path: 'login', component: StubCmp }]),
        LiveQueryService,
        { provide: ApiService, useValue: api },
        { provide: AuthService, useValue: auth },
        { provide: NzMessageService, useValue: message },
      ],
    });
    service = TestBed.inject(LiveQueryService);
    service.socketCtor = FakeWebSocket as unknown as new (url: string) => WebSocket;
    // Task 11: LiveQueryService refuses to dial without a stored JWT, so
    // every dashboard spec seeds the real TokenStore before the component
    // auto-connects on init.
    TestBed.inject(TokenStore).set(TEST_JWT);
  });

  it('auto-connects to the default * channel on init and shows the live-feed tag once open', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();

    const fake = FakeWebSocket.instances[0];
    expect(fake).toBeDefined();
    expect(fake.url).toMatch(/\/ws\/checker\?channel=\*&access_token=jwt-token-123$/); // '*' is not escaped by encodeURIComponent
    expect(service.connected()).toBe(true); // legacy optimistic flag flips immediately

    // The status tag is DERIVED from the REAL socket state (Task 8.15): it
    // stays disconnected until the socket actually opens — no more stale
    // "live" while the feed is not up.
    expect(service.connectState()).toBe('closed');
    fake.open();
    fixture.detectChanges();

    const tag = fixture.nativeElement.querySelector('.status-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toBe('live feed');
    expect(service.connectState()).toBe('open');
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
    const tag = fixture.nativeElement.querySelector('.status-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toBe('disconnected');
  });

  it('Stop during the handshake still flips the status to disconnected (no stale live)', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    // Socket created but never opened — pre-8.15 rxjs 7.8 complete() is a
    // no-op here, so the socket's complete/error callbacks never fired and
    // `connected` stayed true → the tag read "live" with no feed at all.
    expect(FakeWebSocket.instances[0]).toBeDefined();
    expect(service.connected()).toBe(true); // legacy optimistic flag (the bug's fuel)

    fixture.componentInstance.stop();
    fixture.detectChanges();

    expect(service.connected()).toBe(false);
    expect(service.connectState()).toBe('closed');
    const tag = fixture.nativeElement.querySelector('.status-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toBe('disconnected');
  });

  it('surfaces a 1008 policy-violation rejection (separation of duties) in the banner', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.ws-error-alert')).toBeNull();

    // The server refuses the watch: maker trying to watch their own session
    // → policy-violation close with the server's reason.
    FakeWebSocket.instances[0].reject(1008, 'cannot watch this session');
    fixture.detectChanges();

    expect(service.connectState()).toBe('error');
    const banner = fixture.nativeElement.querySelector('.ws-error-alert') as HTMLElement;
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('Feed rejected: cannot watch this session');
    expect(banner.textContent).toContain('cannot be watched by its maker');
  });

  it('shows the generic connection-lost banner for a non-1008 close', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();
    FakeWebSocket.instances[0].reject(1006, '');
    fixture.detectChanges();

    const banner = fixture.nativeElement.querySelector('.ws-error-alert') as HTMLElement;
    expect(banner).not.toBeNull();
    expect(banner.textContent).toContain('Live feed connection lost');
    expect(banner.textContent).not.toContain('Feed rejected');
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
    expect(second.url).toMatch(/channel=bob&access_token=jwt-token-123$/);
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

  // ---- Task 6.7: stmt_type tags -------------------------------------------------

  it('maps all five stmt types to tag colors (case-insensitive, unknown → default)', () => {
    const comp = TestBed.createComponent(CheckerDashboardComponent).componentInstance;
    expect(comp.stmtColor('select')).toBe('blue');
    expect(comp.stmtColor('insert')).toBe('green');
    expect(comp.stmtColor('update')).toBe('orange');
    expect(comp.stmtColor('delete')).toBe('red');
    expect(comp.stmtColor('other')).toBe('default');
    expect(comp.stmtColor('unknown')).toBe('default');
    expect(comp.stmtColor(undefined)).toBe('default');
    expect(comp.stmtColor('SELECT')).toBe('blue'); // tolerate upstream casing
  });

  it('renders a stmt_type tag beside the wire kind tag with the mapped color', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event({ stmt_type: 'insert' }));
    await fixture.whenStable();
    fixture.detectChanges();

    const kinds = fixture.nativeElement.querySelector('tbody tr .cell-kinds') as HTMLElement;
    const tags = kinds.querySelectorAll('nz-tag');
    expect(tags.length).toBe(2);
    expect((tags[0] as HTMLElement).textContent?.trim()).toBe('query'); // wire kind keeps its own color
    expect((tags[1] as HTMLElement).textContent?.trim()).toBe('insert');
    expect((tags[1] as HTMLElement).classList.contains('ant-tag-green')).toBe(true);
  });

  // ---- Task 6.7: status column --------------------------------------------------

  it('shows ok/error status tags and the error message as tooltip title', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    const fake = FakeWebSocket.instances[0];
    fake.open();

    fake.emit(event({ id: 'evt-ok', status: 'ok' }));
    fake.emit(event({ id: 'evt-err', status: 'error', error: 'relation "nope" does not exist' }));
    fake.emit(event({ id: 'evt-none' })); // no status field
    await fixture.whenStable();
    fixture.detectChanges();

    const rows = fixture.nativeElement.querySelectorAll('tbody tr');
    const okTag = (rows[0] as HTMLElement).querySelector('.ant-tag-success');
    expect(okTag?.textContent?.trim()).toBe('ok');

    const errRow = rows[1] as HTMLElement;
    const errTag = errRow.querySelector('.ant-tag-error') as HTMLElement;
    expect(errTag?.textContent?.trim()).toBe('error');
    // Task 9.11: the duplicated attr.title is gone — the nz-tooltip owns the
    // message (no redundant native title attribute).
    expect(errTag?.getAttribute('title')).toBeNull();
    expect(errTag?.hasAttribute('nz-tooltip')).toBe(true);

    const noneRow = rows[2] as HTMLElement;
    expect(noneRow.querySelector('.ant-tag-success')).toBeNull();
    expect(noneRow.querySelector('.ant-tag-error')).toBeNull();
  });

  // ---- Task 6.7: output table ---------------------------------------------------

  it('disables the view button when the event has neither columns nor rows', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event());
    await fixture.whenStable();
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    expect(buttonByText(row, 'view').disabled).toBe(true);
  });

  it('expands a READ-ONLY output table with event columns and cells (no inputs anywhere)', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(
      event({ columns: ['id', 'name'], rows: [['1', 'alpha'], ['2', 'bravo']] }),
    );
    await fixture.whenStable();
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    const view = buttonByText(row, 'view');
    expect(view.disabled).toBe(false);
    view.click();
    fixture.detectChanges();
    await fixture.whenStable();

    const out = fixture.nativeElement.querySelector('tr.output-row') as HTMLElement;
    expect(out).not.toBeNull();
    const table = out.querySelector('.output-table') as HTMLElement;
    const headers = Array.from(table.querySelectorAll('thead th')).map((th) => th.textContent?.trim());
    expect(headers).toEqual(['id', 'name']);
    const cells = Array.from(table.querySelectorAll('tbody td')).map((td) => td.textContent?.trim());
    expect(cells).toEqual(['1', 'alpha', '2', 'bravo']);
    // Read-only by construction: no editable elements inside the expanded area.
    expect(out.querySelectorAll('input, textarea, select').length).toBe(0);
  });

  it('shows the truncated warning alert inside the expanded output', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(
      event({ columns: ['id'], rows: [['1']], truncated: true }),
    );
    await fixture.whenStable();
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    buttonByText(row, 'view').click();
    fixture.detectChanges();
    await fixture.whenStable();

    const alert = fixture.nativeElement.querySelector('tr.output-row .ant-alert') as HTMLElement;
    expect(alert).not.toBeNull();
    expect(alert.textContent).toContain('results truncated');
  });

  it('falls back to a single value column when columns are empty (PG extended protocol)', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event({ columns: [], rows: [['alpha'], ['beta']] }));
    await fixture.whenStable();
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    const view = buttonByText(row, 'view');
    expect(view.disabled).toBe(false); // rows present → still viewable
    view.click();
    fixture.detectChanges();
    await fixture.whenStable();

    const out = fixture.nativeElement.querySelector('tr.output-row') as HTMLElement;
    const table = out.querySelector('.output-table') as HTMLElement;
    const headers = Array.from(table.querySelectorAll('thead th')).map((th) => th.textContent?.trim());
    expect(headers).toEqual(['value']);
    const cells = Array.from(table.querySelectorAll('tbody td')).map((td) => td.textContent?.trim());
    expect(cells).toEqual(['alpha', 'beta']);
  });

  it('falls back to index headers when columns are empty and rows have multiple fields', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event({ columns: [], rows: [['a', 'b'], ['c', 'd']] }));
    await fixture.whenStable();
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    buttonByText(row, 'view').click();
    fixture.detectChanges();
    await fixture.whenStable();

    const out = fixture.nativeElement.querySelector('tr.output-row') as HTMLElement;
    const table = out.querySelector('.output-table') as HTMLElement;
    const headers = Array.from(table.querySelectorAll('thead th')).map((th) => th.textContent?.trim());
    expect(headers).toEqual(['0', '1']);
    const cells = Array.from(table.querySelectorAll('tbody td')).map((td) => td.textContent?.trim());
    expect(cells).toEqual(['a', 'b', 'c', 'd']);
  });

  // ---- Task 6.7/8.5: kill column --------------------------------------------------

  it('hides the row kill button when the event has no session_id (toolbar button still disabled in live-all)', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event());
    await fixture.whenStable();
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    expect(row.querySelector('button[nz-popconfirm]')).toBeNull();
    expect(row.textContent).not.toContain('kill query');
    const toolbar = fixture.nativeElement.querySelector('.kill-connection-btn') as HTMLButtonElement;
    expect(toolbar).not.toBeNull();
    expect(toolbar.disabled).toBe(true);
  });

  it('renders only a kill-query button per row; query kill calls killSession(sid, "query") and keeps the row live', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event({ session_id: 'sess-9' }));
    await fixture.whenStable();
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    const queryBtn = buttonByText(row, 'kill query');
    expect(queryBtn).toBeDefined();
    // Per-row connection kill is gone — the toolbar button owns it (Task 8.15).
    expect(row.textContent).not.toContain('kill connection');
    expect(api.killSession).not.toHaveBeenCalled();

    await confirmKill(fixture, 'kill query');

    expect(api.killSession).toHaveBeenCalledTimes(1);
    expect(api.killSession).toHaveBeenCalledWith('sess-9', 'query');
    expect(message.success).toHaveBeenCalledWith(expect.stringContaining('query kill dispatched'));

    // Query kill leaves the row live: no killed tag, the button stays enabled.
    const after = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    expect(after.textContent).not.toContain('killed');
    expect(buttonByText(after, 'kill query').disabled).toBe(false);
  });

  it('toolbar kill connection acts on the SELECTED session and marks its rows killed on 202', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();
    const fake = FakeWebSocket.instances[1];
    expect(fake).toBeDefined();
    fake.open();

    fake.emit(event({ id: 'evt-a', session_id: 'sess-abc123', sql: 'SELECT 1' }));
    fake.emit(event({ id: 'evt-b', session_id: 'sess-abc123', sql: 'SELECT 2' }));
    await fixture.whenStable();
    fixture.detectChanges();

    await confirmToolbarKill(fixture);

    expect(api.killSession).toHaveBeenCalledTimes(1);
    expect(api.killSession).toHaveBeenCalledWith('sess-abc123', 'connection');
    expect(message.success).toHaveBeenCalledWith(expect.stringContaining('sess-abc123'));

    // Every buffered row of the killed session shows the red killed state.
    const rows = fixture.nativeElement.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
    for (const row of Array.from(rows)) {
      const el = row as HTMLElement;
      const killedTag = Array.from(el.querySelectorAll('nz-tag')).find(
        (t) => t.textContent?.trim() === 'killed',
      );
      expect(killedTag).toBeDefined();
      expect((killedTag as HTMLElement).classList.contains('ant-tag-red')).toBe(true);
      expect(el.querySelector('button[nz-popconfirm]')).toBeNull();
    }
  });

  it('toolbar kill failure shows an error message and leaves the session killable', async () => {
    api.killSession = vi.fn(() => throwError(() => ({ status: 502 })));
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[1].open();
    FakeWebSocket.instances[1].emit(event({ id: 'evt-1', session_id: 'sess-abc123' }));
    await fixture.whenStable();
    fixture.detectChanges();

    await confirmToolbarKill(fixture);

    expect(api.killSession).toHaveBeenCalledWith('sess-abc123', 'connection');
    expect(message.error).toHaveBeenCalledWith(expect.stringContaining('sess-abc123'));
    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    expect(row.textContent).not.toContain('killed');
    const btn = fixture.nativeElement.querySelector('.kill-connection-btn') as HTMLButtonElement;
    expect(btn.disabled).toBe(false); // still killable
  });

  // ---- Task 8.5: session selector -------------------------------------------------

  it('renders the API sessions in the selector plus the live (all) option', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    expect(api.sessions).toHaveBeenCalledTimes(1); // directory pulled on init
    expect(fixture.componentInstance.selectedSession()).toBe('*');
    expect(fixture.componentInstance.sessions().length).toBe(1);

    const labels = await selectorOptions(fixture);
    expect(labels[0]).toBe('live (all)');
    expect(labels).toContain('alice · app · appdb · sess-abc123');
  });

  it('shows only the live (all) option when the session directory is empty', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    const labels = await selectorOptions(fixture);
    expect(labels).toEqual(['live (all)']);
  });

  it('truncates long session ids in the option label (~12 chars)', async () => {
    api.sessions = vi.fn(() => of([session({ session_id: 'sess-0123456789abcdef' })]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    const labels = await selectorOptions(fixture);
    expect(labels).toContain('alice · app · appdb · sess-0123456…'); // 12-char sid + ellipsis
    expect(fixture.componentInstance.shortenSid('sess-0123456789abcdef')).toBe('sess-0123456…');
  });

  it('adds a session option on a started lifecycle event and removes it on ended', async () => {
    let directory: SessionInfo[] = [];
    api.sessions = vi.fn(() => of(directory));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    const fake = FakeWebSocket.instances[0];
    fake.open();

    directory = [session()];
    fake.emit(lifecycle('started', 'sess-abc123'));
    await flushRefresh(); // Task 9.11: lifecycle re-pulls are debounced
    fixture.detectChanges();
    expect(fixture.componentInstance.sessions().length).toBe(1);
    let labels = await selectorOptions(fixture);
    expect(labels).toContain('alice · app · appdb · sess-abc123');

    // Close the dropdown (a click on the open selector toggles it shut).
    (fixture.nativeElement.querySelector('.session-select .ant-select-selector') as HTMLElement).click();
    fixture.detectChanges();
    await fixture.whenStable();

    directory = [];
    fake.emit(lifecycle('ended', 'sess-abc123'));
    await flushRefresh(); // debounced re-pull removes the session
    fixture.detectChanges();
    expect(fixture.componentInstance.sessions().length).toBe(0);
    labels = await selectorOptions(fixture);
    expect(labels).toEqual(['live (all)']);
  });

  it('selecting a session switches the WS channel to sess:<sid> and back to * on live (all)', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();

    const second = FakeWebSocket.instances[1];
    expect(second).toBeDefined();
    expect(second.url).toContain(
      `channel=${encodeURIComponent('sess:sess-abc123')}&access_token=${TEST_JWT}`,
    );
    // Session-context header note shows the session id + username.
    const note = fixture.nativeElement.querySelector('.session-context-tag') as HTMLElement;
    expect(note).not.toBeNull();
    expect(note.textContent).toContain('sess-abc123');
    expect(note.textContent).toContain('alice');

    fixture.componentInstance.onSessionSelect('*');
    fixture.detectChanges();
    const third = FakeWebSocket.instances[2];
    expect(third).toBeDefined();
    expect(third.url).toMatch(/\/ws\/checker\?channel=\*&access_token=jwt-token-123$/);
    expect(fixture.nativeElement.querySelector('.session-context-tag')).toBeNull();
  });

  it('selecting a session through the dropdown reconnects to sess:<sid>', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    const options = await openSelectorOptions(fixture);
    const option = options.find((o) => o.textContent?.includes('sess-abc123')) as HTMLElement;
    option.click();
    fixture.detectChanges();
    await fixture.whenStable();

    expect(fixture.componentInstance.selectedSession()).toBe('sess-abc123');
    expect(FakeWebSocket.instances[1].url).toContain(
      `channel=${encodeURIComponent('sess:sess-abc123')}`,
    );
  });

  // ---- Task 8.5: session lifecycle rows -------------------------------------------

  it('renders kind=session rows with started/ended action tags and no target', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    const fake = FakeWebSocket.instances[0];
    fake.open();

    fake.emit(lifecycle('started', 'sess-1'));
    fake.emit(lifecycle('ended', 'sess-2'));
    await fixture.whenStable();
    fixture.detectChanges();

    const rows = fixture.nativeElement.querySelectorAll('tbody tr');
    expect(rows.length).toBe(2);
    const first = rows[0] as HTMLElement;
    expect(first.textContent).toContain('session');
    expect(first.textContent).toContain('started');
    const second = rows[1] as HTMLElement;
    expect(second.textContent).toContain('ended');
    // Lifecycle events carry no db_ip/db_port → the target cell shows a dash.
    expect(fixture.componentInstance.target(lifecycle('started', 'sess-1'))).toBe('—');
  });

  // ---- Task 8.12: pending sessions (gating-deadlock fix, frontend side) --------

  it('adds a pending option with the waiting badge on action=issued, even before the API knows', async () => {
    let directory: SessionInfo[] = []; // the /api/sessions re-pull has NOT caught up yet
    api.sessions = vi.fn(() => of(directory));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    const fake = FakeWebSocket.instances[0];
    fake.open();

    fake.emit(lifecycle('issued', 'sess-pend1'));
    await flushRefresh(); // Task 9.11: lifecycle re-pulls are debounced
    fixture.detectChanges();

    // The optimistic entry survives even though the API returned an empty list.
    expect(fixture.componentInstance.sessions().length).toBe(1);
    expect(fixture.componentInstance.sessions()[0].status).toBe('pending');

    const options = await openSelectorOptions(fixture);
    const pending = options.find((o) => o.textContent?.includes('sess-pend1')) as HTMLElement;
    expect(pending).toBeDefined();
    expect(pending.textContent).toContain('waiting');
    expect(pending.querySelector('.ant-tag-gold')).not.toBeNull(); // the waiting badge
  });

  it('action=started upgrades the pending session to active (waiting badge gone)', async () => {
    let directory: SessionInfo[] = [session({ status: 'pending' })];
    api.sessions = vi.fn(() => of(directory));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    const fake = FakeWebSocket.instances[0];
    fake.open();

    fake.emit(lifecycle('issued', 'sess-abc123'));
    await flushRefresh(); // Task 9.11: lifecycle re-pulls are debounced
    fixture.detectChanges();
    expect(fixture.componentInstance.sessions()[0].status).toBe('pending');

    // The data plane overwrote the directory record (status active) before
    // publishing started — the re-pull now returns the active shape.
    directory = [session({ status: 'active' })];
    fake.emit(lifecycle('started', 'sess-abc123'));
    await flushRefresh(); // debounced re-pull picks up the active record
    fixture.detectChanges();

    expect(fixture.componentInstance.sessions().length).toBe(1);
    expect(fixture.componentInstance.sessions()[0].status).toBe('active');

    const options = await openSelectorOptions(fixture);
    const opt = options.find((o) => o.textContent?.includes('sess-abc123')) as HTMLElement;
    expect(opt).toBeDefined();
    expect(opt.textContent).not.toContain('waiting');
    expect(opt.querySelector('.ant-tag-gold')).toBeNull();
  });

  it('action=ended removes a pending session from the selector', async () => {
    let directory: SessionInfo[] = [session({ status: 'pending' })];
    api.sessions = vi.fn(() => of(directory));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    const fake = FakeWebSocket.instances[0];
    fake.open();

    fake.emit(lifecycle('issued', 'sess-abc123'));
    await flushRefresh(); // Task 9.11: lifecycle re-pulls are debounced
    fixture.detectChanges();
    expect(fixture.componentInstance.sessions().length).toBe(1);

    directory = [];
    fake.emit(lifecycle('ended', 'sess-abc123'));
    await flushRefresh(); // debounced re-pull removes the session
    fixture.detectChanges();

    expect(fixture.componentInstance.sessions().length).toBe(0);
    const labels = await selectorOptions(fixture);
    expect(labels).toEqual(['live (all)']);
  });

  it('renders pending sessions from the API list with the waiting badge (active ones without)', async () => {
    api.sessions = vi.fn(() =>
      of([
        session({ status: 'pending' }),
        session({ session_id: 'sess-active1', status: 'active' }),
      ]),
    );
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    const options = await openSelectorOptions(fixture);
    const pending = options.find((o) => o.textContent?.includes('sess-abc123')) as HTMLElement;
    expect(pending).toBeDefined();
    expect(pending.textContent).toContain('waiting');
    expect(pending.querySelector('.ant-tag-gold')).not.toBeNull();

    const active = options.find((o) => o.textContent?.includes('sess-active1')) as HTMLElement;
    expect(active).toBeDefined();
    expect(active.textContent).not.toContain('waiting');
    expect(active.querySelector('.ant-tag-gold')).toBeNull();
  });

  it('selecting a pending session arms the gate: subscribes to sess:<sid>', async () => {
    api.sessions = vi.fn(() => of([session({ status: 'pending' })]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    const options = await openSelectorOptions(fixture);
    const pending = options.find((o) => o.textContent?.includes('sess-abc123')) as HTMLElement;
    pending.click();
    fixture.detectChanges();
    await fixture.whenStable();

    expect(fixture.componentInstance.selectedSession()).toBe('sess-abc123');
    expect(FakeWebSocket.instances[1]).toBeDefined();
    expect(FakeWebSocket.instances[1].url).toContain(
      `channel=${encodeURIComponent('sess:sess-abc123')}`,
    );
  });

  it('maps issued lifecycle action tags to gold (started green, ended red)', () => {
    const comp = TestBed.createComponent(CheckerDashboardComponent).componentInstance;
    expect(comp.actionColor('issued')).toBe('gold');
    expect(comp.actionColor('started')).toBe('green');
    expect(comp.actionColor('ended')).toBe('red');
    expect(comp.actionColor(undefined)).toBe('red');
  });

  // ---- Task 8.15: accurate status transitions ------------------------------------

  it('derives watching status when a session is selected and its feed is open', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[1].open();
    fixture.detectChanges();

    const tag = fixture.nativeElement.querySelector('.status-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toBe('watching sess-abc123 · alice');
    expect(tag.classList.contains('ant-tag-success')).toBe(true);
    expect(fixture.componentInstance.feedStatus()).toBe('watching');
  });

  it('flips to disconnected and surfaces the connection-lost banner when the socket errors', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    const fake = FakeWebSocket.instances[0];
    fake.open();
    fixture.detectChanges();
    expect(fixture.componentInstance.feedStatus()).toBe('live-feed');

    fake.fail();
    fixture.detectChanges();

    // Task 9.11: a WS error is surfaced distinctly from a clean disconnect.
    const tag = fixture.nativeElement.querySelector('.status-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toBe('connection lost');
    const alert = fixture.nativeElement.querySelector('.ws-error-alert') as HTMLElement;
    expect(alert).not.toBeNull();
    expect(alert.textContent).toContain('connection lost');
    expect(service.connected()).toBe(false);
    expect(service.connectState()).toBe('error');
  });

  it('flips to disconnected when the server closes the socket cleanly', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();
    fixture.detectChanges();
    expect(fixture.componentInstance.feedStatus()).toBe('live-feed');

    FakeWebSocket.instances[0].close(); // server-side close → rxjs complete
    fixture.detectChanges();

    const tag = fixture.nativeElement.querySelector('.status-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toBe('disconnected');
    expect(service.connectState()).toBe('closed');
  });

  it('flips to session ended when the watched session ends', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[1].open();
    fixture.detectChanges();
    expect(fixture.componentInstance.feedStatus()).toBe('watching');

    FakeWebSocket.instances[1].emit(lifecycle('ended', 'sess-abc123'));
    await fixture.whenStable();
    fixture.detectChanges();

    const tag = fixture.nativeElement.querySelector('.status-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toBe('session ended');
    expect(tag.classList.contains('ant-tag-red')).toBe(true);
    expect(fixture.componentInstance.feedStatus()).toBe('session-ended');
  });

  it('returns to live feed when switching back to live (all) after a session ended', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[1].open();
    FakeWebSocket.instances[1].emit(lifecycle('ended', 'sess-abc123'));
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.componentInstance.feedStatus()).toBe('session-ended');

    fixture.componentInstance.onSessionSelect('*');
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[2].open();
    fixture.detectChanges();

    const tag = fixture.nativeElement.querySelector('.status-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toBe('live feed');
    expect(fixture.componentInstance.feedStatus()).toBe('live-feed');
  });

  it('a late close from a superseded socket does not clobber the new feed status', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[1].open();
    fixture.detectChanges();
    expect(fixture.componentInstance.feedStatus()).toBe('watching');

    // The OLD socket's close event arrives late — the generation guard must
    // keep it from flipping the shared state while the new feed is up.
    FakeWebSocket.instances[0].close();
    fixture.detectChanges();

    expect(fixture.componentInstance.feedStatus()).toBe('watching');
    expect(service.connected()).toBe(true);
    expect(service.connectState()).toBe('open');
  });

  // ---- Task 8.15: toolbar kill-connection -----------------------------------------

  it('toolbar kill connection is disabled in live-all mode', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();

    const btn = fixture.nativeElement.querySelector('.kill-connection-btn') as HTMLButtonElement;
    expect(btn).not.toBeNull();
    expect(btn.disabled).toBe(true);
  });

  // ---- Task 8.15: session context strip + constant-column removal ----------------

  it('renders the session context strip with directory + event fields in session mode', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[1].open();
    FakeWebSocket.instances[1].emit(
      event({ id: 'evt-1', session_id: 'sess-abc123', ticket_id: 'OPS-1234' }),
    );
    await fixture.whenStable();
    fixture.detectChanges();

    const strip = fixture.nativeElement.querySelector('.session-strip') as HTMLElement;
    expect(strip).not.toBeNull();
    // Task 8.16: strip keeps its label/value structure (legibility styling hooks).
    expect(strip.querySelectorAll('.strip-label').length).toBe(1);
    expect(strip.querySelectorAll('.strip-value').length).toBe(6); // username, db, dbType, target, ticket, sid
    const text = strip.textContent ?? '';
    expect(text).toContain('alice'); // username (directory)
    expect(text).toContain('appdb'); // db (directory)
    expect(text).toContain('mysql'); // db_type (directory)
    expect(text).toContain('app@10.0.0.5:3306'); // target (first event)
    expect(text).toContain('OPS-1234'); // ticket_id (query events only)
    expect(text).toContain('sess-abc123'); // session id (short)
  });

  it('renders the strip from directory info with dashes when no event has arrived yet', async () => {
    api.sessions = vi.fn(() => of([session({ status: 'pending' })]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();

    const strip = fixture.nativeElement.querySelector('.session-strip') as HTMLElement;
    expect(strip).not.toBeNull();
    const text = strip.textContent ?? '';
    expect(text).toContain('alice');
    expect(text).toContain('appdb');
    expect(text).toContain('mysql');
    expect(text.match(/—/g)?.length).toBe(2); // target + ticket: no events yet
  });

  it('hides the session context strip in live-all mode', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector('.session-strip')).toBeNull();
  });

  it('removes the constant columns from the table in session mode', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();

    const headers = Array.from(
      (fixture.nativeElement as HTMLElement).querySelectorAll('thead th'),
    ).map((th) => th.textContent?.trim());
    expect(headers).toEqual(['Ts', 'Kind', 'Status', 'Output', 'Kill', 'SQL']);
    const empty = fixture.nativeElement.querySelector('tbody .cell-empty') as HTMLElement;
    expect(empty?.getAttribute('colspan')).toBe('6'); // empty row spans session-mode width
  });

  it('keeps the constant columns in live-all mode', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();

    const headers = Array.from(
      (fixture.nativeElement as HTMLElement).querySelectorAll('thead th'),
    ).map((th) => th.textContent?.trim());
    expect(headers).toEqual([
      'Ts',
      'Kind',
      'Username',
      'DB',
      'Target',
      'Ticket',
      'Status',
      'Output',
      'Kill',
      'SQL',
    ]);
    const empty = fixture.nativeElement.querySelector('tbody .cell-empty') as HTMLElement;
    expect(empty?.getAttribute('colspan')).toBe('10');
  });

  it('wires the checker session-dropdown class for option spacing (Task 8.16)', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();

    await openSelectorOptions(fixture);
    const dropdown = document.querySelector('.checker-session-dropdown') as HTMLElement;
    expect(dropdown).not.toBeNull();
    const options = dropdown.querySelectorAll('.ant-select-item-option');
    expect(options.length).toBeGreaterThan(0);
  });

  // ---- Task 8.18: toolbar controls on the nz-row/nz-col grid -----------------

  it('renders the toolbar on the nz grid with responsive spans (selector the widest col)', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('.checker-controls nz-row') as HTMLElement;
    expect(row).not.toBeNull();
    expect(row.classList.contains('ant-row')).toBe(true);
    // Vertical centering comes from the grid row itself (nzAlign="middle").
    expect(row.classList.contains('ant-row-middle')).toBe(true);

    const cols = Array.from(
      (fixture.nativeElement as HTMLElement).querySelectorAll('.checker-controls nz-col'),
    ) as HTMLElement[];
    const colOf = (sel: string): HTMLElement => {
      const col = cols.find((c) => c.querySelector(sel) !== null);
      if (!col) throw new Error(`no nz-col containing "${sel}"`);
      return col;
    };

    // Session selector: full-width rows below md, the WIDEST col on md/lg.
    const sessionCol = colOf('.session-select');
    expect(sessionCol.classList.contains('ant-col-xs-24')).toBe(true);
    expect(sessionCol.classList.contains('ant-col-sm-24')).toBe(true);
    expect(sessionCol.classList.contains('ant-col-md-13')).toBe(true);
    expect(sessionCol.classList.contains('ant-col-lg-14')).toBe(true);

    // Channel input + Connect/Stop: stable spans (narrower than the selector).
    const channelCol = colOf('.channel-group');
    expect(channelCol.classList.contains('ant-col-xs-24')).toBe(true);
    expect(channelCol.classList.contains('ant-col-sm-24')).toBe(true);
    expect(channelCol.classList.contains('ant-col-md-11')).toBe(true);
    expect(channelCol.classList.contains('ant-col-lg-10')).toBe(true);

    // Kill-connection: stable span (full row on xs, half row on sm).
    const killCol = colOf('.kill-connection-btn');
    expect(killCol.classList.contains('ant-col-xs-24')).toBe(true);
    expect(killCol.classList.contains('ant-col-sm-8')).toBe(true);
    expect(killCol.classList.contains('ant-col-md-6')).toBe(true);
    expect(killCol.classList.contains('ant-col-lg-6')).toBe(true);

    // Status tag + auto-scroll: half-width rows on xs, stable compact spans up.
    const statusCol = colOf('.status-tag');
    expect(statusCol.classList.contains('ant-col-xs-12')).toBe(true);
    expect(statusCol.classList.contains('ant-col-sm-8')).toBe(true);
    expect(statusCol.classList.contains('ant-col-md-6')).toBe(true);
    expect(statusCol.classList.contains('ant-col-lg-6')).toBe(true);

    const autoCol = colOf('.autoscroll-row');
    expect(autoCol.classList.contains('ant-col-xs-12')).toBe(true);
    expect(autoCol.classList.contains('ant-col-sm-8')).toBe(true);
    expect(autoCol.classList.contains('ant-col-md-6')).toBe(true);
    expect(autoCol.classList.contains('ant-col-lg-6')).toBe(true);

    // The selector is strictly wider than the channel wherever they share a row.
    expect(sessionCol.classList.contains('ant-col-md-13')).toBe(true);
    expect(channelCol.classList.contains('ant-col-md-11')).toBe(true);
    expect(sessionCol.classList.contains('ant-col-lg-14')).toBe(true);
    expect(channelCol.classList.contains('ant-col-lg-10')).toBe(true);
  });

  it('shows channel input, connect/stop, kill-connection and the status tag on the grid', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();

    const grid = fixture.nativeElement.querySelector('.checker-controls') as HTMLElement;
    expect(grid).not.toBeNull();

    const input = grid.querySelector('#channel') as HTMLInputElement;
    expect(input).not.toBeNull();
    expect(input.disabled).toBe(false); // editable until the feed connects

    // Connect/stop toggle (Task 9.11): driven by the REAL socket state —
    // Connect until the socket actually opens, Stop while it is open,
    // Connect again after a disconnect.
    const buttons = () =>
      Array.from(grid.querySelectorAll('button')).map((b) => b.textContent?.trim());
    expect(buttons()).toContain('Connect');
    expect(buttons()).not.toContain('Stop');

    FakeWebSocket.instances[0].open();
    fixture.detectChanges();
    expect(buttons()).toContain('Stop');
    expect(buttons()).not.toContain('Connect');

    fixture.componentInstance.stop();
    fixture.detectChanges();
    expect(buttons()).toContain('Connect');
    expect(buttons()).not.toContain('Stop');

    const kill = grid.querySelector('.kill-connection-btn') as HTMLButtonElement;
    expect(kill).not.toBeNull();
    expect(kill.disabled).toBe(true); // live-all mode

    const tag = grid.querySelector('.status-tag') as HTMLElement;
    expect(tag).not.toBeNull();
    expect(tag.textContent?.trim()).toBe('disconnected');
  });

  // ---- Task 9.11: review remediation (round 1 behavioral specs) --------------

  it('session mode shows ONLY the selected session\'s events (review 9.11a misattribution)', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    // A row of ANOTHER session sits in the ring buffer while still in live-all mode.
    FakeWebSocket.instances[0].emit(
      event({ id: 'evt-other', session_id: 'sess-other', sql: 'SELECT other' }),
    );
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelectorAll('tbody tr').length).toBe(1);

    // Selecting the session narrows the table to ITS events only — the
    // buffered foreign row must not be attributed to it.
    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();
    const fake = FakeWebSocket.instances[1];
    fake.open();
    fake.emit(event({ id: 'evt-own', session_id: 'sess-abc123', sql: 'SELECT own' }));
    await fixture.whenStable();
    fixture.detectChanges();

    expect(service.events().length).toBe(2); // ring buffer keeps both
    expect(fixture.componentInstance.visibleEvents().length).toBe(1); // filtered view

    const rows = fixture.nativeElement.querySelectorAll('tbody tr');
    expect(rows.length).toBe(1);
    const row = rows[0] as HTMLElement;
    expect(row.textContent).toContain('SELECT own');
    expect(row.textContent).not.toContain('SELECT other');
    expect(row.textContent).not.toContain('sess-other');
  });

  it('401 from /api/sessions logs out and navigates to /login (no auth loop)', async () => {
    api.sessions = vi.fn(() => throwError(() => ({ status: 401 })));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    // handleUnauthorized fires logout() → navigate() — let the navigation settle.
    await new Promise((r) => setTimeout(r, 0));

    expect(auth.logout).toHaveBeenCalledTimes(1);
    const router = TestBed.inject(Router);
    expect(router.url).toBe('/login');
  });

  it('prunes a pending override after 3 consecutive /api/sessions misses (ghost token)', async () => {
    api.sessions = vi.fn(() => of([])); // the API never records the issue
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(lifecycle('issued', 'sess-ghost'));
    await flushRefresh(); // debounced pull #1 misses it → miss 1
    fixture.detectChanges();
    expect(fixture.componentInstance.sessions().length).toBe(1); // still optimistic

    fixture.componentInstance.refreshSessions(); // miss 2 — still shown
    expect(fixture.componentInstance.sessions().length).toBe(1);

    fixture.componentInstance.refreshSessions(); // miss 3 ≥ PENDING_MAX_MISSES → pruned
    expect(fixture.componentInstance.sessions().length).toBe(0);
    const labels = await selectorOptions(fixture);
    expect(labels).toEqual(['live (all)']);
  });

  it('kill connection is disabled once the watched session has ended', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[1].open();
    fixture.detectChanges();

    const btn = () =>
      fixture.nativeElement.querySelector('.kill-connection-btn') as HTMLButtonElement;
    expect(btn().disabled).toBe(false); // watching a live session

    FakeWebSocket.instances[1].emit(lifecycle('ended', 'sess-abc123'));
    await fixture.whenStable();
    fixture.detectChanges();

    expect(fixture.componentInstance.feedStatus()).toBe('session-ended');
    expect(btn().disabled).toBe(true); // nothing left to kill
  });

  it('a WS ended event marks the session\'s buffered rows killed (WS kill path)', async () => {
    api.sessions = vi.fn(() => of([session()]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    FakeWebSocket.instances[0].open();

    fixture.componentInstance.onSessionSelect('sess-abc123');
    fixture.detectChanges();
    await fixture.whenStable();
    const fake = FakeWebSocket.instances[1];
    fake.open();

    fake.emit(event({ id: 'evt-a', session_id: 'sess-abc123', sql: 'SELECT 1' }));
    fake.emit(event({ id: 'evt-b', session_id: 'sess-abc123', sql: 'SELECT 2' }));
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.componentInstance.killed()).toEqual({}); // rows live before the end

    fake.emit(lifecycle('ended', 'sess-abc123'));
    await fixture.whenStable();
    fixture.detectChanges();

    // The ended lifecycle row joins the two query rows — all marked dead.
    const rows = fixture.nativeElement.querySelectorAll('tbody tr');
    expect(rows.length).toBe(3);
    for (const row of Array.from(rows)) {
      const el = row as HTMLElement;
      const killedTag = Array.from(el.querySelectorAll('nz-tag')).find(
        (t) => t.textContent?.trim() === 'killed',
      );
      expect(killedTag).toBeDefined();
      expect((killedTag as HTMLElement).classList.contains('ant-tag-red')).toBe(true);
      // No kill-query popconfirm on dead rows; the disabled kill button stays.
      expect(el.querySelector('button[nz-popconfirm]')).toBeNull();
      const killBtn = Array.from(el.querySelectorAll('button')).find(
        (b) => b.textContent?.trim() === 'kill',
      ) as HTMLButtonElement | undefined;
      expect(killBtn).toBeDefined();
      expect(killBtn!.disabled).toBe(true);
    }
  });

  it('renders the compact UTC clock in the Ts cell and keeps the full timestamp in title', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event({ ts: '2026-08-11T08:05:09Z' }));
    await fixture.whenStable();
    fixture.detectChanges();

    const cell = fixture.nativeElement.querySelector('tbody tr .cell-ts') as HTMLElement;
    expect(cell.textContent?.trim()).toBe('08:05:09'); // HH:MM:SS UTC
    expect(cell.getAttribute('title')).toBe('2026-08-11T08:05:09Z'); // full RFC3339 for hover

    const comp = fixture.componentInstance;
    expect(comp.formatTs('2026-08-11T08:05:09Z')).toBe('08:05:09');
    expect(comp.formatTs('2026-08-11T08:05:09.123456+02:00')).toBe('06:05:09'); // any tz → UTC clock
    expect(comp.formatTs('')).toBe('—');
    expect(comp.formatTs('not-a-date')).toBe('not-a-date'); // invalid passthrough, no crash
  });

  it('renders the DB column from the event db field in live-all mode', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event({ db: 'salesdb' }));
    await fixture.whenStable();
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    // live-all layout: Ts, Kind, Username, DB, Target, Ticket, Status, Output, Kill, SQL
    const cells = Array.from(row.querySelectorAll('td')).map((td) => td.textContent?.trim());
    expect(cells[3]).toBe('salesdb');
  });

  it('memoizes the derived output columns and rows per event object', () => {
    const comp = TestBed.createComponent(CheckerDashboardComponent).componentInstance;
    const ev = event({ columns: ['id', 'name'], rows: [['1', 'alpha']] });

    expect(comp.outputColumns(ev)).toBe(comp.outputColumns(ev)); // same object identity
    expect(comp.outputRows(ev)).toBe(comp.outputRows(ev));
    expect(comp.outputColumns(ev)).toEqual([
      { title: 'id', key: 'c0' },
      { title: 'name', key: 'c1' },
    ]);
    expect(comp.outputRows(ev)).toEqual([{ c0: '1', c1: 'alpha' }]);
  });

  it('wires nzShowSearch on the session selector', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();

    const select = fixture.nativeElement.querySelector('.session-select') as HTMLElement;
    expect(select).not.toBeNull();
    // Angular 21 renders the static nzShowSearch input as the host attribute
    // `nzshowsearch` (and nz-select adds the ant-select-show-search class).
    expect(select.hasAttribute('nzshowsearch')).toBe(true);
    expect(select.classList.contains('ant-select-show-search')).toBe(true);
  });

  it('coalesces a lifecycle burst into ONE debounced directory re-pull', async () => {
    api.sessions = vi.fn(() => of([]));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges(); // init → connect() → refreshSessions()
    await fixture.whenStable();
    expect(api.sessions).toHaveBeenCalledTimes(1);

    const fake = FakeWebSocket.instances[0];
    fake.open();
    fake.emit(lifecycle('started', 'sess-1'));
    fake.emit(lifecycle('started', 'sess-2'));
    fake.emit(lifecycle('ended', 'sess-3'));
    await flushRefresh(); // debounce window folds the burst into one pull
    fixture.detectChanges();

    expect(api.sessions).toHaveBeenCalledTimes(2); // init + one coalesced re-pull
  });
});
