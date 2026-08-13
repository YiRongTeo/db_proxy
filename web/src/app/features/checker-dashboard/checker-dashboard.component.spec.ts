import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { ApiService, QueryEvent, SessionInfo } from '../../core/api.service';
import { LiveQueryService } from '../../core/live-query.service';
import { NzMessageService } from 'ng-zorro-antd/message';
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

  fail() {
    this.onerror?.({} as Event);
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
function lifecycle(action: 'started' | 'issued' | 'ended', sid: string): QueryEvent {
  return {
    id: `life-${action}-${sid}`,
    ts: '2026-08-11T08:00:00Z',
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

describe('CheckerDashboardComponent', () => {
  let service: LiveQueryService;
  let api: {
    killSession: ReturnType<typeof vi.fn>;
    sessions: ReturnType<typeof vi.fn>;
  };
  let message: { success: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    FakeWebSocket.instances = [];
    api = {
      killSession: vi.fn(() => of({ killed: 'queued' })),
      sessions: vi.fn(() => of([])),
    };
    message = { success: vi.fn(), error: vi.fn() };
    TestBed.configureTestingModule({
      imports: [CheckerDashboardComponent],
      providers: [
        LiveQueryService,
        { provide: ApiService, useValue: api },
        { provide: NzMessageService, useValue: message },
      ],
    });
    service = TestBed.inject(LiveQueryService);
    service.socketCtor = FakeWebSocket as unknown as new (url: string) => WebSocket;
  });

  it('auto-connects to the default * channel on init and shows the live-feed tag once open', () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();

    const fake = FakeWebSocket.instances[0];
    expect(fake).toBeDefined();
    expect(fake.url).toMatch(/\/ws\/checker\?channel=\*$/); // '*' is not escaped by encodeURIComponent
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
    expect(errTag?.getAttribute('title')).toBe('relation "nope" does not exist');

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
    await fixture.whenStable();
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
    await fixture.whenStable();
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
    expect(second.url).toContain(`channel=${encodeURIComponent('sess:sess-abc123')}`);
    // Session-context header note shows the session id + username.
    const note = fixture.nativeElement.querySelector('.session-context-tag') as HTMLElement;
    expect(note).not.toBeNull();
    expect(note.textContent).toContain('sess-abc123');
    expect(note.textContent).toContain('alice');

    fixture.componentInstance.onSessionSelect('*');
    fixture.detectChanges();
    const third = FakeWebSocket.instances[2];
    expect(third).toBeDefined();
    expect(third.url).toMatch(/\/ws\/checker\?channel=\*$/);
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
    await fixture.whenStable();
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
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.componentInstance.sessions()[0].status).toBe('pending');

    // The data plane overwrote the directory record (status active) before
    // publishing started — the re-pull now returns the active shape.
    directory = [session({ status: 'active' })];
    fake.emit(lifecycle('started', 'sess-abc123'));
    await fixture.whenStable();
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
    await fixture.whenStable();
    fixture.detectChanges();
    expect(fixture.componentInstance.sessions().length).toBe(1);

    directory = [];
    fake.emit(lifecycle('ended', 'sess-abc123'));
    await fixture.whenStable();
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

  it('flips to disconnected when the socket errors', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    const fake = FakeWebSocket.instances[0];
    fake.open();
    fixture.detectChanges();
    expect(fixture.componentInstance.feedStatus()).toBe('live-feed');

    fake.fail();
    fixture.detectChanges();

    const tag = fixture.nativeElement.querySelector('.status-tag') as HTMLElement;
    expect(tag.textContent?.trim()).toBe('disconnected');
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
});
