import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { ApiService, QueryEvent } from '../../core/api.service';
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

/** Find a row's button by its visible text (view/kill) — rows contain several buttons. */
function buttonByText(row: HTMLElement, text: string): HTMLButtonElement {
  const btn = Array.from(row.querySelectorAll('button')).find(
    (b) => b.textContent?.trim() === text,
  );
  if (!btn) throw new Error(`no button "${text}" in row`);
  return btn as HTMLButtonElement;
}

/** Open the row's nz-popconfirm and click its OK (confirm) button. */
async function confirmKill(fixture: ComponentFixture<CheckerDashboardComponent>) {
  const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
  const trigger = row.querySelector('button[nz-popconfirm]') as HTMLButtonElement;
  trigger.click();
  fixture.detectChanges();
  await fixture.whenStable();
  const ok = document.querySelectorAll('.ant-popover-buttons button')[1] as HTMLButtonElement;
  ok.click();
  await fixture.whenStable();
  fixture.detectChanges();
}

describe('CheckerDashboardComponent', () => {
  let service: LiveQueryService;
  let api: { killSession: ReturnType<typeof vi.fn> };
  let message: { success: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    FakeWebSocket.instances = [];
    api = { killSession: vi.fn(() => of({ killed: 'queued' })) };
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

  // ---- Task 6.7: kill button ----------------------------------------------------

  it('hides the kill button when the event has no session_id', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event());
    await fixture.whenStable();
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    expect(row.querySelector('button[nz-popconfirm]')).toBeNull();
  });

  it('kill flow: popconfirm confirm calls killSession and marks the row killed on 202', async () => {
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event({ session_id: 'sess-9' }));
    await fixture.whenStable();
    fixture.detectChanges();

    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    expect(row.querySelector('button[nz-popconfirm]')).not.toBeNull();
    expect(api.killSession).not.toHaveBeenCalled();

    await confirmKill(fixture);

    expect(api.killSession).toHaveBeenCalledTimes(1);
    expect(api.killSession).toHaveBeenCalledWith('sess-9');
    expect(message.success).toHaveBeenCalledWith(expect.stringContaining('sess-9'));

    const after = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    const killedTag = Array.from(after.querySelectorAll('nz-tag')).find(
      (t) => t.textContent?.trim() === 'killed',
    );
    expect(killedTag).toBeDefined();
    expect((killedTag as HTMLElement).classList.contains('ant-tag-red')).toBe(true);
    // The kill button is disabled and the popconfirm trigger is gone.
    expect(after.querySelector('button[nz-popconfirm]')).toBeNull();
    const killBtn = Array.from(after.querySelectorAll('button')).find(
      (b) => b.textContent?.trim() === 'kill',
    ) as HTMLButtonElement;
    expect(killBtn.disabled).toBe(true);
  });

  it('kill failure shows an error message and leaves the row killable', async () => {
    api.killSession = vi.fn(() => throwError(() => ({ status: 502 })));
    const fixture = TestBed.createComponent(CheckerDashboardComponent);
    fixture.detectChanges();
    FakeWebSocket.instances[0].open();

    FakeWebSocket.instances[0].emit(event({ session_id: 'sess-7' }));
    await fixture.whenStable();
    fixture.detectChanges();

    await confirmKill(fixture);

    expect(api.killSession).toHaveBeenCalledWith('sess-7');
    expect(message.error).toHaveBeenCalledWith(expect.stringContaining('sess-7'));
    const row = fixture.nativeElement.querySelector('tbody tr') as HTMLElement;
    expect(row.querySelector('button[nz-popconfirm]')).not.toBeNull(); // still killable
    expect(row.textContent).not.toContain('killed');
  });
});
