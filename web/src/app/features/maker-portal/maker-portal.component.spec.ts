import { Component, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { of, throwError } from 'rxjs';
import { ApiService, DbPreset, TokenResponse } from '../../core/api.service';
import { AuthService } from '../../core/auth.service';
import { MakerPortalComponent } from './maker-portal.component';

const PRESET: DbPreset = {
  name: 'mysql-app',
  db_type: 'mysql',
  db_user: 'app',
  db_ip: '127.0.0.1',
  db_port: '3306',
};

/** Phase 9 (Task 9.1): the MSSQL read-only preset — regression fixture for
 * the db_type mapping bug (mssql was collapsed to mysql by the old
 * mysql/postgres ternary, minting tokens that failed with "backend
 * unavailable"). */
const MSSQL_PRESET: DbPreset = {
  name: 'MSSQL read-only',
  db_type: 'mssql',
  db_user: 'ro_user',
  db_ip: '127.0.0.1',
  db_port: '1434',
};

const TOKEN: TokenResponse = { token: 'sess_test123', host: '127.0.0.1', port: '3306', expires_in: 300 };

/** Landing route for the 401 → /login navigation assertions (Task 9.11). */
@Component({ template: '', standalone: true })
class StubCmp {}

describe('MakerPortalComponent', () => {
  let api: {
    dbPresets: ReturnType<typeof vi.fn>;
    requestToken: ReturnType<typeof vi.fn>;
  };
  let auth: {
    user: ReturnType<typeof signal>;
    logout: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    api = {
      dbPresets: vi.fn(() => of([PRESET, MSSQL_PRESET])),
      requestToken: vi.fn(() => of(TOKEN)),
    };
    auth = {
      user: signal('alice'),
      logout: vi.fn(() => of(null)),
    };
    TestBed.configureTestingModule({
      imports: [MakerPortalComponent],
      providers: [
        provideRouter([{ path: 'login', component: StubCmp }]),
        { provide: ApiService, useValue: api },
        { provide: AuthService, useValue: auth },
      ],
    });
  });

  function makeFixture() {
    const fixture = TestBed.createComponent(MakerPortalComponent);
    fixture.detectChanges(); // ngOnInit → loadPresets
    return fixture;
  }

  function issueButton(fixture: ReturnType<typeof makeFixture>): HTMLButtonElement {
    return fixture.nativeElement.querySelector('form button') as HTMLButtonElement;
  }

  it('renders the ticket label as required, without the "(optional)" suffix', () => {
    const fixture = makeFixture();
    const label = fixture.nativeElement.querySelector('label[for="ticket"]') as HTMLElement;
    expect(label).not.toBeNull();
    expect(label.classList.contains('ant-form-item-required')).toBe(true);
    expect(label.textContent).toContain('Ticket id');
    expect(label.textContent).not.toContain('optional');
  });

  it('keeps Issue token disabled until a preset AND a non-blank ticket are set', () => {
    const fixture = makeFixture();
    const comp = fixture.componentInstance;

    // No preset, no ticket.
    expect(issueButton(fixture).disabled).toBe(true);

    // Preset only → still disabled.
    comp.selectedPreset.set(PRESET.name);
    fixture.detectChanges();
    expect(issueButton(fixture).disabled).toBe(true);

    // Preset + ticket → enabled.
    comp.ticketId.set('OPS-1234');
    fixture.detectChanges();
    expect(issueButton(fixture).disabled).toBe(false);

    // Whitespace-only ticket does not count.
    comp.ticketId.set('   ');
    fixture.detectChanges();
    expect(issueButton(fixture).disabled).toBe(true);
  });

  it('blocks submit with an empty ticket, sets the error, and never calls the API', () => {
    const fixture = makeFixture();
    const comp = fixture.componentInstance;
    comp.selectedPreset.set(PRESET.name);
    comp.ticketId.set('');

    comp.submit();

    expect(comp.submitError()).toBe('Ticket id is required');
    expect(api.requestToken).not.toHaveBeenCalled();
  });

  it('blocks submit with a whitespace-only ticket', () => {
    const fixture = makeFixture();
    const comp = fixture.componentInstance;
    comp.selectedPreset.set(PRESET.name);
    comp.ticketId.set('   ');

    comp.submit();

    expect(comp.submitError()).toBe('Ticket id is required');
    expect(api.requestToken).not.toHaveBeenCalled();
  });

  it('maps an MSSQL preset to db_type mssql, not mysql (Phase 9 regression)', async () => {
    const fixture = makeFixture();
    const comp = fixture.componentInstance;
    comp.onPresetChange(MSSQL_PRESET.name);
    comp.ticketId.set('OPS-MSSQL-1');

    comp.submit();
    await fixture.whenStable();
    fixture.detectChanges();

    expect(api.requestToken).toHaveBeenCalledWith(
      expect.objectContaining({
        db_type: 'mssql',
        db_port: '1434',
        db_user: 'ro_user',
        username: 'alice',
      }),
    );
  });

  it('submits the trimmed ticket id and renders the issued token', async () => {
    const fixture = makeFixture();
    const comp = fixture.componentInstance;
    comp.onPresetChange(PRESET.name);
    comp.ticketId.set('  OPS-1234  ');

    comp.submit();
    await fixture.whenStable();
    fixture.detectChanges();

    expect(api.requestToken).toHaveBeenCalledWith(
      expect.objectContaining({ ticket_id: 'OPS-1234', db_type: 'mysql', username: 'alice' }),
    );
    expect(comp.result()).toEqual(TOKEN);
    const tokenInput = fixture.nativeElement.querySelector('.token-input') as HTMLInputElement;
    expect(tokenInput.value).toBe(TOKEN.token);
  });

  // ---- Task 9.11: review remediation (round 1 behavioral specs) --------------

  it('a 401 on preset load logs out and navigates to /login (no auth loop)', async () => {
    api.dbPresets = vi.fn(() => throwError(() => ({ status: 401 })));
    const fixture = makeFixture();
    await fixture.whenStable();
    // handleUnauthorized fires logout() → navigate() — let the navigation settle.
    await new Promise((r) => setTimeout(r, 0));

    expect(auth.logout).toHaveBeenCalledTimes(1);
    expect(TestBed.inject(Router).url).toBe('/login');
  });

  it('changing the ticket id invalidates the previously issued token', async () => {
    const fixture = makeFixture();
    const comp = fixture.componentInstance;
    comp.onPresetChange(PRESET.name);
    comp.ticketId.set('OPS-1111');

    comp.submit();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(comp.result()).toEqual(TOKEN); // issued for OPS-1111

    comp.onTicketChange('OPS-2222');

    expect(comp.ticketId()).toBe('OPS-2222');
    expect(comp.result()).toBeNull(); // stale token cleared
    expect(comp.submitError()).toBeNull();
  });

  it('a 401 on token submit logs out, navigates to /login, and clears the submitting flag', async () => {
    api.requestToken = vi.fn(() => throwError(() => ({ status: 401 })));
    const fixture = makeFixture();
    const comp = fixture.componentInstance;
    comp.onPresetChange(PRESET.name);
    comp.ticketId.set('OPS-1234');

    comp.submit();
    await fixture.whenStable();
    await new Promise((r) => setTimeout(r, 0));

    expect(auth.logout).toHaveBeenCalledTimes(1);
    expect(TestBed.inject(Router).url).toBe('/login');
    expect(comp.submitting()).toBe(false);
    expect(comp.result()).toBeNull();
  });
});
