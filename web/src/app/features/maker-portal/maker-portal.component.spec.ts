import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of } from 'rxjs';
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

const TOKEN: TokenResponse = { token: 'sess_test123', host: '127.0.0.1', port: '3306', expires_in: 300 };

describe('MakerPortalComponent', () => {
  let api: {
    dbPresets: ReturnType<typeof vi.fn>;
    requestToken: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    api = {
      dbPresets: vi.fn(() => of([PRESET])),
      requestToken: vi.fn(() => of(TOKEN)),
    };
    TestBed.configureTestingModule({
      imports: [MakerPortalComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: api },
        { provide: AuthService, useValue: { user: signal('alice') } },
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
});
