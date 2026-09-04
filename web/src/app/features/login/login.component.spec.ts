import { TestBed } from '@angular/core/testing';
import { ActivatedRoute, provideRouter, Router } from '@angular/router';
import { of, throwError } from 'rxjs';
import { ApiService } from '../../core/api.service';
import { AuthService } from '../../core/auth.service';
import { LoginComponent } from './login.component';

/** ActivatedRoute stub exposing a fixed returnUrl query param. */
function routeWithReturnUrl(returnUrl: string | null): unknown {
  return {
    snapshot: {
      queryParamMap: { get: (k: string) => (k === 'returnUrl' ? returnUrl : null) },
    },
  };
}

describe('LoginComponent', () => {
  let api: { login: ReturnType<typeof vi.fn>; logout: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    api = {
      login: vi.fn(() =>
        of({ token: 'jwt-login', username: 'alice', role: 'maker', expires_in: 28800 }),
      ),
      logout: vi.fn(() => of(null)),
    };
    TestBed.configureTestingModule({
      imports: [LoginComponent],
      providers: [provideRouter([]), { provide: ApiService, useValue: api }],
    });
  });

  function navigateSpy(): ReturnType<typeof vi.fn> {
    const router = TestBed.inject(Router);
    return vi.spyOn(router, 'navigate').mockResolvedValue(true);
  }

  it('submits credentials to AuthService and navigates to /maker on success', async () => {
    const nav = navigateSpy();
    const fixture = TestBed.createComponent(LoginComponent);
    const comp = fixture.componentInstance;
    fixture.detectChanges();

    comp.username.set('alice');
    comp.password.set('s3cret');
    comp.submit();
    await fixture.whenStable();

    expect(api.login).toHaveBeenCalledWith('alice', 's3cret');
    expect(comp.error()).toBeNull();
    expect(nav).toHaveBeenCalledWith(['/maker']);
  });

  it('navigates to returnUrl after login when the authGuard redirected here', async () => {
    TestBed.overrideProvider(ActivatedRoute, { useValue: routeWithReturnUrl('/checker') });
    const nav = navigateSpy();
    const fixture = TestBed.createComponent(LoginComponent);
    const comp = fixture.componentInstance;
    fixture.detectChanges();

    comp.username.set('alice');
    comp.password.set('s3cret');
    comp.submit();
    await fixture.whenStable();

    expect(nav).toHaveBeenCalledWith(['/checker']);
  });

  it('rejects empty fields without calling the API', () => {
    const nav = navigateSpy();
    const fixture = TestBed.createComponent(LoginComponent);
    const comp = fixture.componentInstance;
    fixture.detectChanges();

    comp.submit();

    expect(api.login).not.toHaveBeenCalled();
    expect(comp.error()).toBe('Enter both username and password.');
    expect(nav).not.toHaveBeenCalled();
  });

  it('shows an error alert on 401 and does not navigate', async () => {
    const nav = navigateSpy();
    api.login.mockReturnValue(throwError(() => ({ status: 401 })));
    const fixture = TestBed.createComponent(LoginComponent);
    const comp = fixture.componentInstance;
    fixture.detectChanges();

    comp.username.set('alice');
    comp.password.set('wrong');
    comp.submit();
    await fixture.whenStable();

    expect(comp.error()).toBe('Invalid username or password.');
    expect(nav).not.toHaveBeenCalled();
    fixture.detectChanges();
    const alert = fixture.nativeElement.querySelector('nz-alert') as HTMLElement;
    expect(alert).not.toBeNull();
  });

  it('surfaces the server error message for non-401 failures', async () => {
    api.login.mockReturnValue(
      throwError(() => ({ status: 503, error: { error: 'control plane unavailable' } })),
    );
    const fixture = TestBed.createComponent(LoginComponent);
    const comp = fixture.componentInstance;
    fixture.detectChanges();

    comp.username.set('alice');
    comp.password.set('s3cret');
    comp.submit();
    await fixture.whenStable();

    expect(comp.error()).toBe('control plane unavailable');
  });

  it('redirects to /maker on init when a session already exists', async () => {
    const nav = navigateSpy();
    const auth = TestBed.inject(AuthService);
    auth.login('alice', 's3cret').subscribe(); // sets the user signal

    const fixture = TestBed.createComponent(LoginComponent);
    fixture.detectChanges();

    expect(nav).toHaveBeenCalledWith(['/maker']);
  });

  it('redirects to returnUrl on init when a session already exists', async () => {
    TestBed.overrideProvider(ActivatedRoute, { useValue: routeWithReturnUrl('/checker') });
    const nav = navigateSpy();
    const auth = TestBed.inject(AuthService);
    auth.login('alice', 's3cret').subscribe(); // sets the user signal

    const fixture = TestBed.createComponent(LoginComponent);
    fixture.detectChanges();

    expect(nav).toHaveBeenCalledWith(['/checker']);
  });

  it('falls back to /maker for scheme-relative returnUrl values', async () => {
    TestBed.overrideProvider(ActivatedRoute, { useValue: routeWithReturnUrl('//evil.example') });
    const nav = navigateSpy();
    const auth = TestBed.inject(AuthService);
    auth.login('alice', 's3cret').subscribe();

    const fixture = TestBed.createComponent(LoginComponent);
    fixture.detectChanges();

    expect(nav).toHaveBeenCalledWith(['/maker']);
  });
});
