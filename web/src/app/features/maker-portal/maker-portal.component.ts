import { Component, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ClipboardModule } from '@angular/cdk/clipboard';
import { NzAlertModule } from 'ng-zorro-antd/alert';
import { NzButtonModule } from 'ng-zorro-antd/button';
import { NzCardModule } from 'ng-zorro-antd/card';
import { NzDescriptionsModule } from 'ng-zorro-antd/descriptions';
import { NzFormModule } from 'ng-zorro-antd/form';
import { NzInputModule } from 'ng-zorro-antd/input';
import { NzSelectModule } from 'ng-zorro-antd/select';
import { NzSpinModule } from 'ng-zorro-antd/spin';
import { ApiService, DbPreset, TokenResponse } from '../../core/api.service';
import { AuthService } from '../../core/auth.service';

/**
 * Maker Portal: pick a database preset, attach the required ticket id, and
 * issue a single-use token. The token is copied via the CDK clipboard and
 * the connection details are shown as an nz-descriptions block.
 */
@Component({
  selector: 'app-maker-portal',
  standalone: true,
  imports: [
    FormsModule,
    ClipboardModule,
    NzAlertModule,
    NzButtonModule,
    NzCardModule,
    NzDescriptionsModule,
    NzFormModule,
    NzInputModule,
    NzSelectModule,
    NzSpinModule,
  ],
  templateUrl: './maker-portal.component.html',
  styleUrl: './maker-portal.component.scss',
})
export class MakerPortalComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);

  // Preset loading
  readonly presets = signal<DbPreset[]>([]);
  readonly presetsLoading = signal(true);
  readonly presetsError = signal<string | null>(null);

  // Form state (signals, per house style)
  readonly selectedPreset = signal<string | null>(null);
  readonly ticketId = signal('');
  readonly dbType = signal<'mysql' | 'postgres' | 'mssql' | 'oracle'>('mysql');
  readonly dbUser = signal('');
  readonly dbIp = signal('');
  readonly dbPort = signal('');

  // Submit state
  readonly submitting = signal(false);
  readonly submitError = signal<string | null>(null);
  readonly result = signal<TokenResponse | null>(null);
  readonly copied = signal(false);

  ngOnInit(): void {
    this.loadPresets();
  }

  private loadPresets(): void {
    this.presetsLoading.set(true);
    this.presetsError.set(null);
    this.api.dbPresets().subscribe({
      next: (presets) => {
        this.presets.set(presets);
        this.presetsLoading.set(false);
      },
      error: (err) => {
        this.presetsLoading.set(false);
        if (err.status === 401) {
          // Task 9.11: clear the UI session BEFORE leaving — otherwise the
          // stale user signal keeps the authGuard happy and the SPA loops
          // on 401s.
          this.handleUnauthorized();
          return;
        }
        this.presetsError.set('Could not load database presets — is the control plane reachable?');
      },
    });
  }

  /** Selecting a preset fills the hidden db_type/db_user/db_ip/db_port fields. */
  onPresetChange(name: string): void {
    const preset = this.presets().find((p) => p.name === name);
    if (!preset) {
      return;
    }
    this.selectedPreset.set(name);
    // Phase 9 (Task 9.1): pass the preset's db_type through VERBATIM.
    // The pre-Phase-9 ternary (db_type === 'postgres' ? 'postgres' : 'mysql')
    // collapsed mssql → mysql, so an MSSQL preset minted a mysql token aimed
    // at the mssql port — the data plane found no credential key
    // (mysql:ro_user@127.0.0.1:1434) and answered "backend unavailable".
    const t = preset.db_type;
    this.dbType.set(t === 'mysql' || t === 'postgres' || t === 'mssql' || t === 'oracle' ? t : 'mysql');
    this.dbUser.set(preset.db_user);
    this.dbIp.set(preset.db_ip);
    this.dbPort.set(preset.db_port);
    // A new target invalidates any previously issued token.
    this.result.set(null);
    this.submitError.set(null);
  }

  /** Ticket input change: a new ticket invalidates the previously issued token (Task 9.11). */
  onTicketChange(value: string): void {
    this.ticketId.set(value);
    this.result.set(null);
    this.submitError.set(null);
  }

  submit(): void {
    if (!this.ticketId().trim()) {
      this.submitError.set('Ticket id is required');
      return;
    }
    if (!this.selectedPreset()) {
      return;
    }
    this.submitting.set(true);
    this.submitError.set(null);
    this.result.set(null);
    this.api
      .requestToken({
        username: this.auth.user() ?? '',
        db_type: this.dbType(),
        db_user: this.dbUser(),
        db_ip: this.dbIp(),
        db_port: this.dbPort(),
        ticket_id: this.ticketId().trim() || undefined,
      })
      .subscribe({
        next: (res) => {
          this.result.set(res);
          this.submitting.set(false);
        },
        error: (err) => {
          this.submitting.set(false);
          if (err.status === 401) {
            this.handleUnauthorized();
            return;
          }
          this.submitError.set(err.error?.error ?? 'Token request failed — try again.');
        },
      });
  }

  /** 401: best-effort server logout, always clear the UI session, then go to /login. */
  private handleUnauthorized(): void {
    this.auth.logout().subscribe({
      complete: () => void this.router.navigate(['/login']),
      error: () => void this.router.navigate(['/login']),
    });
  }

  onCopy(): void {
    this.copied.set(true);
    setTimeout(() => this.copied.set(false), 2000);
  }
}
