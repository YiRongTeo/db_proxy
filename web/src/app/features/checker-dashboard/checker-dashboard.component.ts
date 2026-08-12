import {
  Component,
  computed,
  effect,
  ElementRef,
  inject,
  OnDestroy,
  OnInit,
  signal,
  viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NzAlertModule } from 'ng-zorro-antd/alert';
import { NzButtonModule } from 'ng-zorro-antd/button';
import { NzCardModule } from 'ng-zorro-antd/card';
import { NzInputModule } from 'ng-zorro-antd/input';
import { NzMessageService } from 'ng-zorro-antd/message';
import { NzPopconfirmModule } from 'ng-zorro-antd/popconfirm';
import { NzSelectModule } from 'ng-zorro-antd/select';
import { NzSwitchModule } from 'ng-zorro-antd/switch';
import { NzTableModule } from 'ng-zorro-antd/table';
import { NzTagModule } from 'ng-zorro-antd/tag';
import { NzTooltipModule } from 'ng-zorro-antd/tooltip';
import { ApiService, QueryEvent, SessionInfo } from '../../core/api.service';
import { LiveQueryService } from '../../core/live-query.service';

/** Kind → nz-tag color mapping (brief 2.8: query=blue, prepare=purple, execute=orange, use=cyan). */
const KIND_COLORS: Record<string, string> = {
  query: 'blue',
  prepare: 'purple',
  execute: 'orange',
  use: 'cyan',
};

/** stmt_type → nz-tag color (Task 6.7: select=blue, insert=green, update=orange, delete=red, other=default). */
const STMT_COLORS: Record<string, string> = {
  select: 'blue',
  insert: 'green',
  update: 'orange',
  delete: 'red',
};

/** One dynamic column of the read-only output table. */
export interface OutputColumn {
  title: string;
  key: string;
}

/**
 * Checker Dashboard: live query feed over /ws/checker.
 * Auto-connects to the `*` channel on init; the operator can switch to a
 * single username channel, stop/reconnect, and toggle auto-scroll. The
 * LiveQueryService ring buffer (cap 500) backs the nz-table.
 *
 * Phase 6 (Task 6.7): each row shows the wire kind + stmt_type tags, a run
 * status tag (ok/error with the error message as tooltip), an expandable
 * READ-ONLY result table (columns from event.columns, cells as plain text),
 * and a kill button (nz-popconfirm → POST /api/kill) for live sessions.
 */
@Component({
  selector: 'app-checker-dashboard',
  standalone: true,
  imports: [
    FormsModule,
    NzAlertModule,
    NzButtonModule,
    NzCardModule,
    NzInputModule,
    NzPopconfirmModule,
    NzSelectModule,
    NzSwitchModule,
    NzTableModule,
    NzTagModule,
    NzTooltipModule,
  ],
  templateUrl: './checker-dashboard.component.html',
  styleUrl: './checker-dashboard.component.scss',
})
export class CheckerDashboardComponent implements OnInit, OnDestroy {
  private readonly live = inject(LiveQueryService);
  private readonly api = inject(ApiService);
  private readonly message = inject(NzMessageService);
  private readonly scrollHost = viewChild.required<ElementRef<HTMLDivElement>>('scrollHost');

  readonly channel = signal('*');
  readonly autoScroll = signal(true);

  readonly events = this.live.events;
  readonly connected = this.live.connected;

  /** Event id whose output table is expanded (single-row expansion). */
  readonly expanded = signal<string | null>(null);

  /** Event id → killed (connection kill accepted by the control plane). */
  readonly killed = signal<Record<string, boolean>>({});

  /** Live data-plane session directory (Task 8.4) backing the session selector. */
  readonly sessions = signal<SessionInfo[]>([]);

  /** Selector value: '*' = live (all); anything else = a data-plane session id. */
  readonly selectedSession = signal<string>('*');

  /** The selected session record (null while '*' or after the session left the directory). */
  readonly selectedSessionInfo = computed(
    () => this.sessions().find((s) => s.session_id === this.selectedSession()) ?? null,
  );

  /** Lifecycle event ids already folded into the directory refresh (idempotency). */
  private readonly seenLifecycle = new Set<string>();

  constructor() {
    // Auto-scroll: whenever the ring buffer grows (or the toggle flips on),
    // pin the viewport to the newest row.
    effect(() => {
      const count = this.live.events().length;
      if (this.autoScroll() && count > 0) {
        this.scrollToBottom();
      }
    });
    // Task 8.5: keep the session selector in sync with kind=session lifecycle
    // events (action started/ended). The directory is re-pulled from the API
    // so last_seen stays fresh; each lifecycle event is folded in exactly once.
    effect(() => {
      for (const ev of this.live.events()) {
        if (ev.kind !== 'session' || !ev.action || !ev.session_id) continue;
        if (this.seenLifecycle.has(ev.id)) continue;
        this.seenLifecycle.add(ev.id);
        this.refreshSessions();
      }
    });
  }

  ngOnInit(): void {
    this.refreshSessions();
    this.connect();
  }

  connect(): void {
    this.live.connect(this.channel().trim() || '*');
  }

  stop(): void {
    this.live.disconnect();
  }

  /** Re-pull the session directory from /api/sessions (init + lifecycle events). */
  refreshSessions(): void {
    this.api.sessions().subscribe({
      next: (list) => this.sessions.set(list),
      error: () => undefined, // keep the last known directory; the selector stays usable
    });
  }

  /** Selector change: '*' keeps the all-queries pattern; a session narrows the feed to sess:<sid>. */
  onSessionSelect(sid: string): void {
    this.selectedSession.set(sid);
    this.channel.set(sid === '*' ? '*' : `sess:${sid}`);
    this.connect();
  }

  /** Selector label: username · db_user · db · session_id (sid display truncated to 12 chars). */
  sessionLabel(s: SessionInfo): string {
    return `${s.username} · ${s.db_user} · ${s.db} · ${this.shortenSid(s.session_id)}`;
  }

  /** Truncate a session id for display (the full id stays in the option value). */
  shortenSid(sid: string): string {
    return sid.length <= 12 ? sid : `${sid.slice(0, 12)}…`;
  }

  kindColor(kind: string): string {
    return KIND_COLORS[kind] ?? 'default';
  }

  /** stmt_type tag color — case-insensitive, unknown/absent → default. */
  stmtColor(stmt: string | undefined): string {
    return (stmt && STMT_COLORS[stmt.toLowerCase()]) ?? 'default';
  }

  /** "db_user@db_ip:db_port" — the resolved target the token mapped to. Lifecycle events carry no db_ip/db_port → dash. */
  target(ev: QueryEvent): string {
    return ev.db_ip ? `${ev.db_user}@${ev.db_ip}:${ev.db_port}` : '—';
  }

  /** The output table is available when the event carries columns and/or rows. */
  hasOutput(ev: QueryEvent): boolean {
    return (ev.columns?.length ?? 0) > 0 || (ev.rows?.length ?? 0) > 0;
  }

  toggleOutput(ev: QueryEvent): void {
    this.expanded.set(this.expanded() === ev.id ? null : ev.id);
  }

  /**
   * Dynamic headers for the read-only output table. Uses event.columns when
   * present; otherwise the documented PG extended-protocol fallback: a single
   * "value" column when rows are single-field, or cell-index headers when rows
   * carry multiple fields with no column names.
   */
  outputColumns(ev: QueryEvent): OutputColumn[] {
    const cols = ev.columns ?? [];
    if (cols.length > 0) return cols.map((c, i) => ({ title: c, key: `c${i}` }));
    const width = (ev.rows ?? []).reduce((m, r) => Math.max(m, r.length), 0);
    if (width <= 1) return [{ title: 'value', key: 'c0' }];
    return Array.from({ length: width }, (_, i) => ({ title: String(i), key: `c${i}` }));
  }

  /** Rows re-mapped to {c0, c1, …} objects so cells render as plain text (read-only by construction). */
  outputRows(ev: QueryEvent): Record<string, string>[] {
    return (ev.rows ?? []).map((r) => Object.fromEntries(r.map((cell, i) => [`c${i}`, cell])));
  }

  /**
   * Popconfirm confirm handler: POST /api/kill with the requested mode.
   * mode=connection marks the row killed on 202 (the backend session is
   * gone); mode=query only aborts the in-flight query — the row stays live
   * and the operator sees a "query kill dispatched" confirmation.
   */
  kill(ev: QueryEvent, mode: 'query' | 'connection'): void {
    if (!ev.session_id) return;
    this.api.killSession(ev.session_id, mode).subscribe({
      next: () => {
        if (mode === 'connection') {
          this.killed.update((m) => ({ ...m, [ev.id]: true }));
          this.message.success(`kill queued for session ${ev.session_id}`);
        } else {
          this.message.success(`query kill dispatched for session ${ev.session_id}`);
        }
      },
      error: (err: { status?: number }) => {
        const detail = err?.status ? `HTTP ${err.status}` : 'network error';
        this.message.error(`kill failed for session ${ev.session_id}: ${detail}`);
      },
    });
  }

  private scrollToBottom(): void {
    // Defer past change detection so the new rows are in the DOM.
    setTimeout(() => {
      const el = this.scrollHost().nativeElement;
      el.scrollTop = el.scrollHeight;
    });
  }

  ngOnDestroy(): void {
    this.live.disconnect(); // no leaks: drop the WebSocket on navigation away
  }
}
