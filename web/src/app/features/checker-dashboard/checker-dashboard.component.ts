import {
  Component,
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
import { NzSwitchModule } from 'ng-zorro-antd/switch';
import { NzTableModule } from 'ng-zorro-antd/table';
import { NzTagModule } from 'ng-zorro-antd/tag';
import { NzTooltipModule } from 'ng-zorro-antd/tooltip';
import { ApiService, QueryEvent } from '../../core/api.service';
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

  /** Event id → killed (kill accepted by the control plane). */
  readonly killed = signal<Record<string, boolean>>({});

  constructor() {
    // Auto-scroll: whenever the ring buffer grows (or the toggle flips on),
    // pin the viewport to the newest row.
    effect(() => {
      const count = this.live.events().length;
      if (this.autoScroll() && count > 0) {
        this.scrollToBottom();
      }
    });
  }

  ngOnInit(): void {
    this.connect();
  }

  connect(): void {
    this.live.connect(this.channel().trim() || '*');
  }

  stop(): void {
    this.live.disconnect();
  }

  kindColor(kind: string): string {
    return KIND_COLORS[kind] ?? 'default';
  }

  /** stmt_type tag color — case-insensitive, unknown/absent → default. */
  stmtColor(stmt: string | undefined): string {
    return (stmt && STMT_COLORS[stmt.toLowerCase()]) ?? 'default';
  }

  /** "db_user@db_ip:db_port" — the resolved target the token mapped to. */
  target(ev: QueryEvent): string {
    return `${ev.db_user}@${ev.db_ip}:${ev.db_port}`;
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

  /** Popconfirm confirm handler: POST /api/kill, mark killed on 202. */
  kill(ev: QueryEvent): void {
    if (!ev.session_id) return;
    this.api.killSession(ev.session_id).subscribe({
      next: () => {
        this.killed.update((m) => ({ ...m, [ev.id]: true }));
        this.message.success(`kill queued for session ${ev.session_id}`);
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
