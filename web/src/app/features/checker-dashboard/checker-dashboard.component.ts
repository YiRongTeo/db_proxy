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
 * The checker's ACCURATE relation to the live feed (Task 8.15):
 * - 'live-feed':     WS open, watching all channels (live-all mode).
 * - 'watching':      WS open, a session is selected and its feed is active.
 * - 'disconnected':  WS closed/errored (or still connecting).
 * - 'session-ended': WS open, watching a session whose ended event arrived.
 */
export type FeedStatus = 'live-feed' | 'watching' | 'disconnected' | 'session-ended';

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
 *
 * Task 8.15 (checker UX): the status tag is DERIVED from the real socket
 * state (LiveQueryService.connectState — not the optimistic `connected`
 * flag) + the selected session + session-ended lifecycle events. Connection
 * kills move to ONE toolbar button acting on the selected session; rows keep
 * only kill-query. In session mode a context strip above the table carries
 * the session's constant fields and the table drops its constant columns so
 * SQL gets the width.
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
  /** Legacy optimistic socket flag — keeps the Connect/Stop toggle behavior. */
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

  /** True while watching a session whose action=ended event has arrived (Task 8.15). */
  readonly sessionEnded = signal(false);

  /**
   * Accurate feed status (Task 8.15): derived from the REAL socket state
   * (connectState — openObserver-driven, generation-guarded) rather than the
   * optimistic `connected` flag, which went stale on stop-during-handshake
   * (rxjs 7.8 complete() no-op pre-open) and on channel switches (a late
   * complete/error from the superseded socket flipped the shared flag).
   */
  readonly feedStatus = computed<FeedStatus>(() => {
    if (this.live.connectState() !== 'open') return 'disconnected';
    if (this.selectedSession() !== '*') {
      return this.sessionEnded() ? 'session-ended' : 'watching';
    }
    return 'live-feed';
  });

  /** Status tag text: "live feed", "watching sid · username", "session ended", "disconnected". */
  readonly statusLabel = computed(() => {
    switch (this.feedStatus()) {
      case 'live-feed':
        return 'live feed';
      case 'watching':
        return `watching ${this.shortenSid(this.selectedSession())} · ${this.selectedSessionInfo()?.username ?? '—'}`;
      case 'session-ended':
        return 'session ended';
      default:
        return 'disconnected';
    }
  });

  /** Status tag color: success while the feed relation is live, red on session-ended, error otherwise. */
  readonly statusColor = computed(() => {
    switch (this.feedStatus()) {
      case 'session-ended':
        return 'red';
      case 'disconnected':
        return 'error';
      default:
        return 'success';
    }
  });

  /**
   * Session context strip data (Task 8.15): the selected session's constant
   * fields, merged from the directory record (selectedSessionInfo/pending
   * overrides) and the first feed event for that session — lifecycle events
   * carry no target address and ticket_id only appears on query events, so
   * the event fills those gaps. Null in live-all mode.
   */
  readonly sessionContext = computed(() => {
    if (this.selectedSession() === '*') return null;
    const sid = this.selectedSession();
    const info = this.selectedSessionInfo();
    const first = this.live.events().find((e) => e.session_id === sid) ?? null;
    return {
      sid,
      sidShort: this.shortenSid(sid),
      username: info?.username ?? first?.username ?? '—',
      db: info?.db ?? first?.db ?? '—',
      dbType: info?.db_type ?? first?.db_type ?? '—',
      target: first ? this.target(first) : '—',
      ticket: first?.ticket_id ?? '—',
    };
  });

  /** Table colspan: 10 columns in live-all mode, 6 in session mode (constant columns removed). */
  readonly tableColspan = computed(() => (this.selectedSession() === '*' ? 10 : 6));

  /** Lifecycle event ids already folded into the directory refresh (idempotency). */
  private readonly seenLifecycle = new Set<string>();

  /**
   * Optimistic "waiting for maker" entries folded in from action=issued
   * lifecycle events (Task 8.12). A token becomes a visible session the
   * moment it is issued — BEFORE the maker ever connects — so the checker
   * can select it and arm the gate (subscribe to sess:<sid>) ahead of the
   * connection; the /api/sessions re-pull then overlays the authoritative
   * record on top. Removed on started/ended.
   */
  private readonly pendingOverrides = new Map<string, SessionInfo>();

  constructor() {
    // Auto-scroll: whenever the ring buffer grows (or the toggle flips on),
    // pin the viewport to the newest row.
    effect(() => {
      const count = this.live.events().length;
      if (this.autoScroll() && count > 0) {
        this.scrollToBottom();
      }
    });
    // Task 8.5/8.12: keep the session selector in sync with kind=session
    // lifecycle events (actions issued/started/ended — issued comes from the
    // control plane at token-issue time). The directory is re-pulled from the
    // API so last_seen stays fresh; each lifecycle event is folded in exactly
    // once. issued additionally folds in an optimistic "waiting" entry so the
    // gate can be armed before the maker connects (gating-deadlock fix 8.11).
    effect(() => {
      for (const ev of this.live.events()) {
        if (ev.kind !== 'session' || !ev.action || !ev.session_id) continue;
        if (this.seenLifecycle.has(ev.id)) continue;
        this.seenLifecycle.add(ev.id);
        this.applyLifecycle(ev);
      }
    });
  }

  /**
   * Fold one unseen session lifecycle event into the selector directory.
   * issued → optimistic pending entry (waiting for maker); started → the
   * pending override is dropped (the data plane record is active now);
   * ended → override dropped and the directory re-pull removes the session.
   * An ended event for the SELECTED session flips the derived status to
   * 'session-ended' (Task 8.15); started/issued for it clear that state.
   */
  private applyLifecycle(ev: QueryEvent): void {
    const sid = ev.session_id!;
    if (ev.action === 'issued') {
      this.pendingOverrides.set(sid, this.pendingSession(ev));
    } else if (ev.action === 'started' || ev.action === 'ended') {
      this.pendingOverrides.delete(sid);
    }
    if (sid === this.selectedSession()) {
      this.sessionEnded.set(ev.action === 'ended');
    }
    this.refreshSessions();
  }

  /** A minimal pending directory entry derived from an action=issued event. */
  private pendingSession(ev: QueryEvent): SessionInfo {
    return {
      session_id: ev.session_id!,
      username: ev.username,
      db_user: ev.db_user,
      db_type: ev.db_type,
      db: ev.db ?? '',
      started_at: ev.ts,
      last_seen: ev.ts,
      status: 'pending',
    };
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

  /**
   * Re-pull the session directory from /api/sessions (init + lifecycle events).
   * The authoritative API list is overlaid with optimistic pending entries
   * (action=issued) that the API may not have picked up yet, so a just-issued
   * session stays selectable — and the gate arming — even if the re-pull
   * races the control plane's record write (Task 8.12).
   */
  refreshSessions(): void {
    this.api.sessions().subscribe({
      next: (list) => {
        const byId = new Map(list.map((s) => [s.session_id, s]));
        for (const [sid, pending] of this.pendingOverrides) {
          if (!byId.has(sid)) byId.set(sid, pending);
        }
        this.sessions.set(Array.from(byId.values()));
      },
      error: () => undefined, // keep the last known directory; the selector stays usable
    });
  }

  /** Selector change: '*' keeps the all-queries pattern; a session narrows the feed to sess:<sid>. */
  onSessionSelect(sid: string): void {
    this.selectedSession.set(sid);
    // Re-watching: 'session-ended' only re-triggers on a fresh ended event
    // for the selected session (Task 8.15).
    this.sessionEnded.set(false);
    this.channel.set(sid === '*' ? '*' : `sess:${sid}`);
    this.connect();
  }

  /**
   * Selector label: username · db_user · db · session_id (sid display
   * truncated to 12 chars). Pending records carry no target db at issue
   * time (Task 8.11) → rendered as a dash; the waiting badge itself is a
   * separate nz-tag in the option template (see isPending).
   */
  sessionLabel(s: SessionInfo): string {
    return `${s.username} · ${s.db_user} · ${s.db || '—'} · ${this.shortenSid(s.session_id)}`;
  }

  /** True while the token is issued but the maker has not connected yet (Task 8.12). */
  isPending(s: SessionInfo): boolean {
    return s.status === 'pending';
  }

  /** Session lifecycle action tag color: issued=gold (waiting), started=green, ended=red. */
  actionColor(action: string | undefined): string {
    if (action === 'started') return 'green';
    if (action === 'issued') return 'gold';
    return 'red';
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
   * Per-row popconfirm confirm handler (Task 8.15): POST /api/kill with
   * mode=query only — connection kills moved to the toolbar button acting on
   * the selected session. A query kill aborts the in-flight query; the row
   * stays live and the operator sees a "query kill dispatched" confirmation.
   */
  killQuery(ev: QueryEvent): void {
    if (!ev.session_id) return;
    this.api.killSession(ev.session_id, 'query').subscribe({
      next: () => {
        this.message.success(`query kill dispatched for session ${ev.session_id}`);
      },
      error: (err: { status?: number }) => {
        const detail = err?.status ? `HTTP ${err.status}` : 'network error';
        this.message.error(`kill failed for session ${ev.session_id}: ${detail}`);
      },
    });
  }

  /**
   * Toolbar kill-connection (Task 8.15): POST /api/kill with mode=connection
   * for the SELECTED session. On 202 every buffered row of that session is
   * marked killed (red tag + disabled) — the connection is gone, so its rows
   * are dead too.
   */
  killSelectedConnection(): void {
    const sid = this.selectedSession();
    if (sid === '*') return;
    this.api.killSession(sid, 'connection').subscribe({
      next: () => {
        this.killed.update((m) => {
          const next = { ...m };
          for (const ev of this.live.events()) {
            if (ev.session_id === sid) next[ev.id] = true;
          }
          return next;
        });
        this.message.success(`kill queued for session ${sid}`);
      },
      error: (err: { status?: number }) => {
        const detail = err?.status ? `HTTP ${err.status}` : 'network error';
        this.message.error(`kill failed for session ${sid}: ${detail}`);
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
