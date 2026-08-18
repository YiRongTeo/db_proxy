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
import { Router } from '@angular/router';
import { NzAlertModule } from 'ng-zorro-antd/alert';
import { NzButtonModule } from 'ng-zorro-antd/button';
import { NzCardModule } from 'ng-zorro-antd/card';
import { NzGridModule } from 'ng-zorro-antd/grid';
import { NzInputModule } from 'ng-zorro-antd/input';
import { NzMessageService } from 'ng-zorro-antd/message';
import { NzPopconfirmModule } from 'ng-zorro-antd/popconfirm';
import { NzSelectModule } from 'ng-zorro-antd/select';
import { NzSwitchModule } from 'ng-zorro-antd/switch';
import { NzTableModule } from 'ng-zorro-antd/table';
import { NzTagModule } from 'ng-zorro-antd/tag';
import { NzTooltipModule } from 'ng-zorro-antd/tooltip';
import { ApiService, QueryEvent, SessionInfo } from '../../core/api.service';
import { AuthService } from '../../core/auth.service';
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
 * Task 9.11 hardening constants:
 * - Lifecycle-event ids are folded into the selector exactly once; the seen
 *   set is capped so a long-lived dashboard cannot grow it unboundedly.
 * - The killed map (rows marked dead by connection kill / session end) is
 *   capped the same way; entries for events that already left the ring
 *   buffer are dropped first (they are gone from the table anyway).
 * - Optimistic pending overrides (action=issued) are pruned when the
 *   /api/sessions list misses them for PENDING_MAX_MISSES consecutive pulls
 *   (the control plane never recorded the issue) or once they outlive the
 *   token TTL (PENDING_MAX_AGE_MS — generous backstop over the 5 min default).
 */
const MAX_SEEN_LIFECYCLE = 1000;
const MAX_KILLED = 1000;
const PENDING_MAX_MISSES = 3;
const PENDING_MAX_AGE_MS = 10 * 60 * 1000; // token TTL default is 5 min
const REFRESH_DEBOUNCE_MS = 200; // lifecycle bursts → one directory re-pull

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
    NzGridModule,
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
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly message = inject(NzMessageService);
  private readonly scrollHost = viewChild.required<ElementRef<HTMLDivElement>>('scrollHost');

  readonly channel = signal('*');
  readonly autoScroll = signal(true);

  readonly events = this.live.events;

  /** Event id whose output table is expanded (single-row expansion). */
  readonly expanded = signal<string | null>(null);

  /** Event id → killed (connection kill accepted or the session ended over the WS). */
  readonly killed = signal<Record<string, boolean>>({});

  /** Live data-plane session directory (Task 8.4) backing the session selector. */
  readonly sessions = signal<SessionInfo[]>([]);

  /** Selector value: '*' = live (all); anything else = a data-plane session id. */
  readonly selectedSession = signal<string>('*');

  /** The selected session record (null while '*' or after the session left the directory). */
  readonly selectedSessionInfo = computed(
    () => this.sessions().find((s) => s.session_id === this.selectedSession()) ?? null,
  );

  /**
   * Rows for the current mode (Task 9.11 — review CRITICAL 9.11a): session
   * mode shows ONLY the selected session's events. Before this the session
   * table rendered the whole ring buffer, so buffered rows of OTHER sessions
   * appeared under the selected session (misattribution).
   */
  readonly visibleEvents = computed(() => {
    const sid = this.selectedSession();
    if (sid === '*') return this.live.events();
    return this.live.events().filter((e) => e.session_id === sid);
  });

  /** True while the REAL socket is open (drives Connect/Stop + channel lockout). */
  readonly feedOpen = computed(() => this.live.connectState() === 'open');

  /** True when the WebSocket dropped with an error (surfaced as a banner). */
  readonly wsError = computed(() => this.live.connectState() === 'error');

  /**
   * Server rejection detail (2026-08-17 separation of duties): when the
   * feed was closed with a 1008 policy-violation close (e.g. a maker trying
   * to watch their own session — the server refuses to arm the gate for
   * the maker), surface the server's reason instead of the generic
   * "connection lost" text. Null for every other close/error.
   */
  readonly feedErrorDetail = computed(() => {
    const lc = this.live.lastClose();
    if (!lc || lc.code !== 1008) return null;
    return lc.reason || 'the server rejected this feed';
  });

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

  /** Status tag text: "live feed", "watching sid · username", "session ended", "connection lost"/"disconnected". */
  readonly statusLabel = computed(() => {
    switch (this.feedStatus()) {
      case 'live-feed':
        return 'live feed';
      case 'watching':
        return `watching ${this.shortenSid(this.selectedSession())} · ${this.selectedSessionInfo()?.username ?? '—'}`;
      case 'session-ended':
        return 'session ended';
      default:
        // Task 9.11: surface the WS error distinctly from a clean disconnect.
        return this.live.connectState() === 'error' ? 'connection lost' : 'disconnected';
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

  /** Lifecycle event ids already folded into the directory refresh (idempotency; capped). */
  private readonly seenLifecycle = new Set<string>();

  /**
   * Optimistic "waiting for maker" entries folded in from action=issued
   * lifecycle events (Task 8.12). A token becomes a visible session the
   * moment it is issued — BEFORE the maker ever connects — so the checker
   * can select it and arm the gate (subscribe to sess:<sid>) ahead of the
   * connection; the /api/sessions re-pull then overlays the authoritative
   * record on top. Removed on started/ended — and pruned by Task 9.11 when
   * the API list keeps missing them (see pullSessions).
   */
  private readonly pendingOverrides = new Map<string, SessionInfo>();

  /** Consecutive API pulls that missed each pending override (Task 9.11 pruning). */
  private readonly pendingMisses = new Map<string, number>();

  /** Pending debounced directory re-pull (lifecycle bursts → one call). */
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;

  /** Memoized per-event derived data (events are immutable; the WeakMap dies with the event object). */
  private readonly columnsCache = new WeakMap<QueryEvent, OutputColumn[]>();
  private readonly rowsCache = new WeakMap<QueryEvent, Record<string, string>[]>();

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
        // Task 9.11: cap the seen-set (ring buffer is 500, so clearing at
        // 1000 only ever re-folds events that are already out of it).
        if (this.seenLifecycle.size >= MAX_SEEN_LIFECYCLE) this.seenLifecycle.clear();
        this.seenLifecycle.add(ev.id);
        this.applyLifecycle(ev);
      }
    });
  }

  /**
   * Fold one unseen session lifecycle event into the selector directory.
   * issued → optimistic pending entry (waiting for maker); started → the
   * pending override is dropped (the data plane record is active now);
   * ended → override dropped, the buffered rows of that session are marked
   * killed (Task 9.11 — the WS path must mark dead rows, not just the 202
   * toolbar path), and the directory re-pull removes the session.
   * An ended event for the SELECTED session flips the derived status to
   * 'session-ended' (Task 8.15); started/issued for it clear that state.
   */
  private applyLifecycle(ev: QueryEvent): void {
    const sid = ev.session_id!;
    if (ev.action === 'issued') {
      this.pendingOverrides.set(sid, this.pendingSession(ev));
    } else if (ev.action === 'started' || ev.action === 'ended') {
      this.pendingOverrides.delete(sid);
      if (ev.action === 'ended') {
        this.markSessionKilled(sid);
      }
    }
    if (sid === this.selectedSession()) {
      this.sessionEnded.set(ev.action === 'ended');
    }
    this.scheduleRefreshSessions();
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
    this.connect(); // pulls the session directory on the way in (Task 9.11)
  }

  connect(): void {
    this.live.connect(this.channel().trim() || '*');
    // Task 9.11: every (re)connect refreshes the session directory — sessions
    // may have appeared or ended while the feed was down, and the selector
    // must not keep stale entries.
    this.refreshSessions();
  }

  stop(): void {
    this.live.disconnect();
  }

  /**
   * Re-pull the session directory from /api/sessions (init + connect + test
   * seams). The authoritative API list is overlaid with optimistic pending
   * entries (action=issued) that the API may not have picked up yet, so a
   * just-issued session stays selectable — and the gate arming — even if the
   * re-pull races the control plane's record write (Task 8.12). A pending
   * entry that the API keeps missing is pruned (Task 9.11, see pullSessions).
   */
  refreshSessions(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    this.pullSessions();
  }

  /** Debounced directory re-pull for lifecycle-event bursts (Task 9.11). */
  private scheduleRefreshSessions(): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    this.refreshTimer = setTimeout(() => {
      this.refreshTimer = null;
      this.pullSessions();
    }, REFRESH_DEBOUNCE_MS);
  }

  private pullSessions(): void {
    this.api.sessions().subscribe({
      next: (list) => {
        const byId = new Map(list.map((s) => [s.session_id, s]));
        for (const [sid, pending] of this.pendingOverrides) {
          if (byId.has(sid)) {
            // The API record is authoritative — the override is not needed.
            this.pendingOverrides.delete(sid);
            this.pendingMisses.delete(sid);
            continue;
          }
          const ageMs = Date.now() - new Date(pending.started_at).getTime();
          const misses = (this.pendingMisses.get(sid) ?? 0) + 1;
          if (misses >= PENDING_MAX_MISSES || ageMs > PENDING_MAX_AGE_MS) {
            // Ghost: the control plane never recorded the issue (or the token
            // outlived its TTL without a connection) — stop showing it.
            this.pendingOverrides.delete(sid);
            this.pendingMisses.delete(sid);
            continue;
          }
          this.pendingMisses.set(sid, misses);
          byId.set(sid, pending);
        }
        this.sessions.set(Array.from(byId.values()));
      },
      error: (err: { status?: number }) => {
        if (err?.status === 401) {
          // Task 9.11: the session cookie expired — clear the UI session
          // FIRST, then send the user to /login. Without the logout the stale
          // user signal keeps the authGuard happy and the SPA loops on 401s.
          this.handleUnauthorized();
          return;
        }
        // keep the last known directory; the selector stays usable
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
   * Dynamic headers for the read-only output table (memoized per event
   * object — Task 9.11: the template calls this twice per row, and the
   * ring-buffer events are immutable). Uses event.columns when present;
   * otherwise the documented PG extended-protocol fallback: a single
   * "value" column when rows are single-field, or cell-index headers when
   * rows carry multiple fields with no column names.
   */
  outputColumns(ev: QueryEvent): OutputColumn[] {
    const cached = this.columnsCache.get(ev);
    if (cached) return cached;
    const cols = ev.columns ?? [];
    let result: OutputColumn[];
    if (cols.length > 0) {
      result = cols.map((c, i) => ({ title: c, key: `c${i}` }));
    } else {
      const width = (ev.rows ?? []).reduce((m, r) => Math.max(m, r.length), 0);
      result =
        width <= 1
          ? [{ title: 'value', key: 'c0' }]
          : Array.from({ length: width }, (_, i) => ({ title: String(i), key: `c${i}` }));
    }
    this.columnsCache.set(ev, result);
    return result;
  }

  /** Rows re-mapped to {c0, c1, …} objects (memoized, see outputColumns). */
  outputRows(ev: QueryEvent): Record<string, string>[] {
    const cached = this.rowsCache.get(ev);
    if (cached) return cached;
    const rows = (ev.rows ?? []).map((r) => Object.fromEntries(r.map((cell, i) => [`c${i}`, cell])));
    this.rowsCache.set(ev, rows);
    return rows;
  }

  /** Compact UTC clock time for the Ts cell (RFC3339 → HH:MM:SS). */
  formatTs(ts: string): string {
    if (!ts || Number.isNaN(Date.parse(ts))) return ts || '—';
    return new Date(ts).toISOString().slice(11, 19);
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
        this.markSessionKilled(sid);
        this.message.success(`kill queued for session ${sid}`);
      },
      error: (err: { status?: number }) => {
        const detail = err?.status ? `HTTP ${err.status}` : 'network error';
        this.message.error(`kill failed for session ${sid}: ${detail}`);
      },
    });
  }

  /**
   * Mark every buffered row of a session killed (Task 9.11 — shared by the
   * 202 toolbar path and the WS ended-event path). The killed map is capped:
   * once it outgrows MAX_KILLED, marks for events that already left the ring
   * buffer are dropped (they are gone from the table anyway), which always
   * brings it back under the cap because the buffer itself is ≤500.
   */
  private markSessionKilled(sid: string): void {
    this.killed.update((m) => {
      const next = { ...m };
      for (const ev of this.visibleEvents()) {
        if (ev.session_id === sid) next[ev.id] = true;
      }
      if (Object.keys(next).length <= MAX_KILLED) return next;
      const kept = new Set(this.live.events().map((e) => e.id));
      const capped: Record<string, boolean> = {};
      for (const id of Object.keys(next)) {
        if (kept.has(id)) capped[id] = true;
      }
      return capped;
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
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    this.live.disconnect(); // no leaks: drop the WebSocket on navigation away
  }
}
