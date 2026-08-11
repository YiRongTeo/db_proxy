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
import { NzButtonModule } from 'ng-zorro-antd/button';
import { NzCardModule } from 'ng-zorro-antd/card';
import { NzInputModule } from 'ng-zorro-antd/input';
import { NzSwitchModule } from 'ng-zorro-antd/switch';
import { NzTableModule } from 'ng-zorro-antd/table';
import { NzTagModule } from 'ng-zorro-antd/tag';
import { QueryEvent } from '../../core/api.service';
import { LiveQueryService } from '../../core/live-query.service';

/** Kind → nz-tag color mapping (brief 2.8: query=blue, prepare=purple, execute=orange, use=cyan). */
const KIND_COLORS: Record<string, string> = {
  query: 'blue',
  prepare: 'purple',
  execute: 'orange',
  use: 'cyan',
};

/**
 * Checker Dashboard: live query feed over /ws/checker.
 * Auto-connects to the `*` channel on init; the operator can switch to a
 * single username channel, stop/reconnect, and toggle auto-scroll. The
 * LiveQueryService ring buffer (cap 500) backs the nz-table.
 */
@Component({
  selector: 'app-checker-dashboard',
  standalone: true,
  imports: [
    FormsModule,
    NzButtonModule,
    NzCardModule,
    NzInputModule,
    NzSwitchModule,
    NzTableModule,
    NzTagModule,
  ],
  templateUrl: './checker-dashboard.component.html',
  styleUrl: './checker-dashboard.component.scss',
})
export class CheckerDashboardComponent implements OnInit, OnDestroy {
  private readonly live = inject(LiveQueryService);
  private readonly scrollHost = viewChild.required<ElementRef<HTMLDivElement>>('scrollHost');

  readonly channel = signal('*');
  readonly autoScroll = signal(true);

  readonly events = this.live.events;
  readonly connected = this.live.connected;

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

  /** "db_user@db_ip:db_port" — the resolved target the token mapped to. */
  target(ev: QueryEvent): string {
    return `${ev.db_user}@${ev.db_ip}:${ev.db_port}`;
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
