package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"zerotrust-proxy/internal/models"
)

// Watch presence (Task 8.6 maker write-gating): while a checker is
// subscribed to a session's own channel (channel=sess:<sid>) the hub keeps
// a presence lease alive in Valkey — that presence is what the data plane's
// write gate probes (WatchActive, EXISTS-any) before relaying SQL on
// write-access maker sessions.
//
// Task 9.9 review remediation (CRITICAL b): presence is REFERENCE-COUNTED
// PER CONNECTION. Each connection holds its OWN lease key
// watch:<sid>:<connid> — set on subscribe, heartbeat-refreshed while
// connected, deleted on disconnect. N checkers watching the same session
// are independent: the first disconnect deletes ONLY its own key, so the
// gate stays open while any other watcher holds a key. The lease has a TTL,
// so a crashed hub/checker cannot leave a stale "watched" state behind for
// more than the lease.
const (
	watchPresenceTTL    = 30 * time.Second // per-connection lease without heartbeats
	watchHeartbeatEvery = 10 * time.Second // hub refresh period while connected
	// watchWriteTimeout bounds each WS write: a stalled checker socket must
	// not pin the hub goroutine (or the pubsub reader) forever — the
	// connection is dropped instead (review 9.9 slow-consumer policy).
	watchWriteTimeout = 10 * time.Second
)

// watchTTLOrDefault / watchHeartbeatOrDefault return the api's configured
// presence parameters, falling back to the production defaults when the
// fields are zero (tests shorten them via the api struct fields).
func (a *api) watchTTLOrDefault() time.Duration {
	if a.watchTTL > 0 {
		return a.watchTTL
	}
	return watchPresenceTTL
}

func (a *api) watchHeartbeatOrDefault() time.Duration {
	if a.watchHeartbeat > 0 {
		return a.watchHeartbeat
	}
	return watchHeartbeatEvery
}

// handleWS bridges Valkey Pub/Sub to a Checker's WebSocket.
// channel=alice → queries:alice ; channel=ticket:TICKET-1 → queries:ticket:TICKET-1 ;
// channel=* or empty → pattern queries:* (all queries).
// channel=sess:<sid> (Task 8.6) additionally marks the session WATCHED for
// the maker write-gate: this connection's per-connection lease
// watch:<sid>:<connid> is set with a presence TTL and heartbeat-refreshed
// until the checker disconnects (or reconnects to another channel — the
// checker UI switches channels by reconnecting, so this connection's
// disconnect defer removes exactly the key it held).
func (a *api) handleWS(w http.ResponseWriter, r *http.Request) {
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		channel = "*"
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Task 8.6 watch presence: channel sess:<sid> → this connection's lease
	// watch:<sid>:<connid>. A malformed channel (empty session id, or a sid
	// with whitespace) holds NO key. Task 9.7 audit: on attach the hub ALSO
	// records the checker's username (from the WS session) in the audit row
	// — the Data Plane never learns it.
	watchSid := ""
	connID := ""
	if strings.HasPrefix(channel, "sess:") {
		if sid := strings.TrimPrefix(channel, "sess:"); sid != "" && !strings.ContainsAny(sid, " \t\r\n") {
			watchSid = sid
			connID = models.NewEventID() // per-connection presence identity
		}
	}
	if watchSid != "" {
		// Separation of duties (user directive 2026-08-17): the checker
		// arming the write-gate presence for a session must NOT be the
		// session's maker. The sess:live:<sid> record (written at TOKEN
		// ISSUE by the control plane, overwritten by the data plane) names
		// the maker; the WS session names the checker. Same user → the
		// connection is closed with a policy violation and NO lease is
		// set — the maker can never open their own write gate. A session
		// whose record is missing/expired is treated as non-existent
		// (fail-closed): no lease either.
		if err := a.checkerMayWatch(r, watchSid); err != nil {
			a.log.Warn("watch rejected", "session_id", watchSid, "reason", err.Error())
			_ = c.Close(websocket.StatusPolicyViolation, "cannot watch this session")
			return
		}
		if sess := sessionFrom(r); sess != nil {
			a.auditChecker(r.Context(), watchSid, sess.Username)
		}
		if err := a.vs.SetWatchConn(ctx, watchSid, connID, a.watchTTLOrDefault()); err != nil {
			a.log.Warn("watch set failed", "session_id", watchSid, "err", err)
		}
		// Heartbeat: refresh THIS connection's presence lease while the
		// checker stays connected. The connection's channel is fixed at
		// subscribe time, so the refresh target never changes — a channel
		// switch is a reconnect, whose disconnect defer removes exactly
		// the key this connection held.
		//
		// Review 9.9 heartbeat resurrect race: the refresh goroutine and the
		// disconnect defer both touch the lease key. mu serializes them —
		// once disconnected is set (under mu) the refresh loop stops, so a
		// refresh can never land AFTER the disconnect's delete and
		// resurrect the key.
		var mu sync.Mutex
		disconnected := false
		go func() {
			t := time.NewTicker(a.watchHeartbeatOrDefault())
			defer t.Stop()
			for {
				select {
				case <-t.C:
					mu.Lock()
					if disconnected {
						mu.Unlock()
						return
					}
					err := a.vs.SetWatchConn(ctx, watchSid, connID, a.watchTTLOrDefault())
					mu.Unlock()
					if err != nil {
						a.log.Warn("watch refresh failed", "session_id", watchSid, "err", err)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		defer func() {
			mu.Lock()
			disconnected = true
			cancel() // stop the read loop, write loop and refresh loop
			err := a.vs.WatchRemoveConn(context.Background(), watchSid, connID)
			mu.Unlock()
			if err != nil {
				a.log.Warn("watch clear failed", "session_id", watchSid, "err", err)
			}
			// Task 9.7 audit: watcher gone → checker_username = NULL
			// (mirrors this connection's lease deletion).
			a.auditChecker(context.Background(), watchSid, "")
		}()
	}

	// Read loop: the hub never expects client messages, but reading is how a
	// disconnected client is DETECTED — Read returns an error the moment the
	// peer closes (or the connection breaks), cancelling ctx so the write
	// loop exits and the watch defer above runs. Without it a dead client
	// would pin this goroutine AND leave its watch lease until TTL expiry.
	go func() {
		defer cancel()
		for {
			if _, _, err := c.Read(ctx); err != nil {
				return
			}
		}
	}()

	key := "queries:" + channel
	pattern := channel == "*"
	out := make(chan []byte, 256)
	// Review 9.9 one-shot subscribe: a transient pubsub failure must not
	// silently end the checker's stream — resubscribe with exponential
	// backoff until the connection closes (subscribeLoop).
	go a.subscribeLoop(ctx, key, pattern, out)

	// keepalive ping
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = c.Ping(ctx)
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case m := <-out:
			// Review 9.9 slow-consumer write deadline: each message gets a
			// bounded write window — a stalled checker socket is dropped
			// (connection closed) instead of pinning the hub forever.
			// Dropped pubsub messages (non-blocking send in store.Subscribe)
			// are the accepted cost for a stuck consumer.
			wctx, wcancel := context.WithTimeout(ctx, watchWriteTimeout)
			err := c.Write(wctx, websocket.MessageText, m)
			wcancel()
			if err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// subscribeLoop keeps a subscription alive: Subscribe blocks for the life
// of the subscription and returns when it ends; a transient failure must
// not end the stream silently, so the loop resubscribes with exponential
// backoff until ctx is cancelled (review 9.9 one-shot subscribe). Messages
// published during a resubscribe gap are lost — these are live events only,
// and audit lifecycle gaps are healed by the pending-audit sweeper.
func (a *api) subscribeLoop(ctx context.Context, key string, pattern bool, out chan<- []byte) {
	backoff := 100 * time.Millisecond
	const maxBackoff = 2 * time.Second
	for {
		err := a.vs.Subscribe(ctx, key, pattern, out)
		if ctx.Err() != nil {
			return
		}
		a.log.Warn("subscribe ended; resubscribing", "channel", key, "err", err)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// checkerMayWatch enforces separation of duties between the checker and
// the maker (user directive 2026-08-17): the user opening a per-session
// watch (channel=sess:<sid>) must not be the session's maker. The maker is
// read from the sess:live:<sid> directory record — the same record the
// sessions list renders — written at TOKEN ISSUE by the control plane
// (pending) and overwritten by the data plane (active); both shapes carry
// `username`. Refusals (returned error) cover three cases, all fail-closed:
// no session identity (unreachable — /ws/checker is session-required), a
// missing/expired/unreadable record (the session is not watchable), and
// checker == maker. The caller closes the WebSocket with a policy-violation
// close and arms NO presence lease, so the write gate stays closed.
func (a *api) checkerMayWatch(r *http.Request, sid string) error {
	checker := sessionFrom(r)
	if checker == nil {
		return errors.New("unauthenticated checker") // unreachable: /ws/checker is session-required
	}
	raw, err := a.vs.GetSessionLive(r.Context(), sid)
	if err != nil {
		return fmt.Errorf("session lookup failed: %w", err)
	}
	if raw == nil {
		return fmt.Errorf("session %s not found", sid)
	}
	var rec pendingSessionRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return fmt.Errorf("session record unreadable: %w", err)
	}
	if rec.Username == checker.Username {
		return fmt.Errorf("checker %q is the maker of session %s", checker.Username, sid)
	}
	return nil
}
