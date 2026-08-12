package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
)

// Watch presence (Task 8.6 maker write-gating): while a checker is
// subscribed to a session's own channel (channel=sess:<sid>) the hub keeps
// watch:<sid> alive in Valkey — that presence key is what the data plane's
// write gate probes (EXISTS watch:<sid>) before relaying SQL on write-access
// maker sessions. The lease is set with a TTL and heartbeat-refreshed while
// the checker stays connected, so a crashed hub/checker cannot leave a stale
// "watched" state behind for more than the lease.
const (
	watchPresenceTTL    = 30 * time.Second // watch:<sid> lease without heartbeats
	watchHeartbeatEvery = 10 * time.Second // hub refresh period while connected
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
// the maker write-gate: watch:<sid> is set with a presence lease and
// heartbeat-refreshed until the checker disconnects (or reconnects to
// another channel — the checker UI switches channels by reconnecting, so
// this connection's disconnect defer clears exactly the key it held).
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

	// Task 8.6 watch presence: channel sess:<sid> → watch:<sid>. A malformed
	// channel (empty session id, or a sid with whitespace) holds NO key.
	watchSid := ""
	if strings.HasPrefix(channel, "sess:") {
		if sid := strings.TrimPrefix(channel, "sess:"); sid != "" && !strings.ContainsAny(sid, " \t\r\n") {
			watchSid = sid
		}
	}
	if watchSid != "" {
		if err := a.vs.SetWatch(ctx, watchSid, a.watchTTLOrDefault()); err != nil {
			a.log.Warn("watch set failed", "session_id", watchSid, "err", err)
		}
		// Heartbeat: refresh the presence lease while this checker stays
		// connected to the session's channel. The connection's channel is
		// fixed at subscribe time, so the refresh target never changes —
		// a channel switch is a reconnect, whose disconnect defer clears
		// the old key.
		go func() {
			t := time.NewTicker(a.watchHeartbeatOrDefault())
			defer t.Stop()
			for {
				select {
				case <-t.C:
					if err := a.vs.SetWatch(ctx, watchSid, a.watchTTLOrDefault()); err != nil {
						a.log.Warn("watch refresh failed", "session_id", watchSid, "err", err)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		defer func() {
			if err := a.vs.DelWatch(context.Background(), watchSid); err != nil {
				a.log.Warn("watch clear failed", "session_id", watchSid, "err", err)
			}
		}()
	}

	// Read loop: the hub never expects client messages, but reading is how a
	// disconnected client is DETECTED — Read returns an error the moment the
	// peer closes (or the connection breaks), cancelling ctx so the write
	// loop exits and the watch defer above runs. Without it a dead client
	// would pin this goroutine AND leave watch:<sid> set until TTL expiry.
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
	go func() {
		if err := a.vs.Subscribe(ctx, key, pattern, out); err != nil && ctx.Err() == nil {
			a.log.Warn("subscribe ended", "channel", key, "err", err)
		}
	}()

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
			if err := c.Write(ctx, websocket.MessageText, m); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}
