package api

import (
	"context"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// handleWS bridges Valkey Pub/Sub to a Checker's WebSocket.
// channel=alice → queries:alice ; channel=ticket:TICKET-1 → queries:ticket:TICKET-1 ;
// channel=* or empty → pattern queries:* (all queries).
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
