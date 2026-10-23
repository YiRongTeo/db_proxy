package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
)

// --- Task 9: the re-lock CALLBACK (owner decision 3) --------------------------
//
// Reuse action "started" — NO new value: when the session re-locks, the
// same hold-start callback fires (the "joinable now" signal again). With
// re-lock on, a session can emit started MULTIPLE times (hold-start, each
// re-lock); ended exactly once. nil tok is SAFE (sidOf falls back to the
// session's directory id).

// relockCbRecorder captures the callback POSTs (mirrors callbackRecorder).
type relockCbRecorder struct {
	mu     sync.Mutex
	bodies []string
	paths  []string
}

func (r *relockCbRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body := make([]byte, 1024)
	n, _ := req.Body.Read(body)
	r.mu.Lock()
	r.bodies = append(r.bodies, string(body[:n]))
	r.paths = append(r.paths, req.URL.Path)
	r.mu.Unlock()
	w.WriteHeader(200)
}

func (r *relockCbRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bodies)
}

func (r *relockCbRecorder) last(t *testing.T) (path, body string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		t.Fatal("no callback recorded")
	}
	return r.paths[len(r.paths)-1], r.bodies[len(r.bodies)-1]
}

func waitRelockCb(t *testing.T, r *relockCbRecorder, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r.count() >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("callbacks = %d, want %d", r.count(), want)
}

// TestRelockFiresStartedCallback: HandleRelock on a live hold-admitted rw
// session fires the session-status callback action "started" — the same
// hold-start signal, no new action value. The tok is the session's (nil is
// safe via sidOf, but the relay retains tok so the authoritative id rides).
func TestRelockFiresStartedCallback(t *testing.T) {
	vs := proxyTestStore(t)
	rec := &relockCbRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()

	p := NewMySQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	cb, err := NewSessionCallbacks(slog.New(slog.NewTextHandler(io.Discard, nil)), srv.URL, time.Second, "", "127.0.0.1:9999")
	if err != nil {
		t.Fatalf("NewSessionCallbacks: %v", err)
	}
	p.SetSessionCallbacks(cb)

	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	defer func() { cpeer.Close(); bpeer.Close(); client.Close(); backend.Close() }()
	sid := "sid-relock-callback"
	s := &mysqlSession{id: sid, access: "rw", holdAdmitted: true, client: client, backend: backend,
		tok: &models.TokenPayload{Username: "relock-maker", DBUser: "rw_user", DBType: "mysql", SessionID: sid, Access: "rw"}}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() {
		p.unregisterSession(sid)
		_ = vs.DelSessionLive(context.Background(), sid)
	})
	p.registerSession(s)
	defer p.unregisterSession(s.id)

	if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
		t.Fatal("HandleRelock = false, want true")
	}
	waitRelockCb(t, rec, 1)
	path, body := rec.last(t)
	if path != "/dbpxy/session/"+sid+"/status" {
		t.Errorf("callback path = %q, want /dbpxy/session/%s/status", path, sid)
	}
	if !containsStr(body, `"action":"started"`) {
		t.Errorf("callback body = %s, want action=started (the hold-start signal reused)", body)
	}
	// Exactly ONE callback for the freeze — a second HandleRelock on the
	// already-frozen session fires nothing (idempotent).
	if p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
		t.Error("duplicate HandleRelock on a frozen session = true, want false (no second freeze/callback)")
	}
	time.Sleep(300 * time.Millisecond)
	if got := rec.count(); got != 1 {
		t.Errorf("callbacks = %d, want exactly 1 (the freeze transition only)", got)
	}
}

// containsStr is strings.Contains (kept local so this file needs no extra
// import beyond the test's own).
func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexStr(s, sub) >= 0)
}

func indexStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
