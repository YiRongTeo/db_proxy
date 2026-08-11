package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

// dialPair opens a real TCP pair on 127.0.0.1:0. net.Pipe cannot be used here:
// it has no deadlines, which decide() requires. Returns (server, client) conns;
// cleanup closes the listener and both conns.
func dialPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- c
	}()
	client, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case server = <-accepted:
		t.Cleanup(func() {
			ln.Close()
			client.Close()
			server.Close()
		})
		return server, client
	case err := <-acceptErr:
		t.Fatalf("accept: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept timed out")
	}
	return nil, nil
}

// TestDecidePGFirstByte: a client byte within the delay classifies the
// connection as PostgreSQL, and the peeked byte stays readable through br.
func TestDecidePGFirstByte(t *testing.T) {
	server, client := dialPair(t)
	br := bufio.NewReader(server)
	if _, err := client.Write([]byte{0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}
	proto, err := decide(server, br, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if proto != "pg" {
		t.Fatalf("proto = %q, want %q", proto, "pg")
	}
	// The peeked byte must still be readable through br — nothing is lost.
	b, err := br.Peek(1)
	if err != nil {
		t.Fatalf("re-peek: %v", err)
	}
	if b[0] != 0x00 {
		t.Fatalf("peeked byte = %#x, want 0x00", b[0])
	}
	got := make([]byte, 1)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read through br: %v", err)
	}
	if got[0] != 0x00 {
		t.Fatalf("read byte = %#x, want 0x00", got[0])
	}
}

// TestDecideMySQLSilence: a silent client classifies as MySQL after the full
// detect delay (MySQL is server-first; the client waits for the handshake).
func TestDecideMySQLSilence(t *testing.T) {
	server, _ := dialPair(t)
	br := bufio.NewReader(server)
	start := time.Now()
	proto, err := decide(server, br, 100*time.Millisecond)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if proto != "mysql" {
		t.Fatalf("proto = %q, want %q", proto, "mysql")
	}
	if elapsed < 90*time.Millisecond {
		t.Fatalf("decide returned after %v, want ~100ms detect delay", elapsed)
	}
}

// TestDecideClosedConn: a connection closed before any byte yields an error
// (not a timeout, not a protocol).
func TestDecideClosedConn(t *testing.T) {
	server, client := dialPair(t)
	br := bufio.NewReader(server)
	client.Close()
	proto, err := decide(server, br, 100*time.Millisecond)
	if err == nil {
		t.Fatalf("decide returned %q, want error", proto)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("decide returned a timeout, want conn-closed error: %v", err)
	}
	if proto != "" {
		t.Fatalf("proto = %q, want empty on error", proto)
	}
}

// TestDispatchPGNilClosesConn: until Phase 4 wires the PG proxy, a detected PG
// client must be dropped (conn closed, warn logged) — never a nil panic.
func TestDispatchPGNilClosesConn(t *testing.T) {
	server, client := dialPair(t)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	d := NewDispatcher(logger, nil /* mysql unused here */, nil, /* pg not wired yet */
		100*time.Millisecond, 8)
	if _, err := client.Write([]byte{0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}
	d.dispatch(context.Background(), server)
	// dispatch must have closed the server conn → client sees EOF/reset.
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected conn closed after pg dispatch with nil pg proxy")
	}
	if !strings.Contains(logBuf.String(), "pg proxy not wired") {
		t.Fatalf("expected warn log about pg proxy not wired, got: %s", logBuf.String())
	}
}
