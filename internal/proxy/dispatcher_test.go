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

// TestDecideMSSQLFirstByte: a 0x12 first byte (TDS PRELOGIN packet type)
// classifies the connection as MSSQL — checked BEFORE the PG branch — and
// the peeked byte stays readable through br.
func TestDecideMSSQLFirstByte(t *testing.T) {
	server, client := dialPair(t)
	br := bufio.NewReader(server)
	if _, err := client.Write([]byte{0x12}); err != nil {
		t.Fatalf("write: %v", err)
	}
	proto, err := decide(server, br, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if proto != "mssql" {
		t.Fatalf("proto = %q, want %q", proto, "mssql")
	}
	// The peeked byte must still be readable through br — nothing is lost.
	b, err := br.Peek(1)
	if err != nil {
		t.Fatalf("re-peek: %v", err)
	}
	if b[0] != 0x12 {
		t.Fatalf("peeked byte = %#x, want 0x12", b[0])
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
		nil, /* mssql unused here */
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

// TestDispatchMSSQLNilClosesConn: until Task 9.2 wires the TDS proxy, a
// detected MSSQL client (first byte 0x12) must be dropped — conn closed,
// warn logged — never a nil panic, and never misrouted to PG/MySQL.
func TestDispatchMSSQLNilClosesConn(t *testing.T) {
	server, client := dialPair(t)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	d := NewDispatcher(logger, nil, nil, nil /* mssql not wired yet */, 100*time.Millisecond, 8)
	if _, err := client.Write([]byte{0x12}); err != nil {
		t.Fatalf("write: %v", err)
	}
	d.dispatch(context.Background(), server)
	// dispatch must have closed the server conn → client sees EOF/reset.
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected conn closed after mssql dispatch with nil mssql proxy")
	}
	if !strings.Contains(logBuf.String(), "mssql proxy not wired") {
		t.Fatalf("expected warn log about mssql proxy not wired, got: %s", logBuf.String())
	}
}

// TestDispatchMSSQLRoutesToHandler: a 0x12-prefixed connection routes to the
// REAL mssql handler (not pg/mysql), and the prelogin byte peeked by decide
// survives the dispatcher's shared bufio.Reader into the handler's own read.
// Review 2026-08-16: the mssqlProxy interface + fake were removed — the
// dispatcher holds the concrete *MSSQLProxy, and the prelogin round trip
// against the real handler proves routing + byte preservation.
func TestDispatchMSSQLRoutesToHandler(t *testing.T) {
	server, client := dialPair(t)
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	mssql := NewMSSQLProxy(logger, nil, &ConfigCredResolver{}, nil)
	d := NewDispatcher(logger, nil, nil, mssql, 100*time.Millisecond, 8)
	// A FULL prelogin packet: decide peeked the 0x12 first byte and the
	// handler must still see it (through br) when it parses the packet.
	if err := writeTDSPacket(client, tdsPrelogin, buildPrelogin(encryptOff)); err != nil {
		t.Fatalf("write prelogin: %v", err)
	}
	done := make(chan struct{})
	go func() {
		d.dispatch(context.Background(), server)
		close(done)
	}()
	// The handler answers the prelogin with its TABULAR response — its
	// arrival proves the mssql handler ran on THIS conn and consumed the
	// peeked bytes.
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	typ, payload, err := readTDSMessage(bufio.NewReader(client))
	if err != nil {
		t.Fatalf("read prelogin response: %v", err)
	}
	if typ != tdsTabular {
		t.Fatalf("prelogin response packet type = %#x, want %#x (TABULAR)", typ, tdsTabular)
	}
	if enc, err := parsePrelogin(payload); err != nil || enc != encryptNotSup {
		t.Fatalf("prelogin response encryption = %#x (err %v), want %#x (ENCRYPT_NOT_SUP)", enc, err, encryptNotSup)
	}
	client.Close() // the handler's LOGIN7 read fails → handleConn returns
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatch did not return within 5s of client close")
	}
}
