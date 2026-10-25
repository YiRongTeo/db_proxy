package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"zerotrust-proxy/internal/models"
)

// --- Alignment review I-2: MSSQL relock freeze WIRE-SHAPE parity ------------
//
// The alignment review found the TDS plane's re-lock freeze under-tested
// relative to mysql (relock_test.go: real relay pipe + ERR 1045 parse +
// backend-never-sees) and pg (relock_mirror_test.go: FATAL 28000 +
// ReadyForQuery tail): TestMSSQLRelockFreezeAndUnfreeze pins only the
// decision helper + flag transitions. These tests honor the "same contract,
// per dialect" comment on the real relay pipe:
//
//   - a frozen session's reply is a well-formed TDS ERROR token (0xAA,
//     error 18456, class 14) + the DONE tail — parsed with the same
//     ERROR-token machinery the live gate tests use (the
//     zz_live_mssql_test.go extractErrorMsg precedent);
//   - the backend NEVER sees a frozen command;
//   - the frozen-ATTENTION branch (mssql_relay.go, the DONE_ATTN ack while
//     frozen) is acked to the client and NOT forwarded;
//   - after a checker re-attaches, the next command FLOWS byte-exact.

// utf16leString is the test's UTF-16LE encoder (the wire shape SQL batch
// text rides in — decodeMSSQLBatch/normalizeTDSBatchText reverse it).
func utf16leString(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	return b
}

// writeRelockBatch sends one single-frame SQL batch (type 0x01) carrying a
// UTF-16LE batch payload. The relay only needs the frame forwarded or
// rejected — the AllHeaders transaction descriptor the live backend demands
// is irrelevant here (the fake backend peer asserts raw bytes).
func writeRelockBatch(t *testing.T, conn net.Conn, sql string) {
	t.Helper()
	if err := writeTDSPacket(conn, tdsSQLBatch, utf16leString(sql)); err != nil {
		t.Fatalf("write frozen batch: %v", err)
	}
}

// TestMSSQLRelockFreezeRejectsOnWire (I-2.1 + I-2.2): drive the REAL relay
// pipe with a frozen (relocked) hold-admitted rw session — the client's SQL
// batch is answered with the well-formed TDS ERROR token (0xAA, 18456,
// class 14, gating message + DONE tail) and the backend NEVER sees the
// command. The mysql/pg wire-freeze mirror (relock_test.go /
// relock_mirror_test.go), per dialect.
func TestMSSQLRelockFreezeRejectsOnWire(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	cbr := bufio.NewReader(cpeer)
	bbr := bufio.NewReader(bpeer)
	sid := "sid-relock-mssql-wire"
	s := &mssqlSession{id: sid, access: "rw", holdAdmitted: true, client: client, backend: backend,
		tok: &models.TokenPayload{Username: "relock-maker", DBUser: "rw_user", DBType: "mssql", SessionID: sid, Access: "rw"}}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() {
		p.unregisterSession(sid)
		_ = vs.DelSessionLive(ctx, sid)
		cpeer.Close()
		bpeer.Close()
		client.Close()
		backend.Close()
	})
	p.registerSession(s)

	// Drive the REAL client→backend relay pipe (as the session would):
	// the freeze blocks inside the loop, so the pipe never deadlocks a
	// lone test goroutine.
	done := make(chan struct{})
	go func() {
		p.pipeMSSQLClientToBackend(bufio.NewReader(client), backend, client, s, s.tok, "relock-test")
		close(done)
	}()

	// Freeze via the ctl:relock payload (exactly what the hub publishes).
	if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
		t.Fatal("HandleRelock(relock rw session) = false, want true (frozen)")
	}

	// The client's next SQL batch is answered with the gating ERROR token…
	writeRelockBatch(t, cpeer, "UPDATE demo_items SET name = 'frozen'")
	_ = cpeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, payload, err := readTDSMessage(cbr)
	if err != nil {
		t.Fatalf("read frozen reply: %v", err)
	}
	_ = cpeer.SetReadDeadline(time.Time{})
	if typ != tdsTabular {
		t.Fatalf("frozen reply type = %#x, want TABULAR (0x04)", typ)
	}
	if !mssqlResponseError(payload) {
		t.Fatalf("frozen reply % x carries no ERROR/DONE_ERROR tokens", payload)
	}
	// The message text names the session with the gating wording.
	if msg := extractErrorMsg(payload); !strings.Contains(msg, "maker gating") || !strings.Contains(msg, sid) {
		t.Errorf("frozen ERROR message = %q, want the gating message naming %s", msg, sid)
	}
	// Pin the ERROR token number/class exactly (18456 / 14): walk the
	// token stream to the 0xAA token like scanLoginSPID does.
	frozen := false
	for pos := 0; pos+3 <= len(payload); {
		switch payload[pos] {
		case 0xAA:
			restLen := int(binary.LittleEndian.Uint16(payload[pos+1 : pos+3]))
			if pos+3+restLen > len(payload) {
				pos = len(payload)
				break
			}
			body := payload[pos+3 : pos+3+restLen]
			if num := binary.LittleEndian.Uint32(body[0:4]); num != 18456 {
				t.Errorf("frozen ERROR number = %d, want 18456", num)
			}
			if class := body[5]; class != 14 {
				t.Errorf("frozen ERROR class = %d, want 14", class)
			}
			frozen = true
			pos = len(payload)
		case 0xFD, 0xFE, 0xFF: // DONE family — 13 modern / 9 legacy
			if pos+13 > len(payload) {
				pos += 9
			} else {
				pos += 13
			}
		default: // length-prefixed tokens
			pos += 3 + int(binary.LittleEndian.Uint16(payload[pos+1:pos+3]))
		}
	}
	if !frozen {
		t.Error("no ERROR token (0xAA) found in the frozen reply")
	}
	// The DONE tail: the message ends with a DONE token carrying
	// DONE_ERROR (0x0002) — the shape sqlcmd ends a failed command with.
	if len(payload) < 13 || payload[len(payload)-13] != 0xFD {
		t.Fatalf("frozen reply has no 13-byte DONE tail: % x", payload)
	}
	if status := binary.LittleEndian.Uint16(payload[len(payload)-12:]); status&tdsDoneError == 0 {
		t.Errorf("DONE tail status = %#04x, want the DONE_ERROR bit", status)
	}

	// …and the backend NEVER sees the command.
	_ = bpeer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := readTDSFrame(bbr); err == nil {
		t.Fatal("frozen batch reached the backend")
	}
	_ = bpeer.SetReadDeadline(time.Time{})
}

// TestMSSQLRelockFrozenAttentionAcked (I-2.3): while frozen, a client
// ATTENTION is answered with the DONE_ATTN ack (the cancel protocol stays
// intact — the mssql_relay.go frozen-ATTENTION branch) and is NOT forwarded
// to the backend.
func TestMSSQLRelockFrozenAttentionAcked(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	cbr := bufio.NewReader(cpeer)
	bbr := bufio.NewReader(bpeer)
	sid := "sid-relock-mssql-attn"
	s := &mssqlSession{id: sid, access: "rw", holdAdmitted: true, client: client, backend: backend,
		tok: &models.TokenPayload{Username: "relock-maker", DBUser: "rw_user", DBType: "mssql", SessionID: sid, Access: "rw"}}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() {
		p.unregisterSession(sid)
		_ = vs.DelSessionLive(ctx, sid)
		cpeer.Close()
		bpeer.Close()
		client.Close()
		backend.Close()
	})
	p.registerSession(s)

	done := make(chan struct{})
	go func() {
		p.pipeMSSQLClientToBackend(bufio.NewReader(client), backend, client, s, s.tok, "relock-test")
		close(done)
	}()

	if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
		t.Fatal("HandleRelock = false, want true")
	}

	// The frozen client cancels: an ATTENTION packet (header-only).
	if err := writeTDSPacket(cpeer, tdsAttention, nil); err != nil {
		t.Fatalf("write attention: %v", err)
	}
	// The client gets its DONE_ATTN ack (a TABULAR message carrying ONLY a
	// DONE token with the DONE_ATTN status bit — buildTDSAttnAck).
	_ = cpeer.SetReadDeadline(time.Now().Add(2 * time.Second))
	typ, payload, err := readTDSMessage(cbr)
	if err != nil {
		t.Fatalf("read frozen attention ack: %v", err)
	}
	_ = cpeer.SetReadDeadline(time.Time{})
	if typ != tdsTabular {
		t.Fatalf("attention ack type = %#x, want TABULAR", typ)
	}
	if len(payload) != 13 || payload[0] != 0xFD {
		t.Fatalf("attention ack payload = % x, want the bare 13-byte DONE_ATTN token", payload)
	}
	if status := binary.LittleEndian.Uint16(payload[1:3]); status&tdsDoneAttn == 0 {
		t.Errorf("attention ack DONE status = %#04x, want the DONE_ATTN bit", status)
	}

	// The ATTENTION is NOT forwarded: the backend sees nothing.
	_ = bpeer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, err := readTDSFrame(bbr); err == nil {
		t.Fatal("frozen ATTENTION reached the backend")
	}
	_ = bpeer.SetReadDeadline(time.Time{})
}

// TestMSSQLRelockUnfreezesForwardOnWatch (I-2.4): freeze → checker
// re-attaches → the frozen poll unfreezes → the next command FLOWS THROUGH
// the relay to the backend byte-exact (the mysql unfreeze mirror,
// TestMySQLRelockUnfreezesOnWatch).
func TestMSSQLRelockUnfreezesForwardOnWatch(t *testing.T) {
	vs := proxyTestStore(t)
	ctx := context.Background()
	p := NewMSSQLProxy(slog.New(slog.NewTextHandler(io.Discard, nil)), vs, &ConfigCredResolver{}, nil)
	client, cpeer := net.Pipe()
	backend, bpeer := net.Pipe()
	bbr := bufio.NewReader(bpeer)
	sid := "sid-relock-mssql-unfreeze"
	s := &mssqlSession{id: sid, access: "rw", holdAdmitted: true, client: client, backend: backend,
		tok: &models.TokenPayload{Username: "relock-maker", DBUser: "rw_user", DBType: "mssql", SessionID: sid, Access: "rw"}}
	cleanupLiveRecord(t, vs, sid)
	t.Cleanup(func() {
		p.unregisterSession(sid)
		_ = vs.DelSessionLive(ctx, sid)
		cpeer.Close()
		bpeer.Close()
		client.Close()
		backend.Close()
	})
	p.registerSession(s)

	// Drive the REAL relay pipe: freeze, then unfreeze on a watcher — the
	// next batch must flow THROUGH the relay to the backend byte-exact.
	done := make(chan struct{})
	go func() {
		p.pipeMSSQLClientToBackend(bufio.NewReader(client), backend, client, s, s.tok, "relock-test")
		close(done)
	}()

	if !p.HandleRelock([]byte(`{"action":"relock","session_id":"` + sid + `"}`)) {
		t.Fatal("HandleRelock = false, want true")
	}

	// A checker attaches — the SAME signal the initial hold polls.
	if err := vs.SetWatchConn(ctx, sid, "relock-checker-mssql-wire", time.Minute); err != nil {
		t.Fatalf("SetWatchConn: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelWatch(context.Background(), sid) })
	waitFor(t, "mssql session unfreezes on watch", func() bool { return !p.sessionFrozen(sid) })

	// Now a batch flows to the backend (forwarded, not blocked): the fake
	// backend peer receives the original frame — header + UTF-16LE payload
	// byte-exact (readTDSMessageFrames preserves both).
	batch := append(append([]byte(nil), allHeaders22...), utf16leString("SELECT 1")...)
	if err := writeTDSPacket(cpeer, tdsSQLBatch, batch); err != nil {
		t.Fatalf("write forwarded batch: %v", err)
	}
	hdr, payload, err := readTDSFrame(bbr)
	if err != nil {
		t.Fatalf("read forwarded batch: %v", err)
	}
	if hdr[0] != tdsSQLBatch || !bytes.Equal(payload, batch) {
		t.Errorf("forwarded = typ %#x % x, want typ %#x % x (byte-exact after unfreeze)",
			hdr[0], payload, tdsSQLBatch, batch)
	}
	cpeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit after the client closed")
	}
}
