package proxy

// node-integration Task 4 — the data-plane half of password-at-mint: when a
// token carries CredOverride, the connect resolves the password from
// ztcred:<sid> FIRST (plain GET — session-mode reconnects may re-read; the
// key dies by TTL, not GETDEL), falling back to the normal resolver chain on
// miss/error with a WARN that carries the REASON only — never the value
// (G2). Tokens without the flag resolve exactly as before (G3).

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// recordingResolver is a CredResolver stub that records every key it is
// asked for and answers from a fixed map (the "normal chain" stand-in).
type recordingResolver struct {
	mu     sync.Mutex
	creds  map[string]string
	asked  []string
	errFor map[string]error // optional per-key errors
}

func (r *recordingResolver) Password(_ context.Context, key string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, key)
	if err, ok := r.errFor[key]; ok {
		return "", err
	}
	pw, ok := r.creds[key]
	if !ok {
		return "", fmt.Errorf("no credentials for %s", key)
	}
	return pw, nil
}

func (r *recordingResolver) askedFor(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range r.asked {
		if k == key {
			return true
		}
	}
	return false
}

// newChainTestProxy builds a MySQL proxy wired through the override chain:
// the resolver is the chain over a recording fallback, so a connect through
// the full handleConn path exercises override-first resolution. Returns the
// listener, the proxy and the log buffer (G2 assertions read it). (Kept for
// full-path follow-ups; the brief's test 2 drives connectMySQLBackend
// directly against a stub backend below.)
func newChainTestProxy(t *testing.T, vs Store, fallback *recordingResolver) (net.Listener, *MySQLProxy, *bytes.Buffer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	var logBuf bytes.Buffer
	chain := WrapCredResolver(fallback, vs, slog.New(slog.NewTextHandler(&logBuf, nil)))
	p := NewMySQLProxy(slog.New(slog.NewTextHandler(&logBuf, nil)), vs, chain, nil)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleConn(context.Background(), conn, bufio.NewReader(conn))
		}
	}()
	return ln, p, &logBuf
}

// chainTestToken stores a session-mode token. When overridePw != "" the flag
// is set and ztcred:<sid> is planted with a 2s TTL (the fallback tests let
// it lapse). With flagOnly=true the flag is set but NO key is planted — the
// "mint stored the flag, the key already expired" shape the fallback WARN
// path exists for.
func chainTestToken(t *testing.T, vs *store.ValkeyStore, username, overridePw string, flagOnly bool) (token string, tok models.TokenPayload) {
	t.Helper()
	tkn, err := store.NewToken()
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}
	sid := "sid-" + tkn[len("sess_"):]
	tok = models.TokenPayload{
		Username: username, DBUser: "chain_user", DBIP: "127.0.0.1", DBPort: "3307",
		DBType: "mysql", TicketID: "T-NI-4", SessionID: sid, Mode: "session",
		IP: "127.0.0.1", IssuedAt: time.Now().Unix(),
	}
	if overridePw != "" || flagOnly {
		tok.CredOverride = true
	}
	if overridePw != "" {
		if err := vs.SetCredOverride(context.Background(), sid, overridePw, 2*time.Second); err != nil {
			t.Fatalf("SetCredOverride: %v", err)
		}
	}
	if err := vs.SetToken(context.Background(), tkn, tok, time.Minute); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	t.Cleanup(func() {
		_ = vs.DelSessionLive(context.Background(), sid)
		_ = vs.DeleteToken(context.Background(), tkn)
		_ = vs.DelCredOverride(context.Background(), sid)
	})
	return tkn, tok
}

// --- direct chain unit tests -------------------------------------------------

// TestChainOverrideWins: CredOverride + present key → the override value,
// and the fallback resolver is NEVER consulted.
func TestChainOverrideWins(t *testing.T) {
	vs := proxyTestStore(t)
	fb := &recordingResolver{creds: map[string]string{"mysql:chain_user@127.0.0.1:3307": "fallback-pw"}}
	chain := WrapCredResolver(fb, vs, testLogger(t))

	_, tok := chainTestToken(t, vs, "chain-win", "override-pw", false)
	// Re-plant with a long TTL (the helper uses 2s; this test reads once).
	if err := vs.SetCredOverride(context.Background(), tok.SessionID, "override-pw", time.Minute); err != nil {
		t.Fatalf("replant: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelCredOverride(context.Background(), tok.SessionID) })

	pw, err := OverrideCreds(chain, &tok).Password(context.Background(), "mysql:chain_user@127.0.0.1:3307")
	if err != nil {
		t.Fatalf("chain.Password: %v", err)
	}
	if pw != "override-pw" {
		t.Fatalf("chain returned %q, want the override %q", pw, "override-pw")
	}
	if len(fb.asked) != 0 {
		t.Fatalf("fallback consulted on an override hit: %v", fb.asked)
	}
	// GET not GETDEL: the second read sees the same value (session-mode
	// reconnects).
	pw2, err := OverrideCreds(chain, &tok).Password(context.Background(), "mysql:chain_user@127.0.0.1:3307")
	if err != nil || pw2 != "override-pw" {
		t.Fatalf("second chain read = %q, %v — override must survive re-reads", pw2, err)
	}
}

// TestChainMissFallsBackWarns: CredOverride + expired/missing key → the
// fallback resolver answers, and the WARN carries the reason only — the
// override VALUE never appears in the log buffer (G2).
func TestChainMissFallsBackWarns(t *testing.T) {
	vs := proxyTestStore(t)
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	fb := &recordingResolver{creds: map[string]string{"mysql:chain_user@127.0.0.1:3307": "fallback-pw"}}
	chain := WrapCredResolver(fb, vs, log)

	_, tok := chainTestToken(t, vs, "chain-miss", "", true) // flag set, but plant NOTHING
	pw, err := OverrideCreds(chain, &tok).Password(context.Background(), "mysql:chain_user@127.0.0.1:3307")
	if err != nil {
		t.Fatalf("chain.Password: %v", err)
	}
	if pw != "fallback-pw" {
		t.Fatalf("chain returned %q, want the fallback %q", pw, "fallback-pw")
	}
	if !fb.askedFor("mysql:chain_user@127.0.0.1:3307") {
		t.Fatalf("fallback not consulted on miss: %v", fb.asked)
	}
	if strings.Contains(logBuf.String(), "fallback-pw") {
		t.Fatalf("log carries a password: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "cred override miss") {
		t.Fatalf("expected a WARN on the fallback path, got: %s", logBuf.String())
	}
}

// TestChainNoFlagNeverConsultsStore (G3): a token without the flag resolves
// exactly like before — the store is never asked, and an override key that
// happens to exist for the sid is IGNORED.
func TestChainNoFlagNeverConsultsStore(t *testing.T) {
	vs := proxyTestStore(t)
	fb := &recordingResolver{creds: map[string]string{"mysql:chain_user@127.0.0.1:3307": "fallback-pw"}}
	chain := WrapCredResolver(fb, vs, testLogger(t))

	_, tok := chainTestToken(t, vs, "chain-noflag", "", false)
	// Plant an override ANYWAY — without the flag it must be ignored.
	if err := vs.SetCredOverride(context.Background(), tok.SessionID, "sneaky-override", time.Minute); err != nil {
		t.Fatalf("plant: %v", err)
	}
	t.Cleanup(func() { _ = vs.DelCredOverride(context.Background(), tok.SessionID) })

	pw, err := OverrideCreds(chain, &tok).Password(context.Background(), "mysql:chain_user@127.0.0.1:3307")
	if err != nil {
		t.Fatalf("chain.Password: %v", err)
	}
	if pw != "fallback-pw" || len(fb.asked) != 1 {
		t.Fatalf("chain = %q (asked %v), want the plain fallback path", pw, fb.asked)
	}
}

// TestChainFallbackErrorSurfaces: override miss + failing fallback → the
// connect fails (the old behavior), with the fallback's error — never a
// value.
func TestChainFallbackErrorSurfaces(t *testing.T) {
	vs := proxyTestStore(t)
	fb := &recordingResolver{errFor: map[string]error{"mysql:chain_user@127.0.0.1:3307": fmt.Errorf("vault down")}}
	chain := WrapCredResolver(fb, vs, testLogger(t))

	_, tok := chainTestToken(t, vs, "chain-err", "", true)
	if _, err := OverrideCreds(chain, &tok).Password(context.Background(), "mysql:chain_user@127.0.0.1:3307"); err == nil {
		t.Fatal("expected the fallback error to surface")
	}
}

// --- full-path test: the connect actually uses the override password --------

// stubSighting records what the stub backend observed.
type stubSighting struct {
	mu   sync.Mutex
	user string
}

func (s *stubSighting) set(user string) {
	s.mu.Lock()
	s.user = user
	s.mu.Unlock()
}

func (s *stubSighting) get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.user
}

// startMySQLStubBackend runs a minimal MySQL SERVER stub that:
//   - sends a handshake V10 advertising mysql_native_password with a fixed 20-byte scramble,
//   - parses the client's handshake response (username = db user),
//   - switches to mysql_clear_password (auth switch) so the password arrives verbatim,
//   - answers OK when the password matches wantPassword, ERR 1045 otherwise.
//
// Returns the listener; sightings go into seen.
func startMySQLStubBackend(t *testing.T, wantPassword string, seen *stubSighting) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				salt := make([]byte, 20)
				for i := range salt {
					salt[i] = byte('a' + i%26)
				}
				hs, err := buildHandshakeV10("8.4.0-stub", 1, salt, advertisedCaps)
				if err != nil {
					return
				}
				if err := writeMySQLPacket(c, 0, hs); err != nil {
					return
				}
				_, resp, err := readMySQLPacket(bufio.NewReader(c))
				if err != nil {
					return
				}
				user, _, _, err := parseStubHandshakeResponse(resp)
				if err != nil {
					return
				}
				if seen != nil {
					seen.set(user)
				}
				// Auth switch to clear password so the stub can compare the
				// literal password (go-mysql honors AUTH_CLEAR_PASSWORD and
				// sends password + \0).
				sw := append([]byte{0xfe}, append([]byte("mysql_clear_password"), 0)...)
				if err := writeMySQLPacket(c, 2, sw); err != nil {
					return
				}
				_, clear, err := readMySQLPacket(bufio.NewReader(c))
				if err != nil {
					return
				}
				got := string(clear)
				got = strings.TrimSuffix(got, "\x00")
				if got == wantPassword {
					_ = writeMySQLPacket(c, 4, okPacket())
					// Drain one command then EOF — enough for the proxy to
					// finish the session setup (thread-id probe answers OK).
					_, _, _ = readMySQLPacket(bufio.NewReader(c))
					return
				}
				_ = writeMySQLPacket(c, 4, errPacket(1045, "28000", "Access denied"))
				_, _, _ = readMySQLPacket(bufio.NewReader(c))
			}(conn)
		}
	}()
	return ln
}

// parseStubHandshakeResponse extracts username, database and the raw auth
// response bytes from a protocol-4.1 handshake response (mirrors
// parseHandshakeResponse but returns the auth bytes).
func parseStubHandshakeResponse(payload []byte) (user, database string, auth []byte, err error) {
	if len(payload) < 32 {
		return "", "", nil, fmt.Errorf("short handshake response")
	}
	i := 32 // 4 caps + 4 maxpacket + 1 charset + 23 reserved
	if i >= len(payload) {
		return "", "", nil, fmt.Errorf("truncated")
	}
	end := bytes.IndexByte(payload[i:], 0)
	if end < 0 {
		return "", "", nil, fmt.Errorf("no username terminator")
	}
	user = string(payload[i : i+end])
	i += end + 1
	if i >= len(payload) {
		return "", "", nil, fmt.Errorf("no auth length")
	}
	n := int(payload[i])
	i++
	if i+n > len(payload) {
		return "", "", nil, fmt.Errorf("truncated auth")
	}
	auth = payload[i : i+n]
	i += n
	// CLIENT_CONNECT_WITH_DB may append a database (null-terminated).
	if i < len(payload) {
		e := bytes.IndexByte(payload[i:], 0)
		if e >= 0 {
			database = string(payload[i : i+e])
		}
	}
	return user, database, auth, nil
}

// TestConnectUsesOverridePassword (brief test 2): a CredOverride token whose
// override key holds "override-pw-Value" connects to a stub backend that
// accepts ONLY that password — and never tries the config fallback value.
func TestConnectUsesOverridePassword(t *testing.T) {
	vs := proxyTestStore(t)
	const overridePw = "override-pw-Value"
	// The stub accepts ONLY the override; the fallback password is wrong
	// for it — if the chain fell back, the connect would fail.
	seen := &stubSighting{}
	ln := startMySQLStubBackend(t, overridePw, seen)
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())

	fb := &recordingResolver{creds: map[string]string{}}
	tkn, tok := chainTestToken(t, vs, "chain-connect", overridePw, false)
	// Point the token at the stub (re-store with the stub's addr; the sid
	// and override key stay).
	tok.DBIP = host
	tok.DBPort = portStr
	if err := vs.SetToken(context.Background(), tkn, tok, time.Minute); err != nil {
		t.Fatalf("re-store token: %v", err)
	}

	// The chain's fallback knows NOTHING: with the override winning, it is
	// never consulted; if it were, the connect would fail (empty map).
	chain := WrapCredResolver(fb, vs, testLogger(t))
	conn, err := connectMySQLBackend(context.Background(), &tok, OverrideCreds(chain, &tok), "appdb")
	if err != nil {
		t.Fatalf("connect with override: %v", err)
	}
	defer conn.Close()
	if got := seen.get(); got != "chain_user" {
		t.Fatalf("stub saw user %q, want chain_user (the connect reached the backend)", got)
	}
	if len(fb.asked) != 0 {
		t.Fatalf("fallback consulted despite an override hit: %v", fb.asked)
	}
	// Sanity: the stub really rejects the fallback password.
	if _, err := connectMySQLBackend(context.Background(), func() *models.TokenPayload {
		cp := tok
		cp.CredOverride = false
		return &cp
	}(), &ConfigCredResolver{Creds: map[string]string{
		fmt.Sprintf("mysql:chain_user@%s:%s", host, portStr): "fallback-pw",
	}}, "appdb"); err == nil {
		t.Fatal("stub accepted the WRONG password — the test proves nothing")
	}
}

// TestLiveSessionOverrideFallbackAfterExpiry (brief test 3): an override
// session connects with the override; after the ztcred: key expires the
// fallback password is what reaches the backend (the proxy logs the fallback
// WARN — reason only). Proven against the same stub backend shape.
func TestLiveSessionOverrideFallbackAfterExpiry(t *testing.T) {
	vs := proxyTestStore(t)
	const overridePw = "override-pw-Value"
	const fallbackPw = "fallback-pw-Value"
	seen := &stubSighting{}
	// The stub accepts the FALLBACK password (the config chain's value).
	ln := startMySQLStubBackend(t, fallbackPw, seen)
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())

	var logBuf bytes.Buffer
	fb := &recordingResolver{creds: map[string]string{
		fmt.Sprintf("mysql:chain_user@%s:%s", host, portStr): fallbackPw,
	}}
	chain := WrapCredResolver(fb, vs, slog.New(slog.NewTextHandler(&logBuf, nil)))

	_, tok := chainTestToken(t, vs, "chain-expiry", overridePw, false)
	tok.DBIP = host
	tok.DBPort = portStr
	tok.CredOverride = true
	// The override was planted with the helper's 2s TTL — wait for the
	// key to lapse, then connect: the fallback must answer.
	deadline := time.Now().Add(5 * time.Second)
	for {
		pw, _ := vs.GetCredOverride(context.Background(), tok.SessionID)
		if pw == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("override key did not expire within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}

	conn, err := connectMySQLBackend(context.Background(), &tok, OverrideCreds(chain, &tok), "appdb")
	if err != nil {
		t.Fatalf("connect after override expiry: %v", err)
	}
	defer conn.Close()
	if !fb.askedFor(fmt.Sprintf("mysql:chain_user@%s:%s", host, portStr)) {
		t.Fatalf("fallback not consulted after override expiry: %v", fb.asked)
	}
	if got := seen.get(); got != "chain_user" {
		t.Fatalf("stub saw user %q — the fallback connect never landed", got)
	}
	if strings.Contains(logBuf.String(), overridePw) || strings.Contains(logBuf.String(), fallbackPw) {
		t.Fatalf("log carries a password value: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "cred override miss") {
		t.Fatalf("expected the fallback WARN, got: %s", logBuf.String())
	}
}

// TestOverrideKeyTTLNeverExceedsToken (brief test 7, live half): a
// session-mode token stored with a 3s TTL and a planted override carries a
// ztcred: key whose remaining TTL never exceeds the token's — checked as
// both decay (same resolution on both keys, what the mint writes).
func TestOverrideKeyTTLNeverExceedsToken(t *testing.T) {
	vs := proxyTestStore(t)
	tkn, tok := chainTestToken(t, vs, "chain-ttl", "ttl-pw", false)
	// Re-store the token with a SHORT ttl and the override at the same
	// value — what a password-at-mint with end_time ≈ now+3s produces.
	if err := vs.SetToken(context.Background(), tkn, tok, 3*time.Second); err != nil {
		t.Fatalf("SetToken: %v", err)
	}
	if err := vs.SetCredOverride(context.Background(), tok.SessionID, "ttl-pw", 3*time.Second); err != nil {
		t.Fatalf("SetCredOverride: %v", err)
	}
	rawc, closeRaw := newRawValkeyProbe(t)
	defer closeRaw()
	// The two writes are separate round-trips: ztcred: lands ~1-2ms after
	// tok:, so a poll tick in that gap sees TokenAlive=false while the
	// override still has a few ms of PTTL — a write-skew artifact, not an
	// orphan. Only a credential alive BEYOND this grace window is an
	// orphan (the assertion's meaning is unchanged: the override still
	// cannot outlive the token in any real sense).
	const writeSkewGrace = 100 * time.Millisecond
	deadline := time.Now().Add(6 * time.Second)
	for {
		tokAlive, err := vs.TokenAlive(context.Background(), tkn)
		if err != nil {
			t.Fatalf("TokenAlive: %v", err)
		}
		credTTLms, _ := rawc.Pttl("ztcred:" + tok.SessionID)
		if !tokAlive {
			if credTTLms > int64(writeSkewGrace/time.Millisecond) {
				t.Fatalf("token expired but ztcred still has %dms left (>%dms grace) — orphaned credential", credTTLms, writeSkewGrace/time.Millisecond)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("token did not expire within 6s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// rawValkeyProbe wraps a raw valkey client exposing only PTTL (the store's
// concrete type keeps its client unexported; the proxy tests need a raw TTL
// read the production surface intentionally omits).
type rawValkeyProbe struct {
	c valkey.Client
}

func newRawValkeyProbe(t *testing.T) (*rawValkeyProbe, func()) {
	t.Helper()
	c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("raw valkey client: %v", err)
	}
	return &rawValkeyProbe{c: c}, func() { c.Close() }
}

func (p *rawValkeyProbe) Pttl(key string) (int64, error) {
	return p.c.Do(context.Background(), p.c.B().Pttl().Key(key).Build()).AsInt64()
}
