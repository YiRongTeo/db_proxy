package proxy

// node-integration IP-lock toggle — unit tests for the policy flag and the
// pass-through mechanism. The LIVE per-plane proofs (flag off → a foreign-IP
// session login SUCCEEDS) live in zz_session_token_consistency_test.go
// (mysql/pg/mssql backends); the oracle plane has no live test harness, but
// it calls the SAME promoted publisher method these tests pin — one
// mechanism, all four planes.

import (
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
)

// TestSessionPolicyIPLockWithDefaults: SessionPolicy.IPLock is a *bool so
// ABSENT (nil) is distinguishable from an explicit false; withDefaults()
// materializes nil → TRUE (secure default — zero-config boots stay locked)
// and preserves an explicit false. The pre-existing Poll clamp is untouched.
func TestSessionPolicyIPLockWithDefaults(t *testing.T) {
	d := SessionPolicy{}.withDefaults()
	if d.IPLock == nil || !*d.IPLock {
		t.Errorf("withDefaults() IPLock = %v, want non-nil true (secure default)", d.IPLock)
	}
	if d.Poll != time.Second {
		t.Errorf("withDefaults() Poll = %v, want 1s (clamp preserved)", d.Poll)
	}

	f := false
	p := SessionPolicy{IPLock: &f, Poll: time.Second}.withDefaults()
	if p.IPLock == nil || *p.IPLock {
		t.Errorf("withDefaults() over explicit false → IPLock = %v, want non-nil false", p.IPLock)
	}

	tr := true
	p = SessionPolicy{IPLock: &tr}.withDefaults()
	if p.IPLock == nil || !*p.IPLock {
		t.Errorf("withDefaults() over explicit true → IPLock = %v, want non-nil true", p.IPLock)
	}
}

// foreignIPTok is a session-mode token stamped for an address no test
// client connects from — the classic foreign-IP rejection case.
func foreignIPTok() *models.TokenPayload {
	return &models.TokenPayload{Mode: "session", IP: "192.0.2.1"}
}

// TestCheckSessionTokenIPLockedDefault: a publisher built LOCKED (the
// constructor default) still rejects a foreign-IP session login — the
// pre-toggle behavior is pinned.
func TestCheckSessionTokenIPLockedDefault(t *testing.T) {
	pub := &sessionPublisher{}
	if got := pub.checkSessionTokenIP(foreignIPTok(), "127.0.0.1"); got == "" {
		t.Fatal("locked publisher allowed a foreign-IP session login")
	}
	if got := pub.checkSessionTokenIP(foreignIPTok(), "192.0.2.1"); got != "" {
		t.Fatalf("locked publisher rejected the stamp-address login: %q", got)
	}
}

// TestCheckSessionTokenIPPassThrough: with the flag disabled the SAME
// foreign-IP login is allowed — checkSessionTokenIP returns "" immediately
// (pass-through). Zero-value publishers stay LOCKED (ipLockDisabled zero
// value = false): a hand-built publisher never silently drops the control.
func TestCheckSessionTokenIPPassThrough(t *testing.T) {
	locked := &sessionPublisher{}
	if got := locked.checkSessionTokenIP(foreignIPTok(), "127.0.0.1"); got == "" {
		t.Fatal("zero-value publisher allowed a foreign-IP login — zero value must stay LOCKED")
	}

	pub := &sessionPublisher{}
	pub.SetIPLock(false)
	if got := pub.checkSessionTokenIP(foreignIPTok(), "127.0.0.1"); got != "" {
		t.Fatalf("disabled IP lock rejected a foreign-IP login: %q (want pass-through)", got)
	}
	// Single-use tokens were never IP-checked — unchanged either way.
	if got := pub.checkSessionTokenIP(&models.TokenPayload{Mode: ""}, "127.0.0.1"); got != "" {
		t.Fatalf("single-use token rejected under disabled lock: %q", got)
	}

	pub.SetIPLock(true)
	if got := pub.checkSessionTokenIP(foreignIPTok(), "127.0.0.1"); got == "" {
		t.Fatal("SetIPLock(true) did not re-arm the lock")
	}
}

// TestSetIPLockWiredThroughProxies: the setter is promoted onto ALL FOUR
// proxies (the publisher is embedded), so one knob reaches every plane —
// compile-time proof that the wiring surface exists everywhere.
func TestSetIPLockWiredThroughProxies(t *testing.T) {
	mysql := &MySQLProxy{}
	pg := &PGProxy{}
	mssql := &MSSQLProxy{}
	oracle := &OracleProxy{}
	mysql.SetIPLock(false)
	pg.SetIPLock(false)
	mssql.SetIPLock(false)
	oracle.SetIPLock(false)
	mysql.SetIPLock(true)
	pg.SetIPLock(true)
	mssql.SetIPLock(true)
	oracle.SetIPLock(true)
}
