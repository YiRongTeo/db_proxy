package models

import (
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// roundTrip marshals v, unmarshals into a fresh value of the same type,
// and asserts deep equality between the original and the result.
func roundTrip(t *testing.T, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	got := reflect.New(reflect.TypeOf(v)).Interface()
	if err := json.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshal %T: %v", v, err)
	}
	if !reflect.DeepEqual(v, reflect.ValueOf(got).Elem().Interface()) {
		t.Errorf("%T round-trip mismatch:\nwant: %+v\n got: %+v", v, v, reflect.ValueOf(got).Elem().Interface())
	}
}

func TestTokenPayloadRoundTrip(t *testing.T) {
	roundTrip(t, TokenPayload{
		Username: "alice.ad",
		DBUser:   "app_ro",
		DBIP:     "10.0.0.5",
		DBPort:   "3306",
		DBType:   "mysql",
		TicketID: "TCKT-1042",
	})
}

func TestTokenPayloadAccessRoundTrip(t *testing.T) {
	// Task 8.6: the access field (read|write) round-trips through JSON.
	roundTrip(t, TokenPayload{
		Username: "alice.ad",
		DBUser:   "app_rw",
		DBIP:     "10.0.0.5",
		DBPort:   "3306",
		DBType:   "mysql",
		TicketID: "TCKT-1042",
		Access:   "write",
	})
}

func TestTokenPayloadEmptyAccessOmitted(t *testing.T) {
	// Task 8.6 backward compatibility: a payload without access (legacy
	// tokens / read-only targets) must marshal WITHOUT the access key — the
	// data plane reads its absence as "read" (gate not applied).
	p := TokenPayload{
		Username: "alice.ad",
		DBUser:   "app_ro",
		DBIP:     "10.0.0.5",
		DBPort:   "3306",
		DBType:   "mysql",
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "access") {
		t.Errorf("expected access to be omitted, got %s", data)
	}
	// And an old wire payload WITHOUT the key decodes with Access == "".
	var got TokenPayload
	if err := json.Unmarshal([]byte(`{"username":"alice.ad","db_user":"app_ro","db_ip":"10.0.0.5","db_port":"3306","db_type":"mysql","ticket_id":"TCKT-1042"}`), &got); err != nil {
		t.Fatalf("unmarshal legacy payload: %v", err)
	}
	if got.Access != "" {
		t.Errorf("legacy payload decoded Access = %q, want \"\"", got.Access)
	}
}

func TestTokenPayloadEmptyTicketIDOmitted(t *testing.T) {
	p := TokenPayload{
		Username: "alice.ad",
		DBUser:   "app_ro",
		DBIP:     "10.0.0.5",
		DBPort:   "3306",
		DBType:   "mysql",
		// TicketID intentionally empty.
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "ticket_id") {
		t.Errorf("expected ticket_id to be omitted, got %s", data)
	}
}

func TestTokenPayloadSessionIDRoundTrip(t *testing.T) {
	// Task 8.11: the control-plane-stamped session id round-trips through
	// JSON alongside the access level.
	roundTrip(t, TokenPayload{
		Username:  "alice.ad",
		DBUser:    "app_rw",
		DBIP:      "10.0.0.5",
		DBPort:    "3306",
		DBType:    "mysql",
		TicketID:  "TCKT-1042",
		Access:    "write",
		SessionID: "sid-0123456789abcdef",
	})
}

func TestTokenPayloadEmptySessionIDOmitted(t *testing.T) {
	// Task 8.11 backward compatibility: a payload without a session id
	// (pre-8.11 tokens / old tests) must marshal WITHOUT the session_id
	// key, and an old wire payload without the key decodes with
	// SessionID == "" — the data plane then falls back to generating one.
	p := TokenPayload{
		Username: "alice.ad",
		DBUser:   "app_ro",
		DBIP:     "10.0.0.5",
		DBPort:   "3306",
		DBType:   "mysql",
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "session_id") {
		t.Errorf("expected session_id to be omitted, got %s", data)
	}
	// And an old wire payload WITHOUT the key decodes with SessionID == "".
	var got TokenPayload
	if err := json.Unmarshal([]byte(`{"username":"alice.ad","db_user":"app_ro","db_ip":"10.0.0.5","db_port":"3306","db_type":"mysql","ticket_id":"TCKT-1042"}`), &got); err != nil {
		t.Fatalf("unmarshal legacy payload: %v", err)
	}
	if got.SessionID != "" {
		t.Errorf("legacy payload decoded SessionID = %q, want \"\"", got.SessionID)
	}
}

func TestNewSessionIDFormat(t *testing.T) {
	// Task 8.11: the shared sid generator produces the sid-<hex> form the
	// data plane already used (sid- prefix + 16 hex chars) and unique ids.
	a := NewSessionID()
	if !strings.HasPrefix(a, "sid-") || len(a) != 4+16 {
		t.Errorf("NewSessionID() = %q, want sid- prefix + 16 hex chars", a)
	}
	if _, err := hex.DecodeString(a[4:]); err != nil {
		t.Errorf("NewSessionID() suffix %q is not hex: %v", a[4:], err)
	}
	b := NewSessionID()
	if a == b {
		t.Errorf("NewSessionID() returned the same id twice: %q", a)
	}
}

func TestTokenResponseRoundTrip(t *testing.T) {
	roundTrip(t, TokenResponse{
		Token:     "sess_9f2c1a7b",
		Host:      "127.0.0.1",
		Port:      "3306",
		ExpiresIn: 300,
	})
}

func TestQueryEventRoundTrip(t *testing.T) {
	roundTrip(t, QueryEvent{
		ID:         "evt_01",
		Ts:         time.Date(2026, 8, 11, 9, 30, 15, 0, time.UTC),
		Kind:       "query",
		Username:   "alice.ad",
		TicketID:   "TCKT-1042",
		DBUser:     "app_ro",
		DBIP:       "10.0.0.5",
		DBPort:     "3306",
		DBType:     "mysql",
		SQL:        "SELECT 1",
		ClientAddr: "192.168.1.20:51234",
	})
}

func TestQueryEventEnhancementRoundTrip(t *testing.T) {
	// An event with ALL Phase 6 enhancement fields populated must
	// round-trip exactly through JSON.
	roundTrip(t, QueryEvent{
		ID:         "evt_01",
		Ts:         time.Date(2026, 8, 11, 9, 30, 15, 0, time.UTC),
		Kind:       "query",
		Username:   "alice.ad",
		TicketID:   "TCKT-1042",
		DBUser:     "app_ro",
		DBIP:       "10.0.0.5",
		DBPort:     "3306",
		DBType:     "mysql",
		SQL:        "SELECT * FROM orders WHERE id = 42",
		ClientAddr: "192.168.1.20:51234",
		StmtType:   "select",
		SessionID:  "sess_dp_9f2c1a7b",
		Status:     "error",
		Error:      "syntax error near 'WHERE'",
		Columns:    []string{"id", "customer", "total"},
		Rows:       [][]string{{"42", "alice", "99.50"}, {"43", "bob", "12.00"}},
		Truncated:  true,
	})
}

func TestQueryEventBackwardCompatNoNewKeys(t *testing.T) {
	// An event produced WITHOUT the enhancement fields must marshal to the
	// old wire shape: every legacy key present, none of the new keys.
	ev := QueryEvent{
		ID:         "evt_01",
		Ts:         time.Date(2026, 8, 11, 9, 30, 15, 0, time.UTC),
		Kind:       "query",
		Username:   "alice.ad",
		TicketID:   "TCKT-1042",
		DBUser:     "app_ro",
		DBIP:       "10.0.0.5",
		DBPort:     "3306",
		DBType:     "mysql",
		SQL:        "SELECT 1",
		ClientAddr: "192.168.1.20:51234",
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("unmarshal into key map: %v", err)
	}
	for _, k := range []string{"id", "ts", "kind", "username", "ticket_id", "db_user", "db_ip", "db_port", "db_type", "sql", "client_addr"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("backward compat: legacy key %q missing from JSON: %s", k, data)
		}
	}
	for _, k := range []string{"stmt_type", "session_id", "status", "error", "columns", "rows", "truncated"} {
		if _, ok := keys[k]; ok {
			t.Errorf("backward compat: unexpected new key %q present in JSON: %s", k, data)
		}
	}
}

func TestQueryEventSessionRoundTrip(t *testing.T) {
	// An event with ALL fields populated — legacy, Phase 6 enhancement, and
	// Phase 8 session fields (action, db) — must round-trip exactly through JSON.
	roundTrip(t, QueryEvent{
		ID:         "evt_01",
		Ts:         time.Date(2026, 8, 11, 9, 30, 15, 0, time.UTC),
		Kind:       "session",
		Username:   "alice.ad",
		TicketID:   "TCKT-1042",
		DBUser:     "app_ro",
		DBIP:       "10.0.0.5",
		DBPort:     "3306",
		DBType:     "mysql",
		SQL:        "SELECT 1",
		ClientAddr: "192.168.1.20:51234",
		StmtType:   "select",
		SessionID:  "sess_dp_9f2c1a7b",
		Status:     "ok",
		Columns:    []string{"id"},
		Rows:       [][]string{{"42"}},
		Truncated:  false,
		Action:     "started",
		DB:         "appdb",
	})
}

func TestQueryEventSessionBackwardCompatNoNewKeys(t *testing.T) {
	// An event produced WITHOUT the Phase 8 session fields must marshal to the
	// old wire shape: every legacy key present, none of the new keys.
	ev := QueryEvent{
		ID:         "evt_01",
		Ts:         time.Date(2026, 8, 11, 9, 30, 15, 0, time.UTC),
		Kind:       "query",
		Username:   "alice.ad",
		TicketID:   "TCKT-1042",
		DBUser:     "app_ro",
		DBIP:       "10.0.0.5",
		DBPort:     "3306",
		DBType:     "mysql",
		SQL:        "SELECT 1",
		ClientAddr: "192.168.1.20:51234",
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("unmarshal into key map: %v", err)
	}
	for _, k := range []string{"id", "ts", "kind", "username", "ticket_id", "db_user", "db_ip", "db_port", "db_type", "sql", "client_addr"} {
		if _, ok := keys[k]; !ok {
			t.Errorf("backward compat: legacy key %q missing from JSON: %s", k, data)
		}
	}
	for _, k := range []string{"stmt_type", "session_id", "status", "error", "columns", "rows", "truncated", "action", "db"} {
		if _, ok := keys[k]; ok {
			t.Errorf("backward compat: unexpected new key %q present in JSON: %s", k, data)
		}
	}
}

func TestSessionRoundTrip(t *testing.T) {
	roundTrip(t, Session{
		Username: "bob.ad",
	})
}

// TestNewEventID (Task 9.9): NewEventID returns the 16-hex event id format
// the control plane publishes in lifecycle events — same generator family
// as NewSessionID (deduplicated via randomHex), distinct values per call.
func TestNewEventID(t *testing.T) {
	a, b := NewEventID(), NewEventID()
	for _, id := range []string{a, b} {
		if len(id) != 16 {
			t.Errorf("NewEventID() = %q, want 16 hex chars", id)
		}
		for _, c := range id {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				t.Errorf("NewEventID() = %q contains non-hex char %q", id, c)
			}
		}
	}
	if a == b {
		t.Errorf("NewEventID() twice = %q, want distinct values", a)
	}
	if !strings.HasPrefix(NewSessionID(), "sid-") {
		t.Errorf("NewSessionID() = %q, want sid- prefix", NewSessionID())
	}
}
