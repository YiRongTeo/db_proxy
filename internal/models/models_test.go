package models

import (
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

func TestSessionRoundTrip(t *testing.T) {
	roundTrip(t, Session{
		Username: "bob.ad",
		Expires:  time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC),
	})
}
