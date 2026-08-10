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

func TestSessionRoundTrip(t *testing.T) {
	roundTrip(t, Session{
		Username: "bob.ad",
		Expires:  time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC),
	})
}
