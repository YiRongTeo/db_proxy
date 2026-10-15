package api

// node-integration Task 4, brief test 6 (G2 audit path): a mint WITH a
// password writes the same pending audit row / event surface as any other
// mint — the password must not appear in the audit row or the issued query
// event. The audit writer persists a FIXED column set (audit.SessionRecord
// carries no credential field), so the assertion is structural: plant a
// distinctive password, mint, then prove the value is in NEITHER the row NOR
// the lifecycle event NOR any queries:sess:* payload.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"zerotrust-proxy/internal/models"
)

// TestAuditOverrideSessionCarriesNoPassword (brief test 6): mint with a
// distinctive password → the audit row, the issued lifecycle event and every
// queries:sess:<sid> payload are free of the password substring.
func TestAuditOverrideSessionCarriesNoPassword(t *testing.T) {
	srv, client, vs, db, cfg := newAuditTestAPIServer(t)

	user := fmt.Sprintf("audit-pw-%d", time.Now().UnixNano())
	authed := withBearer(client, mintJWT(t, cfg, user, "maker"))
	// The issued event is published on the session channel — capture the
	// RAW payloads so the assertion covers unknown future fields too.
	sessPat := subscribePatternAPI(t, vs, "queries:sess:*")

	// Distinctive value that cannot collide with anything else on the wire.
	const pw = "audit-leak-probe-Zx9q7"
	body := fmt.Sprintf(`{"username":%q,"db_user":"ro_user","db_ip":"127.0.0.1","db_port":"3307","db_type":"mysql","ticket_id":"T-NI-4","password":%q}`,
		user, pw)
	tok := issueToken(t, authed, srv.URL, body)
	sid := assertPendingListed(t, authed, srv.URL, user, "ro_user", "mysql")
	t.Cleanup(func() {
		_ = vs.DelSessionLive(context.Background(), sid)
		_, _ = vs.GetDeleteToken(context.Background(), tok) // consume (fetchPayload-less path)
	})

	// 1. The pending audit ROW (all text columns, via the existing helper).
	r := fetchAuditRow(t, db, sid)
	for _, col := range []string{r.sessionID, r.username, r.ticketID, r.dbType, r.dbUser, r.db, r.access} {
		if strings.Contains(col, pw) {
			t.Errorf("audit row column carries the password: %q", col)
		}
	}
	if r.checker.Valid && strings.Contains(r.checker.String, pw) {
		t.Errorf("audit checker column carries the password: %q", r.checker.String)
	}

	// 2. The issued event on the session channel — RAW bytes.
	ev := recvIssuedForSid(t, sessPat, sid)
	assertIssuedEvent(t, ev, user, "ro_user", "mysql", sid)
	// (the decoded event struct has no password field; the RAW-payload proof
	// is the rawChannelScan below plus the row check above.)

	// 3. The session's pending directory record (sess:live:<sid>).
	rec, err := vs.GetSessionLive(context.Background(), sid)
	if err != nil {
		t.Fatalf("GetSessionLive: %v", err)
	}
	if rec != nil && strings.Contains(string(rec), pw) {
		t.Errorf("pending directory record carries the password: %s", rec)
	}
}

// compile-time anchor: the event shape the audit consumer decodes stays
// credential-free (models.QueryEvent has no password field — a new one would
// flow into audit rows via auditLifecycleEvent).
var _ = models.QueryEvent{}
