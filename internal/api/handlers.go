package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// maxBodyBytes caps JSON request bodies at 1 MB.
const maxBodyBytes = 1 << 20

// sessionPendingTTL is the lifetime of a sess:live:<sid> record written at
// TOKEN ISSUE time (Task 8.11): a token whose maker never connects expires
// from the session directory on its own. Mirrors the data plane's
// sessionLiveTTL heartbeat so pending and active records share one cadence.
const sessionPendingTTL = 60 * time.Second

// dbPortDefaults is the SINGLE SOURCE OF TRUTH for default backend ports on
// POST /api/token (node-integration Task 1): db_type → db_subtype → port.
// It resolves an omitted db_port after type validation; an explicit db_port
// always wins (G3). Canonical ports: mysql→3306, postgres→5432, mssql→1433,
// oracle→1521; an absent db_subtype is looked up under the key "default".
// Subtypes beyond "default" (e.g. "master", "slave") are supported by the
// STRUCTURE — no extra entries ship yet, so a subtype with no entry (and no
// explicit db_port) fails with 422. FUTURE DB_TYPES AND SUBTYPES ARE ADDED
// HERE — nowhere else in the codebase needs touching.
var dbPortDefaults = map[string]map[string]string{
	"mysql":    {"default": "3306"},
	"postgres": {"default": "5432"},
	"mssql":    {"default": "1433"},
	"oracle":   {"default": "1521"},
}

// handleHealth reports Control Plane + Valkey liveness.
func (a *api) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := a.vs.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "valkey": "down"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "valkey": "up"})
}

// handleDBPresets returns the configured database presets (bearer JWT principal required).
func (a *api) handleDBPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.cfg.DBPresets)
}

// decodeJSON reads and decodes a JSON request body, capped at 1 MB. The
// MaxBytesReader is bound to the ResponseWriter so an oversized body aborts
// the connection instead of dribbling, and unknown fields are REJECTED —
// a misspelled field is a client bug, not a silently-ignored field (review
// 9.9 MINOR).
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// writeJSON encodes v as a JSON response with the proper Content-Type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleToken issues a single-use DB token. Auth: a VALID BEARER JWT ONLY —
// the route is wrapped in requireJWT (api.go), so by the time the handler
// runs the principal session is always present (sessionFrom(r) != nil) and
// the Valkey jti denylist has ALREADY been consulted: a logged-out token
// cannot mint (Task 7 — one auth path for revocation and mint). The
// control-plane API key (X-Api-Key) was retired in Task 7; there is no key
// fallback.
func (a *api) handleToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		DBUser   string `json:"db_user"`
		DBIP     string `json:"db_ip"`
		// DBPort is OPTIONAL (node-integration Task 1): an explicit value is
		// stored verbatim; when absent the port is resolved from
		// dbPortDefaults via db_type + DBSubtype (default "default").
		DBPort string `json:"db_port"`
		DBType string `json:"db_type"`
		// DBSubtype (node-integration Task 1) refines the default-port
		// lookup (e.g. "master"/"slave" — structure only today). Free-form
		// but trimmed, ≤64 chars, no control chars; absent = subtype
		// "default". It never reaches the payload or credentials key — the
		// port is resolved before either is built.
		DBSubtype string `json:"db_subtype,omitempty"`
		TicketID  string `json:"ticket_id,omitempty"`
		// Mode (Task 9.13) requests a token flavor: "single-use" (default)
		// or "session". Absent → the target preset's token_mode, then the
		// api.token_mode config default.
		Mode string `json:"mode,omitempty"`
		// IdleSeconds (Task 9.13 per-token idle override): the session
		// idle timeout for THIS token. 0/absent = the data plane's
		// session.idle_seconds default (applies to every token mode).
		IdleSeconds int `json:"idle_seconds,omitempty"`
		// EndTime (node-integration Task 2) is the OPTIONAL end_time raw
		// JSON value — RFC3339 UTC string OR integer epoch seconds (see
		// the parse block below). Kept as json.RawMessage so the three
		// legitimate shapes (string / integer / null) can be told apart
		// without interface{} boxing.
		EndTime json.RawMessage `json:"end_time,omitempty"`
		// Password (node-integration Task 4) is the OPTIONAL at-mint
		// credential override: when present, the mint writes it to the
		// SEPARATE Valkey key ztcred:<session_id> (TTL == the token's
		// resolved TTL) and stamps payload.cred_override — the data plane
		// then consults the override FIRST when connecting. HARD RULES
		// (G2): the value is never logged, never echoed in the response,
		// never written to audit rows or events; > 256 bytes and empty
		// values are rejected 422 (an empty string is not a credential).
		// Kept as a POINTER so "absent" (G3 — existing resolution) and
		// "present but empty" (a client bug → 422) stay distinguishable.
		Password *string `json:"password,omitempty"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	// Review 9.9 CRITICAL (a): the requester's username is BOUND to the
	// bearer principal — requireJWT (Task 7) guarantees one, so this branch
	// ALWAYS fires. The body username (if present) must match the
	// principal's sub — otherwise the request is rejected — and the token is
	// ALWAYS issued for the principal's username. Mint-for-others arrives
	// only with the Phase-2 delegation rule (a principal cannot mint in
	// another identity's name).
	if sess := sessionFrom(r); sess != nil {
		if req.Username != "" && req.Username != sess.Username {
			http.Error(w, `{"error":"username does not match session"}`, http.StatusBadRequest)
			return
		}
		req.Username = sess.Username
	}
	req.Username = strings.TrimSpace(req.Username)
	// node-integration Task 1: db_port is no longer a required field — the
	// required set is username/db_user/db_ip (+ ticket_id below). The port
	// is resolved AFTER db_type validation, so an absent db_port here is
	// filled by the dbPortDefaults map or rejected 422 there.
	if req.Username == "" || req.DBUser == "" || req.DBIP == "" {
		http.Error(w, `{"error":"missing required fields"}`, http.StatusBadRequest)
		return
	}
	// Spec amendment 9b: every token must be traceable to a ticket.
	// Review 9.9 MINOR: ticket_id is also shape-validated — it lands in
	// audit rows and event payloads, so no whitespace/control characters and
	// a bounded length.
	if req.TicketID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ticket_id required"})
		return
	}
	tid := strings.TrimSpace(req.TicketID)
	if len(tid) > 128 || strings.ContainsAny(tid, " 	\r\n") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ticket_id"})
		return
	}
	req.TicketID = tid
	// node-integration Task 1: db_subtype shape validation, same review
	// hygiene as ticket_id/session_id — it feeds the dbPortDefaults map
	// lookup, so it is trimmed first (a padded subtype must behave as its
	// bare form) and rejected 400 when overlong or carrying control
	// characters.
	req.DBSubtype = strings.TrimSpace(req.DBSubtype)
	if len(req.DBSubtype) > 64 || strings.ContainsFunc(req.DBSubtype, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid db_subtype"})
		return
	}
	if req.DBType != "mysql" && req.DBType != "postgres" && req.DBType != "mssql" && req.DBType != "oracle" {
		http.Error(w, `{"error":"db_type must be mysql, postgres, mssql or oracle"}`, http.StatusUnprocessableEntity)
		return
	}
	// node-integration Task 1: port resolution — an explicit db_port is
	// stored VERBATIM (existing validation unchanged, explicit wins — G3);
	// only when absent does the dbPortDefaults map supply the port from
	// db_type + db_subtype (absent subtype = "default"). A type-valid
	// request whose type+subtype has no map entry fails 422 with the
	// documented message — never a guessed port.
	if req.DBPort == "" {
		subtype := req.DBSubtype
		if subtype == "" {
			subtype = "default"
		}
		port, ok := dbPortDefaults[req.DBType][subtype]
		if !ok {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error": "no default port for db_type/db_subtype; pass db_port explicitly",
			})
			return
		}
		req.DBPort = port
	}
	// node-integration Task 4: the at-mint credential override — shape
	// validation only here; the KEY write happens after the token is stored
	// (the sid is generated below) with the token's own resolved TTL.
	// G3: an absent password (or JSON null) leaves this block untouched.
	// An explicit EMPTY string is refused (422): an override carrying
	// nothing would flip the data plane onto a dead key. 256 bytes is the
	// cap (inclusive) — beyond it the value is rejected, never truncated
	// (a silently-shortened credential would fail the backend connect
	// opaquely). The value NEVER appears in any error message or log line
	// here (G2).
	hasPassword := false
	if req.Password != nil {
		if *req.Password == "" {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error": "password must not be empty",
			})
			return
		}
		if len(*req.Password) > 256 {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error": "password exceeds 256 bytes",
			})
			return
		}
		hasPassword = true
	}
	// Task 9.13: token mode resolution — request mode wins, then the
	// target preset's token_mode, then the api.token_mode default.
	// Anything other than the two known flavors is a client error.
	mode := req.Mode
	if mode == "" {
		mode = a.modeForPreset(req.DBType, req.DBUser, req.DBIP, req.DBPort)
	}
	if mode == "" {
		mode = a.cfg.TokenMode
	}
	if mode == "" {
		mode = "single-use" // config default guard
	}
	if mode != "single-use" && mode != "session" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "mode must be single-use or session"})
		return
	}
	// Task 9.13 per-token idle override: non-negative only (0/absent =
	// follow the data-plane session.idle_seconds default).
	if req.IdleSeconds < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "idle_seconds must be >= 0"})
		return
	}
	// node-integration Task 2: OPTIONAL end_time — the instant this token
	// (and any session it opens) must die. Accepted shapes: RFC3339 UTC
	// string OR integer epoch seconds. JSON null / absent → no end_time
	// (G3: existing clients unaffected). Everything else — a malformed
	// string, a non-integer number, a bool/object/array — is a client bug
	// → 400 "invalid end_time".
	var endTime time.Time
	hasEndTime := false
	if len(req.EndTime) > 0 && string(req.EndTime) != "null" {
		raw := strings.TrimSpace(string(req.EndTime))
		if len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
			// RFC3339 shape. Numeric UTC offsets (e.g. "+02:00") are
			// ACCEPTED and normalize to the same instant — rejecting a
			// client clock's local-offset spelling would break
			// integrations for no security gain; "Z" is the documented
			// contract.
			parsed, err := time.Parse(time.RFC3339, raw[1:len(raw)-1])
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid end_time"})
				return
			}
			endTime = parsed
		} else {
			// Integer epoch seconds — strconv.ParseInt rules out floats,
			// exponents, and out-of-int64-range values.
			secs, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid end_time"})
				return
			}
			endTime = time.Unix(secs, 0)
		}
		hasEndTime = true
	}
	if hasEndTime {
		// Spec decision: end_time ≤ now is already expired → 422.
		if !endTime.After(time.Now()) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "end_time is in the past"})
			return
		}
		// api.max_session_seconds > 0 caps the end_time horizon; 0 =
		// uncapped. A mint at exactly the ceiling is accepted.
		if a.cfg.MaxSessionSeconds > 0 {
			maxEnd := time.Now().Add(time.Duration(a.cfg.MaxSessionSeconds) * time.Second)
			if endTime.After(maxEnd) {
				writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "end_time exceeds max session duration"})
				return
			}
		}
	}
	// Review 9.9 MINOR: issuance throttle — bound token minting. Every
	// request is bearer-authenticated (Task 7) and the username is bound to
	// the principal, so the username is ALWAYS the throttle key (the
	// API-key-by-client-IP branch was removed together with the key).
	issueKey := req.Username
	if a.issueLimiter.blocked(issueKey, time.Now()) {
		http.Error(w, `{"error":"token issuance rate limited"}`, http.StatusTooManyRequests)
		return
	}
	token, err := store.NewToken()
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	// Task 8.11: stamp the session id at ISSUE time so the session is
	// visible to checkers (status "pending") before the maker connects —
	// the gating-deadlock fix. The data plane adopts this id on connect.
	access := a.accessForPreset(req.DBType, req.DBUser, req.DBIP, req.DBPort)
	// Task 7 role gate (user directive): a checker-role principal may mint
	// only read-access (or ungated ad-hoc) tokens. A checker minting a
	// write-access token would be its own maker — it could open a write
	// session and watch itself, bypassing the data plane's SoD write gate
	// (Task 8.6: a write session's queries are blocked unless a checker
	// WATCHES it, and the checker can never watch its own session). No
	// matching preset → access "" — UNGATED, NOT read: the data plane
	// gates only on literal access=="write", so "" rides the resolved
	// backend account's real privilege and ad-hoc checker mints on
	// read-only accounts stay available (the plan's access semantics).
	// Effective read-only-ness for write-capable accounts is therefore a
	// config-hygiene property: every credentials key backed by rw creds
	// MUST pair with an access:write preset (RUN.md §2.3) — otherwise a
	// checker could mint "" over those creds and run gate-free.
	if sess := sessionFrom(r); sess != nil && sess.Role == "checker" && access == "write" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "checker role limited to read-only tokens"})
		return
	}
	payload := models.TokenPayload{
		Username: req.Username, DBUser: req.DBUser, DBIP: req.DBIP,
		DBPort: req.DBPort, DBType: req.DBType, TicketID: req.TicketID,
		Access:    access,
		SessionID: models.NewSessionID(),
		Mode:      mode,
		// Task 9.13 per-token idle override: 0/absent = the data plane's
		// session.idle_seconds default (every token mode); >0 overrides it
		// for sessions opened with this token.
		IdleSeconds: req.IdleSeconds,
	}
	// node-integration Task 2: the end_time instant, unix seconds —
	// stamped ONLY when the mint carried one (absent end_time → payload
	// and response stay free of expires_at — G3). Informational: the
	// enforcement is the key TTL below.
	// node-integration Task 4: stamp the override flag so the data plane
	// consults ztcred:<sid> FIRST. The password itself NEVER rides the
	// payload (G2) — it lives only in the ztcred: key written below.
	if hasPassword {
		payload.CredOverride = true
	}
	if hasEndTime {
		payload.ExpiresAt = endTime.Unix()
	}
	// node-integration Task 2: ttl = min(end_time − now, existing TTL
	// rules). The end_time deadline is computed FIRST and the mode's own
	// rule below takes min with it — a longer end_time never extends a
	// token past its configured TTL. (For session mode with an INFINITE
	// configured TTL the end_time-derived value becomes the finite key
	// lifetime; the data plane's idle/max-lifetime machinery applies on
	// top, unchanged. When the tok: key expires, the existing revoke path
	// — poll + keyspace fast path — closes running sessions.)
	endTimeTTL := time.Duration(0)
	if hasEndTime {
		endTimeTTL = time.Until(endTime)
	}
	ttl := time.Duration(a.cfg.TokenTTL) * time.Second
	if endTimeTTL > 0 && (ttl <= 0 || endTimeTTL < ttl) {
		ttl = endTimeTTL
	}
	if mode == "session" {
		// Task 9.13 session tokens: TTL from api.session_token_ttl_seconds
		// (0 = INFINITE — the token lives until revoked), stamped issue IP
		// (every connection must come from it) and issued_at (max-lifetime
		// anchor). MaxUses is meaningless here — session tokens are not
		// consumed — so it stays absent.
		ttl = time.Duration(a.cfg.SessionTokenTTL) * time.Second
		if endTimeTTL > 0 && (ttl <= 0 || endTimeTTL < ttl) {
			ttl = endTimeTTL
		}
		payload.IP = models.NormalizeIP(clientIP(r))
		payload.IssuedAt = time.Now().UTC().Unix()
	} else {
		// Task 9.12: connection budget per token (1 = single-use default).
		// Clamped — a config of 0 or negative must never produce a token
		// that dies on its first use unexpectedly; the store also treats
		// < 1 as 1, so this is belt-and-braces.
		payload.MaxUses = a.cfg.TokenMaxUses
		if payload.MaxUses < 1 {
			payload.MaxUses = 1
		}
	}
	if err := a.vs.SetToken(r.Context(), token, payload, ttl); err != nil {
		a.log.Error("token store", "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	// node-integration Task 4: the at-mint credential override. The TTL is
	// the token's own resolved value (the SAME `ttl` just used for tok: —
	// end_time- and mode-aware, so the override can never outlive the
	// session it belongs to; G2). The write happens AFTER SetToken because
	// the payload needs the session id — but a failed override write fails
	// the MINT (500): shipping a cred_override-stamped token without its
	// credential would leave the data plane to fall back to credentials
	// the client explicitly overrode. The session is still cleaned up:
	// SetToken wrote tok:, so it is deleted here before the 500.
	if hasPassword {
		if err := a.vs.SetCredOverride(r.Context(), payload.SessionID, *req.Password, ttl); err != nil {
			a.log.Error("cred override store", "err", err, "session_id", payload.SessionID)
			_ = a.vs.DeleteToken(r.Context(), token)
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
	}
	// Task 9.13: -1 signals an infinite session token to the client (the
	// token never expires — revocation is explicit). node-integration
	// Task 2: an end_time turns the infinite token finite — report the
	// endTime-derived TTL instead of −1.
	expiresIn := int(ttl.Seconds())
	if mode == "session" && a.cfg.SessionTokenTTL <= 0 && endTimeTTL <= 0 {
		expiresIn = -1
	}
	a.issueLimiter.hit(issueKey, time.Now())
	// The token is stored; now list the session at issue time (pending
	// directory record + action=issued lifecycle event). Best-effort — a
	// directory/pubsub hiccup must not fail an already-stored token, but
	// it IS logged.
	a.recordPendingSession(r.Context(), &payload)
	// Task 9.7 audit: persist the pending row (maker username, ticket, db
	// target, access). Best-effort like the directory record — an audit
	// write failure is logged, never fatal to the issue. Phase 2b: stamp
	// the requesting JWT's IdP login session id (empty for local logins)
	// so the DB session traces back to the login that requested it.
	loginSID := ""
	if sess := sessionFrom(r); sess != nil {
		loginSID = sess.LoginSessionID
	}
	a.auditUpsertPending(r.Context(), &payload, loginSID)
	a.log.Info("token issued", "username", payload.Username, "db_user", payload.DBUser,
		"db_type", payload.DBType, "ticket", payload.TicketID, "access", payload.Access,
		"session_id", payload.SessionID)
	writeJSON(w, http.StatusOK, models.TokenResponse{
		Token:     token,
		SessionID: payload.SessionID,
		Host:      a.cfg.DataPlaneHost,
		Port:      a.cfg.DataPlanePort,
		ExpiresIn: expiresIn,
		// node-integration Task 2: the absolute expiry (unix seconds) —
		// the end_time instant when one was given; 0/omitted otherwise.
		ExpiresAt: payload.ExpiresAt,
	})
}

// modeForPreset resolves a db_preset's optional token_mode (Task 9.13) for
// the requested target; "" when no preset matches or the preset declares
// none (the api.token_mode default then applies). Mirrors accessForPreset.
func (a *api) modeForPreset(dbType, dbUser, dbIP, dbPort string) string {
	for _, p := range a.cfg.DBPresets {
		if p.DBType == dbType && p.DBUser == dbUser && p.DBIP == dbIP && p.DBPort == dbPort {
			return p.TokenMode
		}
	}
	return ""
}

// pendingSessionRecord is the CONTROL PLANE's sess:live:<sid> payload
// (Task 8.11): the session directory entry for a just-issued token, visible
// to checkers BEFORE the maker ever connects. DB is unknown at issue time
// (the client requests it in the handshake) and is therefore omitted; the
// data plane overwrites the record with the full active shape when the
// session starts.
type pendingSessionRecord struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	DBUser    string    `json:"db_user"`
	DBType    string    `json:"db_type"`
	DB        string    `json:"db,omitempty"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// recordPendingSession makes a just-issued token's session visible to
// checkers at TOKEN ISSUE time (Task 8.11): it writes the sess:live:<sid>
// directory entry with status "pending" (sessionPendingTTL — a token whose
// maker never connects expires on its own) and publishes the action=issued
// lifecycle event to queries:<user> AND queries:sess:<sid> (the same fan-out
// the data plane uses for started/ended; like them, it deliberately skips
// the ticket channel). Best-effort: the token itself is already stored — a
// directory/pubsub failure is logged, never fatal to the issue.
func (a *api) recordPendingSession(ctx context.Context, p *models.TokenPayload) {
	now := time.Now().UTC()
	rec, err := json.Marshal(pendingSessionRecord{
		SessionID: p.SessionID,
		Username:  p.Username,
		DBUser:    p.DBUser,
		DBType:    p.DBType,
		Status:    "pending",
		StartedAt: now,
		LastSeen:  now,
	})
	if err != nil {
		a.log.Error("pending session record marshal", "err", err)
		return
	}
	if err := a.vs.SetSessionLive(ctx, p.SessionID, rec, sessionPendingTTL); err != nil {
		a.log.Error("pending session record store", "err", err, "session_id", p.SessionID)
	}
	ev := models.QueryEvent{
		ID:        models.NewEventID(),
		Ts:        now,
		Kind:      "session",
		Action:    "issued",
		Username:  p.Username,
		DBUser:    p.DBUser,
		DBType:    p.DBType,
		SessionID: p.SessionID,
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		a.log.Error("issued event marshal", "err", err)
		return
	}
	if err := a.vs.Publish(ctx, "queries:"+ev.Username, raw); err != nil {
		a.log.Error("issued event publish", "err", err, "channel", "queries:"+ev.Username)
	}
	if err := a.vs.Publish(ctx, "queries:sess:"+ev.SessionID, raw); err != nil {
		a.log.Error("issued event publish", "err", err, "channel", "queries:sess:"+ev.SessionID)
	}
	a.log.Info("session issued", "username", ev.Username, "db_user", ev.DBUser,
		"db_type", ev.DBType, "session_id", ev.SessionID)
}

// accessForPreset resolves the token's access level from the db_preset that
// matches the requested target (Task 8.6 maker write-gating): a token issued
// for a read-write preset carries access="write" and is subject to the data
// plane's write gate (queries blocked unless a checker watches the session).
// No matching preset → "" — the data plane treats absent access as read (no
// gate), so tokens for ad-hoc targets stay ungated.
func (a *api) accessForPreset(dbType, dbUser, dbIP, dbPort string) string {
	for _, p := range a.cfg.DBPresets {
		if p.DBType == dbType && p.DBUser == dbUser && p.DBIP == dbIP && p.DBPort == dbPort {
			return p.Access
		}
	}
	return ""
}

// handleKill queues a data-plane session kill (bearer JWT principal required). The kill
// is dispatched over the Valkey ctl:kill channel — no HTTP between planes
// (spec amendment 9e). Mode selects the kill scope (Task 8.3 two-level
// kill): "connection" (default) terminates the whole backend session;
// "query" aborts only the in-flight query. The published payload always
// carries the resolved mode so the data plane never has to guess.
func (a *api) handleKill(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Mode      string `json:"mode"`
	}
	if err := decodeJSON(w, r, &req); err != nil || req.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id required"})
		return
	}
	// Review 9.9 MINOR: session_id shape validation — it becomes the ctl:kill
	// channel payload key, so no whitespace/control characters and a bounded
	// length.
	sid := strings.TrimSpace(req.SessionID)
	if len(sid) > 64 || strings.ContainsAny(sid, " 	\r\n") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session_id"})
		return
	}
	req.SessionID = sid
	mode := req.Mode
	if mode == "" {
		mode = "connection"
	}
	if mode != "connection" && mode != "query" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid mode"})
		return
	}
	b, err := json.Marshal(struct {
		SessionID string `json:"session_id"`
		Mode      string `json:"mode"`
	}{SessionID: req.SessionID, Mode: mode})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	if err := a.vs.Publish(r.Context(), "ctl:kill", b); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "kill dispatch failed"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"killed": "queued"})
}

// handleSessions lists the live data-plane session directory (bearer JWT
// principal required). The directory is the sess:live:* keys the data plane
// heartbeats (Task 8.2); thread_id stays backend-internal and is not
// exposed to the checker. An empty directory is encoded as [] (never null).
func (a *api) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := a.vs.ListSessionsParsed(r.Context())
	if err != nil {
		a.log.Error("list sessions", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}
