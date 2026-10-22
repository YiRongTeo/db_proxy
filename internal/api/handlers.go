package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// maxBodyBytes caps JSON request bodies at 1 MB.
const maxBodyBytes = 1 << 20

// compatDBPortNormalizes a decoded db_port JSON value (kept as RawMessage
// so number, string, and null stay distinguishable) into the canonical
// DECIMAL STRING the port map and payload expect: a JSON integer and a
// numeric string are the same port (3306 == "3306"); whitespace is
// trimmed. A fractional number or any non-numeric shape is a client error
// — the returned message NAMES the field.
func compatDBPort(raw json.RawMessage) (string, string) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", ""
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 1 && s[0] == '"' && s[len(s)-1] == '"' {
		unq, err := strconv.Unquote(s)
		if err != nil {
			return "", "db_port must be an integer or numeric string"
		}
		s = unq
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "db_port must be an integer or numeric string"
	}
	if _, err := strconv.ParseInt(s, 10, 64); err != nil {
		return "", "db_port must be an integer or numeric string"
	}
	return s, ""
}

// sessionPendingTTL is the lifetime of a sess:live:<sid> record written at
// TOKEN ISSUE time: a token whose maker never connects expires from the
// session directory on its own. Mirrors the data plane's sessionLiveTTL
// heartbeat so pending and active records share one cadence.
const sessionPendingTTL = 60 * time.Second

// dbPortDefaults resolves an omitted db_port on POST /api/token:
// db_type → db_subtype ("default" when absent) → port. An explicit db_port
// always wins; a subtype with no entry fails with 422. Future db_types and
// subtypes are added HERE and nowhere else.
var dbPortDefaults = map[string]map[string]string{
	"mysql":    {"default": "3306"},
	"mariadb":  {"default": "6603"},
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
// a misspelled field is a client bug, not a silently-ignored field.
//
// The returned error is the raw stdlib decode error (it names the
// offending field/type — e.g. "json: cannot unmarshal number into Go
// struct field .db_port of type string" — and carries no secrets);
// callers surface it verbatim in the 400 body instead of an opaque
// "bad request".
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

// handleToken issues a DB token (single-use or session mode). Auth: a
// VALID BEARER JWT ONLY —
// the route is wrapped in requireJWT (api.go), so by the time the handler
// runs the principal session is always present (sessionFrom(r) != nil) and
// the Valkey jti denylist has ALREADY been consulted: a logged-out token
// cannot mint. There is no API-key fallback.
func (a *api) handleToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		DBUser   string `json:"db_user"`
		DBIP     string `json:"db_ip"`
		// DBPort is OPTIONAL: an explicit value is stored verbatim; an
		// absent one resolves from dbPortDefaults via db_type + DBSubtype.
		// RawMessage so a JSON NUMBER and a numeric STRING both decode —
		// the node client sends numbers; compatDBPort normalizes either
		// to the canonical decimal string ("3306" == 3306).
		DBPort json.RawMessage `json:"db_port,omitempty"`
		DBType string          `json:"db_type"`
		// DBSubtype refines the default-port lookup (e.g. "master"/"slave",
		// structure only today); trimmed, ≤64 chars, no control chars,
		// absent = "default". Never reaches the payload or credentials key.
		DBSubtype string `json:"db_subtype,omitempty"`
		TicketID  string `json:"ticket_id,omitempty"`
		// Mode requests a token flavor: "single-use" (default) or
		// "session". Absent → the target preset's token_mode, then the
		// api.token_mode config default.
		Mode string `json:"mode,omitempty"`
		// IdleSeconds is the per-token idle override: the session idle
		// timeout for THIS token. 0/absent = the data plane's
		// session.idle_seconds default (applies to every token mode).
		IdleSeconds int `json:"idle_seconds,omitempty"`
		// EndTime is the OPTIONAL end_time raw JSON value — RFC3339 string
		// (offset authoritative), a naive datetime/ISO/date-only string
		// (interpreted in the gateway's LOCAL timezone), OR integer epoch
		// seconds. json.RawMessage so the three legitimate shapes (string /
		// integer / null) stay distinguishable.
		//
		// ENDTIME CAMPEX ALIAS: the node client's contract spells the key
		// endTime (camelCase). EndTimeCamel is the EXACT alias of
		// end_time — the only camelCase alias in this API. Both raw keys
		// are read; null counts as absent on either side; both present
		// with non-null, textually different values → 400 (below).
		EndTime      json.RawMessage `json:"end_time,omitempty"`
		EndTimeCamel json.RawMessage `json:"endTime,omitempty"`
		// Password is the OPTIONAL at-mint credential override: the mint
		// writes it to the SEPARATE Valkey key ztcred:<session_id> (TTL ==
		// the token's) and stamps payload.cred_override, so the data plane
		// consults the override FIRST. HARD RULES: never logged, never
		// echoed, never audited; empty and >256-byte values are rejected.
		// A POINTER so "absent" and "present but empty" stay distinguishable.
		Password *string `json:"password,omitempty"`
		// Access is the OPTIONAL explicit access level (Task 6, node-
		// integration): "read"/"ro" (case-insensitive) → canonical "ro" —
		// TRUE read-only, every write SQL command rejected at the proxy;
		// "write"/"rw" → canonical "rw" — the connection is HELD until a
		// checker watches. Absent/null/"" → the preset path unchanged.
		// Anything else → 422 naming the field. Normalization happens
		// BEFORE the checker SoD check below (checker + rw → 403).
		Access string `json:"access,omitempty"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"bad request: %s"}`, err), http.StatusBadRequest)
		return
	}
	// db_port compat: the JSON number-or-string value decodes here into
	// the canonical decimal string. Absent/null stays "" → the existing
	// dbPortDefaults resolution below (unchanged). A fractional number or
	// non-numeric garbage is a 400 that NAMES the field.
	dbPort, portErr := compatDBPort(req.DBPort)
	if portErr != "" {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, portErr), http.StatusBadRequest)
		return
	}
	req.DBPort = json.RawMessage(dbPort)
	// endTime alias reconciliation: the camelCase key IS end_time. Null
	// counts as absent on both sides; both set with non-null values that
	// differ TEXTUALLY → 400 naming both spellings; identical → fine.
	if len(req.EndTimeCamel) > 0 && string(req.EndTimeCamel) != "null" {
		if len(req.EndTime) > 0 && string(req.EndTime) != "null" &&
			string(req.EndTime) != string(req.EndTimeCamel) {
			http.Error(w, `{"error":"end_time and endTime are both set with different values"}`, http.StatusBadRequest)
			return
		}
		req.EndTime = req.EndTimeCamel
	}
	// The requester's username is BOUND to the bearer principal: the body
	// username (if present) must match the principal's sub — otherwise the
	// request is rejected — and the token is ALWAYS issued for the
	// principal's username (no mint-for-others).
	if sess := sessionFrom(r); sess != nil {
		if req.Username != "" && req.Username != sess.Username {
			http.Error(w, `{"error":"username does not match session"}`, http.StatusBadRequest)
			return
		}
		req.Username = sess.Username
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.DBUser == "" || req.DBIP == "" {
		http.Error(w, `{"error":"missing required fields"}`, http.StatusBadRequest)
		return
	}
	// Every token must be traceable to a ticket; ticket_id lands in audit
	// rows and event payloads, so it is shape-validated: no
	// whitespace/control characters, bounded length.
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
	// db_subtype feeds the dbPortDefaults lookup: trimmed first (a padded
	// subtype behaves as its bare form), rejected 400 when overlong or
	// carrying control characters.
	req.DBSubtype = strings.TrimSpace(req.DBSubtype)
	if len(req.DBSubtype) > 64 || strings.ContainsFunc(req.DBSubtype, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid db_subtype"})
		return
	}
	if req.DBType != "mysql" && req.DBType != "mariadb" && req.DBType != "postgres" && req.DBType != "mssql" && req.DBType != "oracle" {
		http.Error(w, `{"error":"db_type must be mysql, mariadb, postgres, mssql or oracle"}`, http.StatusUnprocessableEntity)
		return
	}
	// Port resolution: an explicit db_port is stored verbatim; only an
	// absent one falls back to dbPortDefaults. A type+subtype with no map
	// entry is a 422 — never a guessed port. (DBPort is the compat-
	// normalized canonical decimal string by this point; "" = absent.)
	if string(req.DBPort) == "" {
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
		req.DBPort = json.RawMessage(port)
	}
	// At-mint credential override: shape validation only — the key write
	// happens after SetToken (it needs the sid), with the token's own TTL.
	// An EMPTY string is refused: an override carrying nothing would flip
	// the data plane onto a dead key. >256 bytes is rejected, never
	// truncated. The value NEVER appears in an error message or log line.
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
	// Token mode resolution: request mode wins, then the target preset's
	// token_mode, then the api.token_mode default. Anything other than
	// the two known flavors is a client error.
	mode := req.Mode
	if mode == "" {
		mode = a.modeForPreset(req.DBType, req.DBUser, req.DBIP, string(req.DBPort))
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
	// Per-token idle override: non-negative only (0/absent = follow the
	// data-plane session.idle_seconds default).
	if req.IdleSeconds < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "idle_seconds must be >= 0"})
		return
	}
	// OPTIONAL end_time — the instant this token (and any session it
	// opens) must die. RFC3339 string (an offset, when present, is
	// authoritative), a naive datetime/ISO/date-only string (interpreted
	// in the gateway's LOCAL timezone), or integer epoch seconds; null
	// or absent means none; anything else is a client bug → 400.
	var endTime time.Time
	hasEndTime := false
	if len(req.EndTime) > 0 && string(req.EndTime) != "null" {
		raw := strings.TrimSpace(string(req.EndTime))
		if len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
			s := raw[1 : len(raw)-1]
			// RFC3339 first (unchanged): numeric UTC offsets are
			// ACCEPTED and normalize to the same instant (rejecting
			// them breaks integrations for no security gain). When an
			// offset IS present it is authoritative — the gateway
			// never re-zones it.
			parsed, err := time.Parse(time.RFC3339, s)
			if err != nil {
				// Defensive shapes for clients that send NAIVE
				// timestamps (no timezone): the gateway's LOCAL
				// timezone supplies it — wall-clock intent. Tried in
				// order after RFC3339 fails; only if ALL fail is it
				// a client bug → 400.
				for _, layout := range []string{
					"2006-01-02 15:04:05", // naive datetime (client main-app's shape)
					"2006-01-02T15:04:05", // naive ISO
					"2006-01-02",          // date-only → local midnight
					"2006-01-02 15:04",    // minute precision
				} {
					if t2, e2 := time.ParseInLocation(layout, s, time.Local); e2 == nil {
						parsed, err = t2, nil
						break
					}
				}
			}
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid end_time"})
				return
			}
			endTime = parsed
		} else {
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
	// Issuance throttle: bound token minting. Requests are bearer-
	// authenticated and the username is bound to the principal, so the
	// username is ALWAYS the throttle key.
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
	// Stamp the session id at ISSUE time so the session is visible to
	// checkers (status "pending") before the maker connects; the data
	// plane adopts this id on connect.
	// Task 6 (node-integration) access resolution: the EXPLICIT access
	// field wins when present (normalized read/ro → "ro", write/rw → "rw",
	// case-insensitive; anything else → 422 naming the field); absent/null/
	// "" falls to the preset path — where "read" migrates to "ro" (TRUE
	// read-only) and "write" stays "write" (legacy no-gate, flagged in
	// docs). Normalization happens BEFORE the checker SoD check so a
	// checker sending "rw" is 403'd on the canonical value.
	var access string
	if raw := strings.TrimSpace(req.Access); raw != "" {
		switch strings.ToLower(raw) {
		case "read", "ro":
			access = "ro"
		case "write", "rw":
			access = "rw"
		default:
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error": "access must be read, ro, write or rw",
			})
			return
		}
		// Oracle has NO statement classification (TNS capture is Phase 1):
		// Task 6 + fix round 1: oracle is structurally EXCLUDED from BOTH
		// access levels the explicit field can request. ro: no statement
		// classification exists (TNS Phase-1), so a ro-oracle session
		// would be silently unprotected. rw: the oracle plane has NO hold
		// point (the captured-response TNS login opens the backend in one
		// shot), so an rw-oracle session would skip the checker gate
		// entirely — the data plane refuses such tokens pre-connect
		// (fail-closed) and the mint refuses them here, symmetrically.
		// Preset "write" on oracle keeps the legacy ungated semantics
		// (SELECT-only service accounts remain the data-side control).
		if req.DBType == "oracle" && (access == "ro" || access == "rw") {
			kind := "ro"
			if access == "rw" {
				kind = "rw"
			}
			http.Error(w, fmt.Sprintf(`{"error":"access %s is not supported for db_type oracle — the gateway cannot hold or classify Oracle sessions yet; use a preset write token or a SELECT-only backend account"}`, kind), http.StatusUnprocessableEntity)
			return
		}
	} else {
		access = a.accessForPreset(req.DBType, req.DBUser, req.DBIP, string(req.DBPort))
		// Preset migration: preset "read" now enforces ro (TRUE read-only);
		// preset "write" keeps the legacy no-gate. The oracle guard below
		// covers the migrated ro on oracle — an oracle preset with access
		// "write" keeps the legacy ungated semantics (no silent protection
		// claim is made for it in docs).
		if access == "read" {
			access = "ro"
		}
		if access == "ro" && req.DBType == "oracle" {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
				"error": "access ro is not supported for db_type oracle — the gateway cannot classify Oracle statements yet; use a SELECT-only backend account",
			})
			return
		}
	}
	// Role gate (SoD): a checker-role principal may mint only read-access
	// (or ungated ad-hoc) tokens — a write token would let a checker open
	// a write session and watch itself, bypassing the write gate (a
	// session's queries are blocked unless a checker watches, and the
	// checker can never watch its own session). Task 6: the canonical rw
	// (explicit or aliased) is equally refused — the hold-admission model
	// is still a write capability. No matching preset → access "" —
	// UNGATED, NOT read: the data plane gates only on literal
	// access=="write", so "" rides the backend account's real privilege.
	// Config hygiene consequence: every credentials key backed by rw
	// creds MUST pair with an access:write preset (RUN.md §2.3), or a
	// checker minting "" over it runs gate-free.
	// Task 7 (node-integration): auth.allow_checker_write (default FALSE,
	// strict SoD) is the UAT escape hatch — true skips THIS refusal so a
	// checker-role principal may mint write/rw tokens. The self-watch SoD
	// (checkerMayWatch) is unaffected: even with the flag on, a checker
	// still cannot watch their own session. The oracle+rw refusal above is
	// ALSO unaffected (the data plane has no hold point for oracle —
	// fail-closed regardless of this flag).
	if !a.cfg.AllowCheckerWrite {
		if sess := sessionFrom(r); sess != nil && sess.Role == "checker" && (access == "write" || access == "rw") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "checker role limited to read-only tokens"})
			return
		}
	}
	payload := models.TokenPayload{
		Username: req.Username, DBUser: req.DBUser, DBIP: req.DBIP,
		DBPort: string(req.DBPort), DBType: req.DBType, TicketID: req.TicketID,
		Access:    access,
		SessionID: models.NewSessionID(),
		Mode:      mode,
		// 0/absent = the data plane's session.idle_seconds default (every
		// token mode); >0 overrides it for sessions opened with this token.
		IdleSeconds: req.IdleSeconds,
	}
	// Task 5 (node-integration append) DB-driven routing: resolve the data
	// plane for THIS mint. Routing disabled (default) → the configured
	// plane, byte-identical legacy behavior (G3, no data_plane stamped).
	// Enabled → color + least-loaded lookup with ANY failure falling back
	// to the config plane (a routing failure NEVER fails a mint). The
	// choice rides the payload (data_plane) and the token-issued log line.
	route := a.chooseRoute(r.Context(), a.routeSource, a.cfg.Routing.Color)
	if !route.Fallback {
		payload.DataPlane = route.DataPlane
	}
	// Stamps only what the mint carried: ExpiresAt is informational (the
	// tok: TTL below is the enforcement); CredOverride sends the data
	// plane to ztcred:<sid> FIRST — the password NEVER rides the payload,
	// it lives only in the ztcred: key written below.
	if hasPassword {
		payload.CredOverride = true
	}
	if hasEndTime {
		payload.ExpiresAt = endTime.Unix()
	}
	// ttl = min(end_time − now, the mode's TTL rules): a longer end_time
	// never extends a token past its configured TTL, and when the tok:
	// key expires the revoke path closes running sessions.
	endTimeTTL := time.Duration(0)
	if hasEndTime {
		endTimeTTL = time.Until(endTime)
	}
	ttl := time.Duration(a.cfg.TokenTTL) * time.Second
	if endTimeTTL > 0 && (ttl <= 0 || endTimeTTL < ttl) {
		ttl = endTimeTTL
	}
	if mode == "session" {
		// Session tokens: TTL from api.session_token_ttl_seconds (0 =
		// INFINITE — lives until revoked), stamped issue IP (every
		// connection must come from it) and issued_at (max-lifetime
		// anchor). MaxUses stays absent — session tokens are not consumed.
		ttl = time.Duration(a.cfg.SessionTokenTTL) * time.Second
		if endTimeTTL > 0 && (ttl <= 0 || endTimeTTL < ttl) {
			ttl = endTimeTTL
		}
		payload.IP = models.NormalizeIP(clientIP(r))
		payload.IssuedAt = time.Now().UTC().Unix()
	} else {
		// Connection budget per token. Clamped — 0 or negative must never
		// produce a token that dies on first use; the store also treats
		// < 1 as 1.
		payload.MaxUses = a.cfg.TokenMaxUses
		if payload.MaxUses < 1 {
			payload.MaxUses = 1
		}
	}
	// An at-mint password needs a FINITE ttl (SetCredOverride refuses
	// ttl<=0 — an eternal credential is forbidden), so refuse here,
	// before any write.
	if hasPassword && ttl <= 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
			"error": "password requires a finite token ttl — supply end_time or set api.session_token_ttl_seconds",
		})
		return
	}
	if err := a.vs.SetToken(r.Context(), token, payload, ttl); err != nil {
		a.log.Error("token store", "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	// The override write shares the token's resolved ttl — it can never
	// outlive the session. It follows SetToken because the sid is needed;
	// a failed write fails the MINT, deleting the token first so no
	// cred_override-stamped token ships without its credential.
	if hasPassword {
		if err := a.vs.SetCredOverride(r.Context(), payload.SessionID, *req.Password, ttl); err != nil {
			a.log.Error("cred override store", "err", err, "session_id", payload.SessionID)
			_ = a.vs.DeleteToken(r.Context(), token)
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
	}
	// -1 signals an infinite session token (revocation is explicit); an
	// end_time turns it finite — report the end_time-derived TTL instead.
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
	// Audit: persist the pending row (maker username, ticket, db target,
	// access). Best-effort like the directory record — a failure is
	// logged, never fatal to the issue. The requesting JWT's IdP login
	// session id (empty for local logins) is stamped so the DB session
	// traces back to the login that requested it.
	loginSID := ""
	if sess := sessionFrom(r); sess != nil {
		loginSID = sess.LoginSessionID
	}
	a.auditUpsertPending(r.Context(), &payload, loginSID)
	a.log.Info("token issued", "username", payload.Username, "db_user", payload.DBUser,
		"db_type", payload.DBType, "ticket", payload.TicketID, "access", payload.Access,
		"session_id", payload.SessionID,
		"data_plane", route.DataPlane) // Task 5: the plane this mint points at (config fallback included)
	writeJSON(w, http.StatusOK, models.TokenResponse{
		Token:     token,
		SessionID: payload.SessionID,
		Host:      route.Host,
		Port:      route.Port,
		ExpiresIn: expiresIn,
		// The absolute expiry (unix seconds) — the end_time instant when
		// one was given; omitted otherwise.
		ExpiresAt: payload.ExpiresAt,
	})
}

// modeForPreset resolves a db_preset's optional token_mode for the
// requested target; "" when no preset matches or the preset declares
// none (the api.token_mode default then applies). Mirrors accessForPreset.
func (a *api) modeForPreset(dbType, dbUser, dbIP, dbPort string) string {
	for _, p := range a.cfg.DBPresets {
		if p.DBType == dbType && p.DBUser == dbUser && p.DBIP == dbIP && p.DBPort == dbPort {
			return p.TokenMode
		}
	}
	return ""
}

// pendingSessionRecord is the CONTROL PLANE's sess:live:<sid> payload: the
// session directory entry for a just-issued token, visible to checkers
// BEFORE the maker ever connects. DB is unknown at issue time (the client
// requests it in the handshake) and is therefore omitted; the data plane
// overwrites the record with the full active shape when the session starts.
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
// checkers at TOKEN ISSUE time: it writes the sess:live:<sid> directory
// entry with status "pending" (sessionPendingTTL) and publishes the
// action=issued lifecycle event to queries:<user> AND queries:sess:<sid>
// (the same fan-out the data plane uses; it deliberately skips the ticket
// channel). Best-effort: the token is already stored — a failure is
// logged, never fatal to the issue.
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
// matches the requested target (maker write-gating): a token issued
// for a read-write preset carries access="write" and is subject to the data
// plane's write gate (queries blocked unless a checker watches the session).
// No matching preset → "" — the data plane treats absent access as read (no
// gate), so tokens for ad-hoc targets stay ungated.
// Task 6 preset migration: preset "read" resolves to "ro" (TRUE read-only —
// every write SQL command rejected at the proxy, no checker involvement);
// the MIGRATION happens at the handleToken call site (this helper returns
// the preset verbatim so modeForPreset-style reuse stays honest).
func (a *api) accessForPreset(dbType, dbUser, dbIP, dbPort string) string {
	for _, p := range a.cfg.DBPresets {
		if p.DBType == dbType && p.DBUser == dbUser && p.DBIP == dbIP && p.DBPort == dbPort {
			return p.Access
		}
	}
	return ""
}

// handleKill queues a data-plane session kill (bearer JWT principal
// required). The kill is dispatched over the Valkey ctl:kill channel — no
// HTTP between planes. Mode selects the kill scope: "connection" (default)
// terminates the whole backend session;
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
	// session_id shape validation — it becomes the ctl:kill channel
	// payload key, so no whitespace/control characters, bounded length.
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
// heartbeats; thread_id stays backend-internal and is not
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
