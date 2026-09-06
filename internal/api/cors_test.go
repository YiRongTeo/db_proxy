package api

// Phase 2 Task 3 — CORS for browser-direct REST: the Control Plane's REST
// APIs (bearer-JWT guarded since Task 5) become callable from the OTHER
// app's browser UI cross-origin. The middleware wraps the whole Routes()
// mux and reuses auth.jwt.allowed_origins — the SAME list that already
// governs the checker WebSocket upgrade (Task 9 Phase 1) — so one list =
// one mental model: "origins allowed to talk to this plane".
//
// Contract under test (see cors.go for the matching-rule rationale):
//   - preflight OPTIONS from an allowed origin      -> 204 + allow headers,
//     ACAO echoes the exact Origin, never "*", no Allow-Credentials
//     (Bearer auth is origin-pinned, no cookies in this system).
//   - preflight OPTIONS from a disallowed origin    -> 403 (NOT 204)
//   - preflight OPTIONS with no Origin header       -> pass through; the mux
//     decides (spaHandler 404s unknown /api paths as today).
//   - actual (non-OPTIONS) from an allowed origin   -> handler result +
//     ACAO echo + Vary: Origin
//   - actual from a disallowed origin               -> 403 (before auth)
//   - same-origin (Origin host == request Host)     -> pass through
//     untouched, no CORS headers — browsers send Origin on same-origin
//     POSTs, so the host comparison is what keeps them fast-path.
//   - EMPTY allowlist = same-origin only: every cross-origin Origin 403s.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"zerotrust-proxy/internal/config"
	"zerotrust-proxy/internal/store"
)

// newCORSServer builds the real Control Plane mux (Routes(), CORS wrapper
// included) against the LIVE Valkey with auth.jwt.allowed_origins set to
// origins (same fixture shape as newTestAPIServer in me_test.go, plus the
// allowlist knob). Returns the config so tests can mint bearer tokens.
func newCORSServer(t *testing.T, origins ...string) (*httptest.Server, *http.Client, *config.ControlConfig) {
	t.Helper()
	vs, err := store.NewValkeyStore(context.Background(), store.StoreOptions{Addrs: []string{"127.0.0.1:6379"}})
	if err != nil {
		t.Fatalf("NewValkeyStore: %v", err)
	}
	t.Cleanup(vs.Close)
	j := testJWTBlock()
	j.AllowedOrigins = origins
	cfg := &config.ControlConfig{
		AuthUser:     testJWTUser,
		AuthPassword: testJWTPassword,
		AuthRole:     "maker",
		JWT:          j,
		SessionTTL:   8,
		TokenTTL:     60,
		StaticDir:    t.TempDir(),
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := httptest.NewServer(NewAPI(log, cfg, vs, nil).Routes())
	t.Cleanup(srv.Close)
	return srv, &http.Client{}, cfg
}

// doCORSReq fires method at url with the given Origin and optional bearer
// token, returning the response (caller closes the body).
func doCORSReq(t *testing.T, client *http.Client, method, url, origin, bearer string) *http.Response {
	t.Helper()
	var body io.Reader
	if method == http.MethodPost && strings.Contains(url, "/api/login") {
		body = strings.NewReader(`{"username":"` + testJWTUser + `","password":"` + testJWTPassword + `"}`)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("NewRequest(%s %s): %v", method, url, err)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s (origin %q): %v", method, url, origin, err)
	}
	return resp
}

// assertCORSHeaderAbsence checks the two things this middleware must NEVER
// send: Access-Control-Allow-Origin: * (bearer auth must stay
// origin-pinned) and Access-Control-Allow-Credentials (no cookies — the
// system is Bearer-only).
func assertCORSHeaderAbsence(t *testing.T, h http.Header) {
	t.Helper()
	if v := h.Get("Access-Control-Allow-Origin"); v == "*" {
		t.Error("Access-Control-Allow-Origin is \"*\"; must echo the exact origin or be absent")
	}
	if v := h.Get("Access-Control-Allow-Credentials"); v != "" {
		t.Errorf("Access-Control-Allow-Credentials = %q; must never be set (Bearer auth, no cookies)", v)
	}
}

// TestCORSPreflightAllowedOrigin: preflight from an exact-match allowed
// origin -> 204 with the full allow-header set; ACAO echoes the exact
// Origin value (never "*"), no credentials header.
func TestCORSPreflightAllowedOrigin(t *testing.T) {
	const (
		origin     = "https://other-app.example"
		allowMeth  = "GET, POST, OPTIONS"
		allowHdrs  = "Authorization, Content-Type"
		maxAge     = "600"
		unknownAPI = "/api/me"
	)
	srv, client, _ := newCORSServer(t, origin)

	for _, path := range []string{unknownAPI, "/api/not-a-real-route"} {
		t.Run(path, func(t *testing.T) {
			resp := doCORSReq(t, client, http.MethodOptions, srv.URL+path, origin, "")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("OPTIONS %s: status %d, want 204", path, resp.StatusCode)
			}
			hdrs := resp.Header
			if got := hdrs.Get("Access-Control-Allow-Origin"); got != origin {
				t.Errorf("ACAO = %q, want exact origin %q", got, origin)
			}
			if got := hdrs.Get("Access-Control-Allow-Methods"); got != allowMeth {
				t.Errorf("ACAM = %q, want %q", got, allowMeth)
			}
			if got := hdrs.Get("Access-Control-Allow-Headers"); got != allowHdrs {
				t.Errorf("ACAH = %q, want %q", got, allowHdrs)
			}
			if got := hdrs.Get("Access-Control-Max-Age"); got != maxAge {
				t.Errorf("max-age = %q, want %q", got, maxAge)
			}
			assertCORSHeaderAbsence(t, hdrs)
		})
	}
}

// TestCORSPreflightDisallowedOrigin403: preflight from an origin NOT on the
// allowlist -> 403, never a 204 that would let the browser proceed.
func TestCORSPreflightDisallowedOrigin403(t *testing.T) {
	srv, client, _ := newCORSServer(t, "https://other-app.example")

	resp := doCORSReq(t, client, http.MethodOptions, srv.URL+"/api/me", "https://evil.example", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("OPTIONS from disallowed origin: status %d, want 403", resp.StatusCode)
	}
	if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("ACAO = %q on a 403; disallowed origins must not be echoed", v)
	}
	assertCORSHeaderAbsence(t, resp.Header)
}

// TestCORSPreflightNoOriginPassThrough: an OPTIONS with NO Origin header is
// not a browser preflight — the middleware must pass it through untouched
// and let the mux decide (the "/" catch-all routes it to spaHandler, whose
// /api guard 404s as today; it must NOT get a 204 or CORS headers).
func TestCORSPreflightNoOriginPassThrough(t *testing.T) {
	srv, client, _ := newCORSServer(t, "https://other-app.example")

	resp := doCORSReq(t, client, http.MethodOptions, srv.URL+"/api/health", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("OPTIONS /api/health without Origin: status %d, want 404 (spaHandler /api guard — mux's own answer, not CORS)", resp.StatusCode)
	}
	hdrs := resp.Header
	if v := hdrs.Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("ACAO = %q on a no-Origin OPTIONS; pass-through must stay untouched", v)
	}
	if v := hdrs.Get("Access-Control-Allow-Methods"); v != "" {
		t.Errorf("ACAM = %q on a no-Origin OPTIONS; pass-through must stay untouched", v)
	}
	assertCORSHeaderAbsence(t, hdrs)
}

// TestCORSActualGETAllowedOrigin: a real cross-origin GET with a bearer JWT
// from an allowed origin -> 200, ACAO echoes the exact origin, Vary:
// Origin, and no credentials header.
func TestCORSActualGETAllowedOrigin(t *testing.T) {
	const origin = "https://other-app.example"
	srv, client, cfg := newCORSServer(t, origin)
	tok := mintJWT(t, cfg, testJWTUser, "maker")

	resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/me", origin, tok)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/me from allowed origin: status %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
		t.Errorf("ACAO = %q, want exact origin %q", got, origin)
	}
	if vary := resp.Header.Get("Vary"); !strings.Contains(vary, "Origin") {
		t.Errorf("Vary = %q, want it to contain Origin (cache must key on Origin)", vary)
	}
	assertCORSHeaderAbsence(t, resp.Header)
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode /api/me: %v", err)
	}
	if got["username"] != testJWTUser {
		t.Errorf("username = %q, want %q", got["username"], testJWTUser)
	}
}

// TestCORSActualDisallowedOrigin403: a real cross-origin request from a
// disallowed origin -> 403 BEFORE auth runs (no bearer attached here on
// purpose: a 401 would mean the request reached requireJWT, a 403 means
// CORS shut it down first) and before the handler responds.
func TestCORSActualDisallowedOrigin403(t *testing.T) {
	srv, client, _ := newCORSServer(t, "https://other-app.example")

	for _, tc := range []struct{ name, method, path string }{
		{"GET authed route, no bearer", http.MethodGet, "/api/me"},
		{"GET open route", http.MethodGet, "/api/health"},
		{"POST login", http.MethodPost, "/api/login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := doCORSReq(t, client, tc.method, srv.URL+tc.path, "https://evil.example", "")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s from disallowed origin: status %d, want 403", tc.path, resp.StatusCode)
			}
			if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
				t.Errorf("ACAO = %q on a 403; disallowed origins must not be echoed", v)
			}
			assertCORSHeaderAbsence(t, resp.Header)
		})
	}
}

// TestCORSSameOriginPOSTNoACAO: a same-origin POST (Origin host == request
// Host — what browsers send for same-origin POSTs) must pass through with
// NO CORS headers: /api/login still works, response carries no ACAO.
func TestCORSSameOriginPOSTNoACAO(t *testing.T) {
	srv, client, _ := newCORSServer(t) // empty allowlist: same-origin must STILL pass

	resp := doCORSReq(t, client, http.MethodPost, srv.URL+"/api/login", srv.URL, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("same-origin POST /api/login: status %d, want 200", resp.StatusCode)
	}
	hdrs := resp.Header
	if v := hdrs.Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("ACAO = %q on a same-origin POST; same-origin traffic needs no CORS headers", v)
	}
	if v := hdrs.Get("Access-Control-Allow-Methods"); v != "" {
		t.Errorf("ACAM = %q on a same-origin POST; must stay untouched", v)
	}
	assertCORSHeaderAbsence(t, hdrs)
}

// TestCORSWildcardPatternSchemePinned: an entry "https://*.example.com" is
// a scheme-pinned host glob (WS-identical semantics): it matches any
// https subdomain of example.com but NEVER http, and never other hosts.
func TestCORSWildcardPatternSchemePinned(t *testing.T) {
	srv, client, cfg := newCORSServer(t, "https://*.example.com")
	tok := mintJWT(t, cfg, testJWTUser, "maker")

	t.Run("https subdomain allowed on authed route", func(t *testing.T) {
		resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/me", "https://app.example.com", tok)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/me from https://app.example.com: status %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
			t.Errorf("ACAO = %q, want exact origin", got)
		}
	})
	t.Run("deep subdomain matches the glob", func(t *testing.T) {
		resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/health", "https://sub.deep.example.com", "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/health from https://sub.deep.example.com: status %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://sub.deep.example.com" {
			t.Errorf("ACAO = %q, want exact origin", got)
		}
	})
	for _, evil := range []string{"http://app.example.com", "https://evil.com", "https://example.com"} {
		t.Run("rejected "+evil, func(t *testing.T) {
			resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/health", evil, "")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("GET /api/health from %s: status %d, want 403", evil, resp.StatusCode)
			}
		})
	}
}

// TestCORSHostEntryAnyScheme: a scheme-less entry ("other-app.example") is
// a host glob with an OPTIONAL scheme prefix — it allows that host over
// ANY scheme, exactly like the WS OriginPatterns semantics (one list, one
// matching rule). The ACAO echo is always the exact Origin the browser
// sent, so the response stays valid CORS.
func TestCORSHostEntryAnyScheme(t *testing.T) {
	srv, client, _ := newCORSServer(t, "other-app.example")

	for _, origin := range []string{"https://other-app.example", "http://other-app.example"} {
		t.Run(origin, func(t *testing.T) {
			resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/health", origin, "")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET /api/health from %s: status %d, want 200", origin, resp.StatusCode)
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
				t.Errorf("ACAO = %q, want exact origin %q", got, origin)
			}
		})
	}
}

// TestCORSOriginPortPartOfHost: the PORT rides the Origin HOST in the
// matching rule (identical to the WS vendor's), so an allowlist entry
// without the port must NOT match the same host on a non-default port —
// "https://app.example.com" is a different origin than
// "https://app.example.com:8443" and 403s until the entry spells the port
// out. (Config-load glob validation guards malformed entries — see
// internal/config TestJWTAllowedOriginsLoad — so only well-formed globs
// reach this middleware.)
func TestCORSOriginPortPartOfHost(t *testing.T) {
	t.Run("port-less entry rejects the same host on :8443", func(t *testing.T) {
		srv, client, _ := newCORSServer(t, "https://app.example.com")
		resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/health", "https://app.example.com:8443", "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GET /api/health from https://app.example.com:8443 (entry https://app.example.com): status %d, want 403", resp.StatusCode)
		}
		if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("ACAO = %q on a 403; disallowed origins must not be echoed", v)
		}
		assertCORSHeaderAbsence(t, resp.Header)
	})
	t.Run("port-spelled entry allows the :8443 origin (ACAO echoes it)", func(t *testing.T) {
		srv, client, _ := newCORSServer(t, "https://app.example.com:8443")
		resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/health", "https://app.example.com:8443", "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/health from https://app.example.com:8443 (entry spells the port): status %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com:8443" {
			t.Errorf("ACAO = %q, want exact origin %q", got, "https://app.example.com:8443")
		}
	})
	t.Run("port-spelled entry still rejects the port-less same host", func(t *testing.T) {
		srv, client, _ := newCORSServer(t, "https://app.example.com:8443")
		resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/health", "https://app.example.com", "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GET /api/health from https://app.example.com (entry https://app.example.com:8443): status %d, want 403", resp.StatusCode)
		}
	})
}

// TestCORSEmptyAllowlistSameOriginOnly: with auth.jwt.allowed_origins EMPTY
// (the committed default) NO cross-origin Origin is allowed — current
// behavior preserved. No-Origin and same-origin requests keep working.
func TestCORSEmptyAllowlistSameOriginOnly(t *testing.T) {
	srv, client, _ := newCORSServer(t) // no origins

	t.Run("cross-origin rejected", func(t *testing.T) {
		resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/health", "https://other-app.example", "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("GET /api/health cross-origin with empty allowlist: status %d, want 403", resp.StatusCode)
		}
	})
	t.Run("no-Origin request untouched", func(t *testing.T) {
		resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/health", "", "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/health without Origin: status %d, want 200", resp.StatusCode)
		}
		if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("ACAO = %q on a no-Origin request; must stay untouched", v)
		}
	})
	t.Run("same-origin GET with Origin header untouched", func(t *testing.T) {
		resp := doCORSReq(t, client, http.MethodGet, srv.URL+"/api/health", srv.URL, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /api/health same-origin: status %d, want 200", resp.StatusCode)
		}
		if v := resp.Header.Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("ACAO = %q on a same-origin GET; must stay untouched", v)
		}
	})
}
