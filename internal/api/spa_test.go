package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestSPAHandler builds a spaHandler backed by a temp static dir holding a
// real index.html plus one asset file, so the fallback guard can be exercised
// without the full mux.
func newTestSPAHandler(t *testing.T) spaHandler {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><title>Test SPA</title>"), 0o644); err != nil {
		t.Fatalf("write index.html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte("console.log('asset')"), 0o644); err != nil {
		t.Fatalf("write app.js: %v", err)
	}
	return spaHandler{staticDir: dir}
}

// TestSPAHandlerAPIPaths404: unregistered /api/ and /ws/ paths must 404 with a
// non-HTML body — never the index.html fallback (regression for the guard).
func TestSPAHandlerAPIPaths404(t *testing.T) {
	h := newTestSPAHandler(t)
	for _, p := range []string{"/api/unknown", "/api/health/", "/ws/foo"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: got status %d, want 404 (must not fall back to index.html)", p, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "<title>Test SPA</title>") {
			t.Errorf("%s: response contains index.html content; want plain 404", p)
		}
	}
}

// TestSPAHandlerIndexFallback: a missing SPA route gets 200 index.html.
func TestSPAHandlerIndexFallback(t *testing.T) {
	h := newTestSPAHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/maker", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/maker: got status %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "<title>Test SPA</title>") {
		t.Errorf("/maker: body %q does not contain index.html content", body)
	}
}

// TestSPAHandlerServesAssets: an existing static file is served as-is (200,
// non-HTML), not replaced by the index fallback.
func TestSPAHandlerServesAssets(t *testing.T) {
	h := newTestSPAHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/app.js: got status %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "console.log('asset')" {
		t.Errorf("/app.js: got body %q, want asset content", body)
	}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
		t.Errorf("/app.js: content-type %q is HTML; want the asset type", ct)
	}
}
