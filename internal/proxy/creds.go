package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// CredResolver resolves the backend DB password for a credential key.
// Task 8.7: the Data Plane owns DB credentials (zero-trust); the password
// returned exists in memory ONLY for the in-flight connect call — it is
// never stored, cached, written to disk, or logged.
type CredResolver interface {
	// Password returns the backend DB password for key, or an error. Error
	// messages carry the key name and/or HTTP status codes — NEVER a
	// password and NEVER a response body.
	Password(ctx context.Context, key string) (string, error)
}

// ConfigCredResolver resolves passwords from the committed config-file
// credentials list (source "config" — the default; pre-Task-8.7 behavior).
// Key → password map lookup; a missing key is an error ("no credentials for
// <key>"), exactly like the pre-resolver connect path.
type ConfigCredResolver struct {
	Creds map[string]string
}

// Password looks up key in the committed credentials map.
func (r *ConfigCredResolver) Password(_ context.Context, key string) (string, error) {
	pw, ok := r.Creds[key]
	if !ok {
		return "", fmt.Errorf("no credentials for %s", key)
	}
	return pw, nil
}

// APICredResolver resolves passwords from the credential API (source "api",
// Task 8.7): a GET to {url}?db_type=&db_user=&db_ip=&db_port= carrying the
// X-Api-Key header; a 200 {"password": "..."} response yields the password.
//
// Password hygiene (HARD requirement): the password is held in memory only
// for the in-flight connect call — no caching, no disk writes. Non-200
// responses surface as errors carrying the STATUS CODE ONLY (the response
// body is drained for connection reuse but never read into any error or log
// line); network errors are wrapped as-is. This resolver never logs.
type APICredResolver struct {
	url    string
	apiKey string
	hc     *http.Client
}

// CredAPITLS is the outbound TLS trust for the credential vault, mirrored
// from config.CredentialsAPITLSConfig so this package keeps taking primitives
// (no config import, no layering inversion). The zero value means "system
// trust store", which already covers a publicly-trusted HTTPS vault; only an
// internal CA / self-signed endpoint needs CAFile.
type CredAPITLS struct {
	CAFile             string
	MinVersion         string
	InsecureSkipVerify bool
}

// newCredHTTPClient builds the vault client. With no TLS options it returns
// the historical client (nil Transport = http.DefaultTransport = system trust
// store), so existing deployments are byte-for-byte unchanged. With options it
// clones the default transport and swaps in a TLS config: the CA file is
// APPENDED to the system pool (public and internal endpoints both work),
// min_version pins the floor, and InsecureSkipVerify is honoured as the
// dev-only escape hatch its config comment promises.
func newCredHTTPClient(timeout time.Duration, o *CredAPITLS) (*http.Client, error) {
	if o == nil {
		return &http.Client{Timeout: timeout}, nil
	}
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Operator-set, warned about at boot by cmd/data; never defaulted on.
		InsecureSkipVerify: o.InsecureSkipVerify, // #nosec G402
	}
	if o.MinVersion == "1.3" {
		tc.MinVersion = tls.VersionTLS13
	}
	if o.CAFile != "" {
		raw, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("credential api: read ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("credential api: ca_file %q: no certificates found", o.CAFile)
		}
		tc.RootCAs = pool
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("credential api: default transport is not *http.Transport")
	}
	tr := base.Clone()
	tr.TLSClientConfig = tc
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// NewAPICredResolver validates the vault URL (fail fast at construction:
// an unreachable/malformed vault must not surface mid-session) and builds
// the client with the configured timeout. timeout <= 0 falls back to 5s.
func NewAPICredResolver(rawURL, apiKey string, timeout time.Duration) (*APICredResolver, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("credential api: empty url")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("credential api: parse url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("credential api: url %q must be absolute (scheme + host)", rawURL)
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return newResolverWithTLS(rawURL, apiKey, timeout, nil)
}

// NewAPICredResolverTLS is NewAPICredResolver plus outbound TLS trust for an
// internal CA / self-signed vault (tls may be nil for the system trust store).
func NewAPICredResolverTLS(rawURL, apiKey string, timeout time.Duration, tlsOpts *CredAPITLS) (*APICredResolver, error) {
	return newResolverWithTLS(rawURL, apiKey, timeout, tlsOpts)
}

func newResolverWithTLS(rawURL, apiKey string, timeout time.Duration, tlsOpts *CredAPITLS) (*APICredResolver, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("credential api: empty url")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("credential api: parse url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("credential api: url %q must be absolute (scheme + host)", rawURL)
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	hc, err := newCredHTTPClient(timeout, tlsOpts)
	if err != nil {
		return nil, err
	}
	return &APICredResolver{
		url:    rawURL,
		apiKey: apiKey,
		hc:     hc,
	}, nil
}

// parseCredKey splits a credential key of the form "dbtype:user@ip:port"
// (the format backendKey produces, Task 8.7) into its parts. An unparseable
// key is an error — a malformed key must never reach the vault with garbage
// query params.
func parseCredKey(key string) (dbType, dbUser, dbIP, dbPort string, err error) {
	bad := func() (string, string, string, string, error) {
		return "", "", "", "", fmt.Errorf("invalid credential key %q: want dbtype:user@ip:port", key)
	}
	dbType, rest, ok := strings.Cut(key, ":")
	if !ok || dbType == "" {
		return bad()
	}
	dbUser, addr, ok := strings.Cut(rest, "@")
	if !ok || dbUser == "" {
		return bad()
	}
	dbIP, dbPort, ok = strings.Cut(addr, ":")
	if !ok || dbIP == "" || dbPort == "" {
		return bad()
	}
	return dbType, dbUser, dbIP, dbPort, nil
}

// Password fetches the password for key from the vault: GET
// {url}?db_type=&db_user=&db_ip=&db_port= with X-Api-Key. 200 → the
// password field; any other status → error naming the status code ONLY.
func (r *APICredResolver) Password(ctx context.Context, key string) (string, error) {
	dbType, dbUser, dbIP, dbPort, err := parseCredKey(key)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(r.url)
	if err != nil {
		return "", fmt.Errorf("credential api: parse url: %w", err)
	}
	q := u.Query()
	q.Set("db_type", dbType)
	q.Set("db_user", dbUser)
	q.Set("db_ip", dbIP)
	q.Set("db_port", dbPort)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", fmt.Errorf("credential api: build request: %w", err)
	}
	req.Header.Set("X-Api-Key", r.apiKey)

	resp, err := r.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("credential api: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Status code ONLY — the body is drained (connection reuse) but
		// never surfaces in the error or any log line.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return "", fmt.Errorf("credential api: status %d for %s", resp.StatusCode, key)
	}
	var out struct {
		Password string `json:"password"`
	}
	// Bounded read (1 MiB): a misbehaving vault must not pin the session.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("credential api: decode response: %w", err)
	}
	if out.Password == "" {
		return "", fmt.Errorf("credential api: empty password for %s", key)
	}
	return out.Password, nil
}
