package proxy

// node-integration Task 4 — the credential-override chain. When a token
// carries CredOverride (minted with a password), the backend credential is
// resolved from ztcred:<sid> FIRST; a missing/expired key (or a store error)
// falls through to the normal resolver chain with a WARN that carries the
// REASON only — never a value (G2). Tokens without the flag resolve exactly
// as before (G3): the store is never consulted, byte-for-byte today's path.
//
// Wiring: the proxy constructors wrap the configured CredResolver into an
// overrideChain ONCE (WrapCredResolver). The connect paths call
// OverrideCreds(creds, tok) — a CredResolver view bound to the token — and
// hand THAT to the existing connect*Backend functions, so no connect
// signature changes and every protocol (MySQL, PostgreSQL, MSSQL, Oracle —
// including the kill-query / pg_cancel second connects) inherits
// override-first resolution uniformly.

import (
	"context"
	"log/slog"

	"zerotrust-proxy/internal/models"
	"zerotrust-proxy/internal/store"
)

// overrideStore is the narrow store surface the chain needs (the concrete
// *store.ValkeyStore satisfies it; the interface keeps this file taking
// primitives, mirroring Store in store_iface.go).
type overrideStore interface {
	// GetCredOverride returns the override password for sid; ""/nil on a
	// clean miss (missing or expired key).
	GetCredOverride(ctx context.Context, sid string) (string, error)
}

// overrideChain wraps the configured backend-password resolver with the
// ztcred:<sid> override lookup. Built once per proxy (WrapCredResolver);
// stateless — per-call tokens enter through OverrideCreds.
type overrideChain struct {
	fallback CredResolver  // the config list / credential API chain
	vs       overrideStore // ztcred:<sid> reads
	log      *slog.Logger  // WARN channel on fallback (reason only, never a value)
}

// compile-time: the concrete store satisfies the narrow override surface.
var _ overrideStore = (*store.ValkeyStore)(nil)

// WrapCredResolver builds the chain around r. A nil vs or nil r (tests
// constructing proxies without a store/resolver) degrades to the bare
// resolver — every behavior below the wrap stays byte-identical. vs is the
// Store the proxy already holds: only its GetCredOverride surface is used
// (satisfying overrideStore is compile-time-checked here).
func WrapCredResolver(r CredResolver, vs overrideStore, log *slog.Logger) CredResolver {
	if vs == nil || r == nil {
		return r
	}
	return &overrideChain{fallback: r, vs: vs, log: log}
}

// Password is the un-bound resolution path (the chain itself satisfies
// CredResolver for symmetry; today's call sites all go through
// OverrideCreds with the token in scope).
func (c *overrideChain) Password(ctx context.Context, key string) (string, error) {
	return c.fallback.Password(ctx, key)
}

// tokenBoundResolver resolves override-first for ONE token — the per-call
// type OverrideCreds hands to the connect paths.
type tokenBoundResolver struct {
	chain *overrideChain
	tok   *models.TokenPayload
}

// Password resolves the backend password for key: override first when the
// token carries the flag, the configured chain otherwise.
func (t *tokenBoundResolver) Password(ctx context.Context, key string) (string, error) {
	c := t.chain
	tok := t.tok
	if tok == nil || !tok.CredOverride || tok.SessionID == "" {
		// G3: no override in play — today's path, no store call.
		return c.fallback.Password(ctx, key)
	}
	ov, oerr := c.vs.GetCredOverride(ctx, tok.SessionID)
	if oerr != nil {
		// The error text is FIXED upstream (never carries a value) — the
		// reason reaches the log, the value never does (G2).
		c.warn("cred override read failed; falling back to the configured resolver", tok.SessionID)
		return c.fallback.Password(ctx, key)
	}
	if ov == "" {
		// Missing/expired key: the override died with its TTL (the same TTL
		// the token has, so this is a narrow race window, not a policy
		// change). WARN with the reason only, then the normal chain.
		c.warn("cred override miss; falling back to the configured resolver", tok.SessionID)
		return c.fallback.Password(ctx, key)
	}
	return ov, nil
}

// warn logs at WARN with the session id — a REASON ONLY. The passwords
// resolved above never reach it (G2: no password in any log line).
func (c *overrideChain) warn(msg, sid string) {
	if c.log != nil {
		c.log.Warn(msg, "session_id", sid)
	}
}

// OverrideCreds returns the token-bound CredResolver for tok. Non-chain
// resolvers (tests passing bare ConfigCredResolvers) pass through
// unchanged, so their exact behavior is preserved everywhere.
func OverrideCreds(r CredResolver, tok *models.TokenPayload) CredResolver {
	if c, ok := r.(*overrideChain); ok {
		return c.credsFor(tok)
	}
	return r
}

// credsFor returns the token-bound view.
func (c *overrideChain) credsFor(tok *models.TokenPayload) CredResolver {
	return &tokenBoundResolver{chain: c, tok: tok}
}
