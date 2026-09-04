package proxy

// Task 9.13 — session tokens (option A): IP-locked, non-consuming tokens
// with LIVE revocation. The data plane enforces:
//
//   - IP lock at login: a session-mode token only opens connections from
//     the normalized address stamped at issue time (payload.IP).
//   - Continuous liveness: the session sweeper re-checks tok:<token>
//     every policy.Poll; the valkey keyspace-notification consumer
//     (cmd/data) revokes instantly on del/expired events when the server
//     publishes them. Deleting the key by ANY means — control-plane kill,
//     valkey-cli, expiry — closes the running session(s).
//   - Idle timeout + max lifetime (both configurable, 0 = off): the
//     safety valves for infinite-TTL tokens (a forgotten GUI window must
//     not pin a backend connection forever).
//
// Single-use tokens (the default) are untouched: they are consumed
// atomically at login and never enter the sweeper.

import (
	"context"
	"log/slog"
	"time"

	"zerotrust-proxy/internal/models"
)

// SessionPolicy is the data-plane enforcement set for session-mode tokens.
// All durations are configurable; 0 disables the respective check. Poll
// (revoke liveness interval) defaults to 1s when zero.
type SessionPolicy struct {
	Idle        time.Duration
	MaxLifetime time.Duration
	Poll        time.Duration
}

// withDefaults normalizes a policy: Poll < 500ms is clamped to 1s (the
// liveness poll must not hammer valkey; a 500ms-1s revocation latency is
// the worst case, and the keyspace fast path is instant when available).
func (p SessionPolicy) withDefaults() SessionPolicy {
	if p.Poll < 500*time.Millisecond {
		p.Poll = time.Second
	}
	return p
}

// checkSessionTokenIP enforces the session-token IP lock at login: a
// session-mode token only accepts connections whose normalized client
// address equals the address stamped at issue time. Returns "" when the
// connection is allowed, otherwise the rejection reason (the caller writes
// it into the protocol-appropriate login-error packet). Single-use tokens
// (mode "") skip the check entirely — their consumption is the gate.
func checkSessionTokenIP(tok *models.TokenPayload, clientAddr string) string {
	if tok == nil || tok.Mode != "session" {
		return ""
	}
	got := models.NormalizeIP(clientAddr)
	if got == "" || got != tok.IP {
		return "token locked to a different address"
	}
	return ""
}

// sweepableSession is the per-session snapshot the sweeper inspects. The
// proxies take it under their registry lock (one-liners per proxy).
type sweepableSession struct {
	id       string
	token    string // raw token — only set for session-mode sessions (their key is the liveness handle)
	issuedAt int64  // payload.IssuedAt (unix seconds); 0 = unknown → no lifetime check
	lastSeen time.Time
	idleSec  int // payload.IdleSeconds — per-token idle override; 0 = follow policy.Idle
}

// sweepSnapshot applies the policy to a snapshot and returns the ids to
// kill. Order of checks: max-lifetime, then idle, then token-liveness.
//
//   - Idle applies to EVERY session (every token mode — Task 9.13 round-2:
//     single-use sessions are idle-swept too, configured via the data
//     plane's session.idle_seconds). The effective idle is the token's own
//     idle_seconds override when set (>0), else the policy default.
//   - Token-liveness (revocation) applies ONLY to session-mode sessions
//     (token != ""): single-use tokens are consumed at login, so their key
//     is legitimately gone — an EXISTS check would kill them instantly.
//
// now is injected so tests drive the clock.
func sweepSnapshot(vs Store, snapshot []sweepableSession, policy SessionPolicy, now time.Time) []string {
	var victims []string
	for _, s := range snapshot {
		if policy.MaxLifetime > 0 && s.issuedAt > 0 && now.Unix()-s.issuedAt >= int64(policy.MaxLifetime/time.Second) {
			victims = append(victims, s.id)
			continue
		}
		idle := policy.Idle
		if s.idleSec > 0 {
			idle = time.Duration(s.idleSec) * time.Second
		}
		if idle > 0 && !s.lastSeen.IsZero() && now.Sub(s.lastSeen) >= idle {
			victims = append(victims, s.id)
			continue
		}
		if s.token == "" {
			continue // single-use: consumed at login, no key to watch
		}
		// Live revocation: the key must still exist. A bounded ctx — a
		// hung valkey must not stall the sweep (review 2026-08-17).
		ctx, cancel := storeCallCtx()
		alive, err := vs.TokenAlive(ctx, s.token)
		cancel()
		if err != nil || !alive {
			victims = append(victims, s.id)
		}
	}
	return victims
}

// sessionSweeper is the per-proxy surface the shared sweeper loop needs.
type sessionSweeper interface {
	// SweepSessionTokens snapshots the registry, applies the policy and
	// returns the session ids to kill (it does NOT kill them itself).
	SweepSessionTokens(policy SessionPolicy, now time.Time) []string
	KillSession(id string) bool
	// RevokeToken closes every registered session bound to the token
	// (keyspace fast path) and returns how many were closed.
	RevokeToken(token string) int
}

// RunSessionSweeper is the data plane's token-liveness/idle/lifetime loop
// (Task 9.13): every policy.Poll it sweeps all three proxies, then kills
// the victims. Deleting tok:<token> by any external means therefore closes
// the running session(s) within one poll interval — the keyspace
// notification consumer (cmd/data) makes it instant on top of this. Runs
// until ctx is cancelled.
func RunSessionSweeper(ctx context.Context, log *slog.Logger, policy SessionPolicy, proxies ...sessionSweeper) {
	policy = policy.withDefaults()
	t := time.NewTicker(policy.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, p := range proxies {
				for _, id := range p.SweepSessionTokens(policy, now) {
					if p.KillSession(id) {
						log.Info("session token revoked", "session_id", id)
					}
				}
			}
		}
	}
}
