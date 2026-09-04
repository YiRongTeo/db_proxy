package proxy

// Task 9.13 session tokens — per-proxy registry methods. The three proxies
// share the sweep logic (sweepSnapshot in session_token.go); these methods
// only touch their own registries. See session_token.go for the semantics.

import "time"

// --- MySQL ----------------------------------------------------------------

func (p *MySQLProxy) sessionSnapshot() []sweepableSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]sweepableSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		out = append(out, sweepableSession{id: s.id, token: s.token, issuedAt: s.tok.IssuedAt, lastSeen: s.lastSeen, idleSec: s.tok.IdleSeconds})
	}
	return out
}

// SweepSessionTokens applies the session policy to the MySQL registry and
// returns the session ids to kill (it does not kill them — the shared
// sweeper does, via KillSession).
func (p *MySQLProxy) SweepSessionTokens(policy SessionPolicy, now time.Time) []string {
	return sweepSnapshot(p.vs, p.sessionSnapshot(), policy, now)
}

// RevokeToken closes every registered MySQL session bound to the token
// (keyspace fast path) and reports how many were closed.
func (p *MySQLProxy) RevokeToken(token string) int {
	var ids []string
	p.mu.Lock()
	for _, s := range p.sessions {
		if s.token == token {
			ids = append(ids, s.id)
		}
	}
	p.mu.Unlock()
	n := 0
	for _, id := range ids {
		if p.KillSession(id) {
			n++
		}
	}
	return n
}

// TokenForSession returns the raw session-mode token for a registered
// session ("" when the session is single-use or unknown) — the kill path
// uses it to revoke the key so the session cannot re-establish.
func (p *MySQLProxy) TokenForSession(id string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.sessions[id]
	if s == nil {
		return "", false
	}
	return s.token, true
}

// --- PostgreSQL -----------------------------------------------------------

func (p *PGProxy) sessionSnapshot() []sweepableSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]sweepableSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		out = append(out, sweepableSession{id: s.id, token: s.token, issuedAt: s.tok.IssuedAt, lastSeen: s.lastSeen, idleSec: s.tok.IdleSeconds})
	}
	return out
}

// SweepSessionTokens applies the session policy to the PG registry and
// returns the session ids to kill.
func (p *PGProxy) SweepSessionTokens(policy SessionPolicy, now time.Time) []string {
	return sweepSnapshot(p.vs, p.sessionSnapshot(), policy, now)
}

// RevokeToken closes every registered PG session bound to the token.
func (p *PGProxy) RevokeToken(token string) int {
	var ids []string
	p.mu.Lock()
	for _, s := range p.sessions {
		if s.token == token {
			ids = append(ids, s.id)
		}
	}
	p.mu.Unlock()
	n := 0
	for _, id := range ids {
		if p.KillSession(id) {
			n++
		}
	}
	return n
}

// TokenForSession returns the raw session-mode token for a registered
// session.
func (p *PGProxy) TokenForSession(id string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.sessions[id]
	if s == nil {
		return "", false
	}
	return s.token, true
}

// --- MSSQL ----------------------------------------------------------------

func (p *MSSQLProxy) sessionSnapshot() []sweepableSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]sweepableSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		out = append(out, sweepableSession{id: s.id, token: s.token, issuedAt: s.tok.IssuedAt, lastSeen: s.lastSeen, idleSec: s.tok.IdleSeconds})
	}
	return out
}

// SweepSessionTokens applies the session policy to the MSSQL registry and
// returns the session ids to kill.
func (p *MSSQLProxy) SweepSessionTokens(policy SessionPolicy, now time.Time) []string {
	return sweepSnapshot(p.vs, p.sessionSnapshot(), policy, now)
}

// RevokeToken closes every registered MSSQL session bound to the token.
func (p *MSSQLProxy) RevokeToken(token string) int {
	var ids []string
	p.mu.Lock()
	for _, s := range p.sessions {
		if s.token == token {
			ids = append(ids, s.id)
		}
	}
	p.mu.Unlock()
	n := 0
	for _, id := range ids {
		if p.KillSession(id) {
			n++
		}
	}
	return n
}

// TokenForSession returns the raw session-mode token for a registered
// session.
func (p *MSSQLProxy) TokenForSession(id string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.sessions[id]
	if s == nil {
		return "", false
	}
	return s.token, true
}
