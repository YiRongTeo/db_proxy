package proxy

// SessionKiller is the data-plane kill interface: force-close a live session
// by id, reporting whether a session was found. Both MySQLProxy and PGProxy
// implement it through their per-session registries (the closer closes the
// client AND backend conns, so the relay pipes exit and handleConn tears the
// session down). Compile-time assertions below pin both implementations.
type SessionKiller interface {
	KillSession(id string) bool
}

var (
	_ SessionKiller = (*MySQLProxy)(nil)
	_ SessionKiller = (*PGProxy)(nil)
	_ SessionKiller = (*Killer)(nil)
)

// Killer fans a ctl:kill request out to both proxies' registries. Session ids
// are generated per proxy ("sid-" + random hex), so a live session lives on
// exactly one plane — but the ctl:kill subscriber (Task 6.4) does not know
// which protocol a session uses, so it asks both. Both are always tried so an
// (astronomically unlikely) id collision on the other plane cannot leave a
// session alive; KillSession is a fast mutex-guarded map lookup on a miss.
type Killer struct {
	mysql SessionKiller
	pg    SessionKiller
}

func NewKiller(mysql, pg SessionKiller) *Killer {
	return &Killer{mysql: mysql, pg: pg}
}

// KillSession tries the MySQL registry first, then the PostgreSQL registry,
// and reports whether either plane had the session.
func (k *Killer) KillSession(id string) bool {
	killed := false
	if k.mysql != nil && k.mysql.KillSession(id) {
		killed = true
	}
	if k.pg != nil && k.pg.KillSession(id) {
		killed = true
	}
	return killed
}
