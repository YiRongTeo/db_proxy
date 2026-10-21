package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"time"

	"zerotrust-proxy/internal/models"
)

// --- Task 6 (node-integration): the rw connection HOLD ----------------------
//
// An access:"rw" session is HELD between protocol auth and the backend
// connect: the client's login COMPLETES (the proxy answers its own success
// packet — the client believes it is connected), but the backend connection
// is NOT opened and the credential is NOT drawn until a checker actively
// watches the session (WatchActive(sid) true). Admission is ONE-WAY: a
// watcher detaching after admission never kills the session — enforcement
// after admission is the backend account's business, and a running rw
// session behaves exactly like today's ungated session.
//
// The held state is VISIBLE: the mint-time pending sess:live:<sid> record
// (status "pending", 60s TTL) is re-armed by the hold heartbeat while the
// client stays connected, so the checker directory shows the session as
// pending until admission. On admission the normal connect path runs and
// overwrites the record with the active shape.
//
// Client disconnect while held → clean exit: the hold goroutine ends, the
// (never-created) backend is untouched, and the pending record is removed
// so nothing leaks in the directory.

// rwHoldPollInterval is the WatchActive poll cadence while a rw session is
// held (the brief's 500ms bounded ticker).
const rwHoldPollInterval = 500 * time.Millisecond

// holdConnector is the per-protocol backend-connect seam the hold calls on
// admission. Signature mirrors the connect paths: the credential draw is
// INSIDE the connector (res.Password / OverrideCreds happen there), so a
// held session draws nothing until this runs.
type holdConnector func(ctx context.Context, tok *models.TokenPayload, res CredResolver, db string) (net.Conn, error)

// watchForAdmission polls WatchActive(sid) on the bounded ticker until a
// watcher appears (admitted → send on admitted), stop closes, or ctx dies.
// Store errors are logged and retried on the next tick — a hung valkey must
// not admit or fail the session on its own (the hold persists until the
// client gives up or a watcher arrives).
func (pub *sessionPublisher) watchForAdmission(ctx context.Context, sid string, stop <-chan struct{}, admitted chan<- struct{}) {
	ticker := time.NewTicker(rwHoldPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			pctx, cancel := storeCallCtx()
			watched, err := pub.vs.WatchActive(pctx, sid)
			cancel()
			if err != nil {
				pub.log.Error("rw hold: watch check failed — still held", "session_id", sid, "err", err)
				continue
			}
			if watched {
				pub.log.Info("rw hold: checker watching — admitting", "session_id", sid)
				select {
				case admitted <- struct{}{}:
				default:
				}
				return
			}
		}
	}
}

// holdHeartbeat re-arms the mint-time pending sess:live:<sid> record so a
// long-held rw session never silently drops out of the checker directory
// (the record carries status "pending" — exactly what the directory should
// show pre-admission). Best-effort: a store hiccup logs and the next tick
// retries.
func (pub *sessionPublisher) holdHeartbeat(tok *models.TokenPayload) {
	now := time.Now().UTC()
	rec, err := json.Marshal(pendingSessionRecordShape{
		SessionID: tok.SessionID, Username: tok.Username, DBUser: tok.DBUser,
		DBType: tok.DBType, Status: "pending", StartedAt: now, LastSeen: now,
	})
	if err != nil {
		pub.log.Error("rw hold: pending record marshal", "err", err)
		return
	}
	ctx, cancel := storeCallCtx()
	defer cancel()
	if err := pub.vs.SetSessionLive(ctx, tok.SessionID, rec, sessionLiveTTL); err != nil {
		pub.log.Error("rw hold: pending record refresh", "session_id", tok.SessionID, "err", err)
	}
}

// pendingSessionRecordShape mirrors the control plane's pending record
// (handlers.go pendingSessionRecord) so the data plane's hold refresh is
// wire-identical: the directory shows pending until the backend connect
// overwrites the record with the active shape.
type pendingSessionRecordShape struct {
	SessionID string    `json:"session_id"`
	Username  string    `json:"username"`
	DBUser    string    `json:"db_user"`
	DBType    string    `json:"db_type"`
	DB        string    `json:"db,omitempty"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// finishHeldSession removes the mint-time pending record when a held
// session ends without admission (client disconnect / teardown): no leaked
// sess:live entry, no dangling directory row. Best-effort.
func (pub *sessionPublisher) finishHeldSession(sid string) {
	ctx, cancel := storeCallCtx()
	defer cancel()
	if err := pub.vs.DelSessionLive(ctx, sid); err != nil {
		pub.log.Error("rw hold: pending record cleanup", "session_id", sid, "err", err)
	}
}

// holdRWSession is the shared hold loop, called by each plane's connect
// path AFTER client auth + token validation and BEFORE the credential draw
// / backend dial. It:
//
//  1. answers the client's login success (writeLoginOK — the plane's own
//     success packet, so protocol auth completes per the contract),
//  2. arms a client-liveness watcher: the FIRST read attempt on the client
//     conn after the success packet returns (error/EOF = the client went
//     away — it would never send anything the hold consumes), and
//  3. heartbeats the pending directory record + polls WatchActive on the
//     bounded ticker until a watcher watches.
//
// On admission the connect runs (the credential draw happens inside) and
// its result returns to the caller (which proceeds into the normal relay
// path exactly as it would have before the hold existed). A client
// disconnect while held exits cleanly with NO backend and the pending
// record removed.
//
// clientDied is the plane's own disconnect signal when it has one (the
// handshake read loop's exit); when nil the hold probes liveness itself by
// reading one byte with a short deadline in a loop — a live client simply
// times out each probe (it sends nothing until admitted), a dead one
// errors immediately.
func (pub *sessionPublisher) holdRWSession(ctx context.Context, client net.Conn, clientDied <-chan struct{}, writeLoginOK func() error, tok *models.TokenPayload, res CredResolver, db string, connect holdConnector) (net.Conn, error) {
	sid := tok.SessionID
	pub.log.Info("rw hold: session held — waiting for a checker",
		"session_id", sid, "username", tok.Username, "db_user", tok.DBUser)
	// Login success FIRST: auth completes, the client is none the wiser.
	if err := writeLoginOK(); err != nil {
		pub.finishHeldSession(sid)
		return nil, err
	}
	pub.holdHeartbeat(tok)
	stop := make(chan struct{})
	admitted := make(chan struct{}, 1)
	go pub.watchForAdmission(ctx, sid, stop, admitted)
	defer close(stop)
	ticker := time.NewTicker(rwHoldPollInterval)
	defer ticker.Stop()
	// Liveness: the PLANES supply clientDied (a Peek-based disconnect probe
	// — never consuming relay bytes). The hold does not touch the client
	// conn beyond the login write; when a plane passes nil the hold treats
	// liveness as unknown (the hold ends on ctx, admission, or the login
	// write failing).
	for {
		if clientDied != nil {
			select {
			case <-clientDied:
				pub.log.Info("rw hold: client disconnected while held — no backend opened",
					"session_id", sid, "username", tok.Username)
				pub.finishHeldSession(sid)
				return nil, net.ErrClosed
			default:
			}
		}
		select {
		case <-ctx.Done():
			pub.finishHeldSession(sid)
			return nil, ctx.Err()
		case <-admitted:
			backend, err := connect(ctx, tok, res, db)
			if err != nil {
				// Admission happened but the connect failed: report it to
				// the client exactly like the pre-hold connect failure
				// (the caller writes its protocol error); the pending
				// record is removed — the session never came up.
				pub.finishHeldSession(sid)
				return nil, err
			}
			return backend, nil
		case <-ticker.C:
			// Heartbeat the pending record so a long hold (minutes) never
			// expires out of the directory while the client is connected.
			pub.holdHeartbeat(tok)
		}
	}
}

// holdClientWatch is per-plane (each plane's handshake read loop already
// detects disconnect; the planes pass their own death channels).

// startHoldClientProbe arms the Peek-based disconnect probe for a held
// rw session (the CRITICAL-2 leak fix, shared by all three hold planes).
// It is EXACTLY the probe loop the planes used to inline, with one
// addition: probeStop. The probe re-arms a rwHoldPollInterval read
// deadline on the client conn every cycle; without a stop signal that
// deadline survives admission and kills the relay read of any client
// idle longer than 500ms. stopHoldClientProbe MUST run on admission —
// before the conn is handed to the relay — to stop the goroutine, clear
// the deadline, and retire the death signal.
//
// Conns are expected to honor read deadlines (every real socket does); a
// deadline-ignoring test conn (net.Pipe) leaves the probe parked inside
// Peek until its NEXT deadline-setting cycle — stopHoldClientProbe still
// returns (see below), the conn is handed to the relay deadline-free, and
// the parked Peek is broken by the first real deadline clearance.
//
// The returned probeExited channel closes when the probe goroutine has
// returned from its loop (on real sockets: fully off the conn).
func startHoldClientProbe(client net.Conn, br *bufio.Reader) (clientDied chan struct{}, probeStop chan struct{}, probeExited chan struct{}) {
	died := make(chan struct{})
	stop := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		// Disconnect probe: Peek (NOT Read — a consumed byte would
		// corrupt the relayed stream). A held client is silent — the
		// peek hits the conn deadline every cycle and the client stays
		// held; a peer close errors instantly. Early client data (a
		// protocol-broken early query) counts as liveness and STAYS
		// buffered for the post-admission relay.
		for stopped := false; !stopped; {
			// Check the stop signal between cycles so a stop observed
			// mid-cycle is honored before the next Peek arms.
			select {
			case <-stop:
				return
			default:
			}
			_ = client.SetReadDeadline(time.Now().Add(rwHoldPollInterval))
			if _, err := br.Peek(1); err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue // silent — still held, still alive
				}
				// disconnected: raise the death signal, then WAIT for
				// the stop close before leaving. Waiting (instead of
				// exiting immediately) keeps the stop/exit handshake
				// total: stopHoldClientProbe closes stop and waits for
				// exited; whatever order the two goroutines observe the
				// closes in, exited is always seen after stop.
				close(died)
				<-stop
				return
			}
			_ = client.SetReadDeadline(time.Time{})
		}
	}()
	return died, stop, exited
}

// stopHoldClientProbe tears the probe down at admission and restores the
// conn to the deadline-free state the relay contract requires. The ORDER
// is load-bearing: close stop, WAIT for the probe goroutine to return
// (bounded — the conn honors read deadlines, so its Peek finishes within
// one rwHoldPollInterval), THEN clear the read deadline. Clearing before
// the exit would race: the probe's final cycle can arm a fresh 500ms
// deadline after the clear, and an expired-but-uncleared deadline makes
// every later read fail instantly — the exact leak this fix removes.
// The death signal is retired UNLESS the probe already fired it (a
// genuinely dead client keeps its signal; the hold's select must still
// see it).
func stopHoldClientProbe(client net.Conn, probeStop chan<- struct{}, probeExited <-chan struct{}, clientDied chan struct{}) {
	close(probeStop)
	<-probeExited
	_ = client.SetReadDeadline(time.Time{})
	// Retire the death signal ONLY if the probe never fired.
	select {
	case <-clientDied:
		// already dead — leave the signal for the hold's select
	default:
		close(clientDied)
	}
}
