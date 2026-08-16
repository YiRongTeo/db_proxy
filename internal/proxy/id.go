package proxy

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// newEventID returns a random 64-bit hex id for a QueryEvent. rand.Read
// cannot fail in practice on supported platforms; the zero fallback keeps
// the id field non-empty even in that pathological case.
func newEventID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

// newCancelKey returns a random 32-bit cancel secret for the PG
// CancelRequest model (pid + secret; review 2026-08-17). rand.Read cannot
// fail in practice on supported platforms; the time-based fallback keeps
// sessions cancellable in that pathological case.
func newCancelKey() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint32(b[:])
}
