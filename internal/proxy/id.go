package proxy

import (
	"crypto/rand"
	"encoding/hex"
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
