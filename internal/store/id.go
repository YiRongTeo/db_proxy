package store

import (
	"crypto/rand"
	"encoding/hex"
)

// newID returns a random 128-bit hex id (used for tokens and session ids).
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewToken returns a token of the form sess_<32 hex chars>.
func NewToken() (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	return "sess_" + id, nil
}
