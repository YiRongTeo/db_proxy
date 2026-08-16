// Package storetest provides test-only helpers for building ValkeyStore
// instances. Task 9.9 review remediation: production code must not carry
// test-only surface, so the plaintext direct-mode convenience constructor
// moved here from internal/store.
package storetest

import (
	"context"

	"zerotrust-proxy/internal/store"
)

// NewValkeyStoreDirect is the plaintext direct-mode convenience wrapper
// (single address, no sentinel, no TLS) for tests.
func NewValkeyStoreDirect(ctx context.Context, addr, password string, db int) (*store.ValkeyStore, error) {
	return store.NewValkeyStore(ctx, store.StoreOptions{Addrs: []string{addr}, Password: password, DB: db})
}
