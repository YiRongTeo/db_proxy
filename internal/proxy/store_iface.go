package proxy

import (
	"context"
	"time"

	"zerotrust-proxy/internal/models"
)

// Store is the narrow store surface the three proxies depend on. The
// concrete *store.ValkeyStore satisfies it; keeping an interface here lets
// tests inject erroring wrappers without a fake valkey server (review
// 2026-08-16, ITEM 5 GETDEL-error replies).
type Store interface {
	GetDeleteToken(ctx context.Context, token string) (*models.TokenPayload, error)
	Publish(ctx context.Context, channel string, message []byte) error
	SetSessionLive(ctx context.Context, sid string, rec []byte, ttl time.Duration) error
	DelSessionLive(ctx context.Context, sid string) error
	WatchActive(ctx context.Context, sid string) (bool, error)
	// TokenAlive (Task 9.13 session liveness) reports whether a token key
	// still exists — the session sweeper's revocation signal.
	TokenAlive(ctx context.Context, token string) (bool, error)
	// DeleteToken (Task 9.13) removes a token key unconditionally — the
	// kill path revokes a session by deleting its key so no new
	// connection can re-establish it.
	DeleteToken(ctx context.Context, token string) error
}
