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
}
