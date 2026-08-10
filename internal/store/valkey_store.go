package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/valkey-io/valkey-go"
	"zerotrust-proxy/internal/models"
)

// ValkeyStore wraps valkey-go with the token/session primitives.
type ValkeyStore struct {
	client valkey.Client
}

func NewValkeyStore(ctx context.Context, addr, password string, db int) (*ValkeyStore, error) {
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, Password: password, SelectDB: db})
	if err != nil {
		return nil, fmt.Errorf("valkey client: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := client.Do(pingCtx, client.B().Ping().Build()).Error(); err != nil {
		return nil, fmt.Errorf("valkey ping: %w", err)
	}
	return &ValkeyStore{client: client}, nil
}

func (s *ValkeyStore) Close() { s.client.Close() }

// Ping checks Valkey connectivity (used by the health endpoint).
func (s *ValkeyStore) Ping(ctx context.Context) error {
	return s.client.Do(ctx, s.client.B().Ping().Build()).Error()
}

// SetToken stores a token payload with a TTL (single-use semantics enforced
// by the caller using GetDeleteToken).
func (s *ValkeyStore) SetToken(ctx context.Context, token string, p models.TokenPayload, ttl time.Duration) error {
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.client.Do(ctx, s.client.B().Set().Key("tok:"+token).Value(string(data)).Ex(ttl).Build()).Error()
}

// GetDeleteToken atomically reads and deletes a token. Returns (nil, nil)
// when the token is absent or already consumed — this is the single-use gate.
func (s *ValkeyStore) GetDeleteToken(ctx context.Context, token string) (*models.TokenPayload, error) {
	raw, err := s.client.Do(ctx, s.client.B().Getdel().Key("tok:"+token).Build()).ToString()
	if errors.Is(err, valkey.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p models.TokenPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("token payload decode: %w", err)
	}
	return &p, nil
}

// CreateSession stores a UI session with a TTL and returns its id.
func (s *ValkeyStore) CreateSession(ctx context.Context, sess models.Session, ttl time.Duration) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	key := "sess:ui:" + id
	if err := s.client.Do(ctx, s.client.B().Set().Key(key).Value(string(data)).Ex(ttl).Build()).Error(); err != nil {
		return "", err
	}
	return id, nil
}

// GetSession returns the session for an id, or nil if absent/expired.
func (s *ValkeyStore) GetSession(ctx context.Context, id string) (*models.Session, error) {
	raw, err := s.client.Do(ctx, s.client.B().Get().Key("sess:ui:"+id).Build()).ToString()
	if errors.Is(err, valkey.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sess models.Session
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *ValkeyStore) DeleteSession(ctx context.Context, id string) error {
	return s.client.Do(ctx, s.client.B().Del().Key("sess:ui:"+id).Build()).Error()
}
