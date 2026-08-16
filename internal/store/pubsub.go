package store

import (
	"context"
	"fmt"

	"github.com/valkey-io/valkey-go"
)

// Publish sends a raw JSON message to a channel.
func (s *ValkeyStore) Publish(ctx context.Context, channel string, message []byte) error {
	return s.client.Do(ctx, s.client.B().Publish().Channel(channel).Message(string(message)).Build()).Error()
}

// Subscribe streams messages from a channel (or pattern when pattern=true,
// e.g. "queries:*"). It blocks until ctx is cancelled or the connection
// fails, forwarding each message to out. It returns an error if the
// subscription itself fails; on ctx cancellation it returns ctx.Err().
func (s *ValkeyStore) Subscribe(ctx context.Context, channel string, pattern bool, out chan<- []byte) error {
	var cmd valkey.Completed
	if pattern {
		cmd = s.client.B().Psubscribe().Pattern(channel).Build()
	} else {
		cmd = s.client.B().Subscribe().Channel(channel).Build()
	}
	// Receive registers the subscription and invokes fn for every message
	// until ctx is cancelled (it then returns ctx.Err()). fn runs on the
	// client's reader goroutine, so it must NEVER block — a slow consumer
	// would otherwise head-of-line-block every other subscription on this
	// client (review 9.9 slow-consumer HOL). The send is therefore
	// non-blocking: the bounded out buffer absorbs bursts, and once it is
	// full NEW messages are dropped. Live query events tolerate drops (the
	// checker UI renders what arrives); audit lifecycle drops are healed by
	// the pending-audit sweeper.
	err := s.client.Receive(ctx, cmd, func(msg valkey.PubSubMessage) {
		select {
		case out <- []byte(msg.Message):
		case <-ctx.Done():
		default: // slow consumer — drop rather than block the reader
		}
	})
	if err != nil {
		return fmt.Errorf("subscribe %s: %w", channel, err)
	}
	return nil
}
