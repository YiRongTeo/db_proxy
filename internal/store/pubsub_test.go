package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
)

// TestPubSubChannelAndPattern subscribes to the same channel both directly and
// via a pattern, publishes two messages, and expects each subscriber to
// receive both, in publish order. Cancelling the context must make both
// Subscribe calls return.
//
// The pattern is scoped to a UNIQUE namespace (queries:pubsub-*): the
// alternative "queries:*" catches foreign events published by other packages
// running in parallel (go test ./... — api/proxy live suites publish session
// lifecycle events on queries:<user> / queries:sess:<sid>), which made the
// exact-payload assertions racy.
func TestPubSubChannelAndPattern(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	channelName := "queries:pubsub-" + uniqueSid(t)
	patternName := "queries:pubsub-*"
	channelOut := make(chan []byte, 8)
	patternOut := make(chan []byte, 8)
	subErr := make(chan error, 2)
	acked := make(chan struct{}, 2)

	// ack fires on the wire reader goroutine when the server confirms the
	// subscription, so publishing after the ack cannot race the subscribe.
	subscribe := func(channel string, pattern bool, out chan<- []byte) {
		subCtx := valkey.WithOnSubscriptionHook(ctx, func(valkey.PubSubSubscription) {
			select {
			case acked <- struct{}{}:
			default:
			}
		})
		subErr <- s.Subscribe(subCtx, channel, pattern, out)
	}

	go subscribe(channelName, false, channelOut)
	go subscribe(patternName, true, patternOut)

	for i := 0; i < 2; i++ {
		select {
		case <-acked:
		case <-time.After(5 * time.Second):
			t.Fatal("subscription not confirmed within 5s")
		}
	}

	msg1 := []byte(`{"id":1,"query":"SELECT 1"}`)
	msg2 := []byte(`{"id":2,"query":"SELECT 2"}`)
	if err := s.Publish(ctx, channelName, msg1); err != nil {
		t.Fatalf("Publish #1: %v", err)
	}
	if err := s.Publish(ctx, channelName, msg2); err != nil {
		t.Fatalf("Publish #2: %v", err)
	}

	// Each subscriber must receive both messages, in publish order.
	for name, out := range map[string]chan []byte{"channel": channelOut, "pattern": patternOut} {
		got1 := recvPubSubMsg(t, out)
		got2 := recvPubSubMsg(t, out)
		if string(got1) != string(msg1) || string(got2) != string(msg2) {
			t.Fatalf("%s subscriber: got %q then %q, want %q then %q", name, got1, got2, msg1, msg2)
		}
	}

	// Cancelling the context must make both Subscribe calls return.
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case err := <-subErr:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Subscribe returned %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Subscribe did not return within 5s of context cancel")
		}
	}
}

func recvPubSubMsg(t *testing.T, out <-chan []byte) []byte {
	t.Helper()
	select {
	case m := <-out:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for pubsub message")
		return nil
	}
}
