package memlog_test

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/telemetrylog"
	"github.com/marmutapp/superbased-observer/internal/telemetrylog/memlog"
)

func TestMaxAckPendingRetainsCreditAcrossNakAndReplicas(t *testing.T) {
	for _, terminal := range []string{"ack", "term"} {
		t.Run(terminal, func(t *testing.T) {
			clk := &clock{t: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)}
			log := memlog.New(memlog.Options{Now: clk.now})
			t.Cleanup(func() { _ = log.Close() })
			for _, body := range []string{"first", "second"} {
				if _, err := log.Publish(t.Context(), pushRecord("org", body)); err != nil {
					t.Fatal(err)
				}
			}
			spec := telemetrylog.ConsumerSpec{Name: "ordered", MaxAckPending: 1, AckWait: time.Minute}
			first, err := log.Subscribe(t.Context(), spec)
			if err != nil {
				t.Fatal(err)
			}
			second, err := log.Subscribe(t.Context(), spec)
			if err != nil {
				t.Fatal(err)
			}
			got, err := first.Fetch(t.Context(), 64, 0)
			if err != nil || len(got) != 1 || got[0].Sequence() != 1 {
				t.Fatalf("initial=%v err=%v", got, err)
			}
			if other, err := second.Fetch(t.Context(), 64, 0); err != nil || len(other) != 0 {
				t.Fatalf("inflight credit escaped: n=%d err=%v", len(other), err)
			}
			if err := got[0].Nak(t.Context(), time.Second); err != nil {
				t.Fatal(err)
			}
			if other, err := second.Fetch(t.Context(), 64, 0); err != nil || len(other) != 0 {
				t.Fatalf("NAK released durable credit: n=%d err=%v", len(other), err)
			}
			clk.advance(time.Second)
			retry, err := second.Fetch(t.Context(), 64, 0)
			if err != nil || len(retry) != 1 || retry[0].Sequence() != 1 || retry[0].Attempt() != 2 {
				t.Fatalf("retry=%v err=%v", retry, err)
			}
			before, trusted := got[0].(telemetrylog.OrderedDelivery).OrderPosition()
			after, retryTrusted := retry[0].(telemetrylog.OrderedDelivery).OrderPosition()
			if !trusted || !retryTrusted || before != after {
				t.Fatalf("retry order changed: before=%+v after=%+v", before, after)
			}
			if terminal == "ack" {
				err = retry[0].Ack(t.Context())
			} else {
				err = retry[0].Term(t.Context(), "test quarantine")
			}
			if err != nil {
				t.Fatal(err)
			}
			next, err := first.Fetch(t.Context(), 64, 0)
			if err != nil || len(next) != 1 || next[0].Sequence() != 2 {
				t.Fatalf("next=%v err=%v", next, err)
			}
		})
	}
}

func TestOrderPositionUsesImmutableLogLifetime(t *testing.T) {
	clk := &clock{t: time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)}
	var positions []telemetrylog.OrderPosition
	for range 2 {
		log := memlog.New(memlog.Options{Now: clk.now})
		t.Cleanup(func() { _ = log.Close() })
		if _, err := log.Publish(t.Context(), pushRecord("org", "same")); err != nil {
			t.Fatal(err)
		}
		consumer, err := log.Subscribe(t.Context(), telemetrylog.ConsumerSpec{Name: "reader"})
		if err != nil {
			t.Fatal(err)
		}
		got, err := consumer.Fetch(t.Context(), 1, 0)
		if err != nil || len(got) != 1 {
			t.Fatalf("fetch=%v err=%v", got, err)
		}
		position, trusted := got[0].(telemetrylog.OrderedDelivery).OrderPosition()
		if !trusted || position.Sequence != 1 {
			t.Fatalf("position=%+v trusted=%v", position, trusted)
		}
		positions = append(positions, position)
	}
	if positions[0].Generation == positions[1].Generation {
		t.Fatal("distinct log lifetimes shared a generation under the same injected clock")
	}
}
