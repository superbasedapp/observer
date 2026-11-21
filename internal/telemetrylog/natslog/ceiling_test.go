package natslog

import (
	"context"
	"errors"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
)

// TestRereadCeilingRetriesOnceThenUnknown pins R-A05: the ceiling re-read is
// tried twice; a single failure is absorbed, two make the ceiling unknown
// (never the first read, which would report a false ahead).
func TestRereadCeilingRetriesOnceThenUnknown(t *testing.T) {
	ok := &jetstream.StreamInfo{State: jetstream.StreamState{LastSeq: 42}}
	for _, tc := range []struct {
		name        string
		fails       int
		wantCeiling uint64
		wantUnknown bool
		wantCalls   int
	}{
		{"first read succeeds", 0, 42, false, 1},
		{"one failure is retried", 1, 42, false, 2},
		{"two failures are unknown", 2, 0, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			info := func(context.Context, ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) {
				calls++
				if calls <= tc.fails {
					return nil, errors.New("broker blip")
				}
				return ok, nil
			}
			ceiling, unknown := rereadCeiling(context.Background(), info)
			if ceiling != tc.wantCeiling || unknown != tc.wantUnknown || calls != tc.wantCalls {
				t.Fatalf("rereadCeiling = %d, %v after %d calls; want %d, %v after %d", ceiling, unknown, calls, tc.wantCeiling, tc.wantUnknown, tc.wantCalls)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, unknown := rereadCeiling(ctx, func(context.Context, ...jetstream.StreamInfoOpt) (*jetstream.StreamInfo, error) { return ok, nil }); !unknown {
		t.Fatal("a cancelled context must report the ceiling unknown")
	}
}
