package openshellorg

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// TestTransportTable: one case per tested version, plus an untested one.
func TestTransportTable(t *testing.T) {
	cases := []struct {
		version string
		ok      bool
		relay   RelayShape
	}{
		{"0.1.6", true, RelayTTYOff},
		{"0.1.7", false, ""},
		{"", false, ""},
	}
	for _, tc := range cases {
		r, ok := TransportFor(tc.version)
		if ok != tc.ok || r.Relay != tc.relay || (ok && r.Suspend) {
			t.Errorf("%q: %+v %v", tc.version, r, ok)
		}
	}
}

// TestAckFilter: credit lines are taken out and reported; other lines and
// a split credit line across two feeds behave.
func TestAckFilter(t *testing.T) {
	var got []int64
	f := NewAckFilter(func(n int64) { got = append(got, n) })
	out := f.Feed([]byte("hello\n"))
	out = append(out, f.Feed(AckLine(10)[:5])...)
	out = append(out, f.Feed(append(AckLine(10)[5:], AckLine(42)...))...)
	out = append(out, f.Feed([]byte("bye\n\x1esbo-ack nope\n"))...)
	if string(out) != "hello\nbye\n\x1esbo-ack nope\n" {
		t.Errorf("passed on %q", out)
	}
	if len(got) != 2 || got[0] != 10 || got[1] != 42 {
		t.Errorf("credit %v", got)
	}
	// A long run with no newline is passed on, not held forever.
	if out := f.Feed([]byte("a partial line that is no credit line at all")); len(out) == 0 {
		t.Error("a non-credit partial line was held")
	}
}

// TestCreditWaitRoom: room, credit raising it, a stall and the stream end.
func TestCreditWaitRoom(t *testing.T) {
	c := NewCredit()
	ctx := context.Background()
	if err := c.WaitRoom(ctx, 0, 100, 100, time.Second); err != nil {
		t.Fatalf("room at zero: %v", err)
	}
	if err := c.WaitRoom(ctx, 100, 1, 100, 20*time.Millisecond); !errors.Is(err, ErrNoCredit) {
		t.Errorf("stall: %v", err)
	}
	go func() { time.Sleep(5 * time.Millisecond); c.Set(50) }()
	if err := c.WaitRoom(ctx, 100, 50, 100, time.Second); err != nil {
		t.Errorf("credit raised: %v", err)
	}
	c.Set(10) // never lowers
	if c.Consumed() != 50 {
		t.Errorf("consumed %d", c.Consumed())
	}
	c.Close()
	if err := c.WaitRoom(ctx, 1000, 1, 100, time.Second); !errors.Is(err, ErrStreamEnded) {
		t.Errorf("after close: %v", err)
	}
}

// TestAckFilterAndCreditUnderAFlood (fix round 1, the 11.4 frame-flood row):
// a box that floods credit lines, forges a credit far above what was sent,
// or writes a long run with no newline neither grows the filter's buffer
// nor opens room beyond the window.
func TestAckFilterAndCreditUnderAFlood(t *testing.T) {
	c := NewCredit()
	f := NewAckFilter(c.Set)
	var flood []byte
	for i := range 100000 {
		flood = append(flood, AckLine(int64(i))...)
	}
	if out := f.Feed(flood); len(out) != 0 || len(f.buf) != 0 {
		t.Fatalf("a credit flood passed on %d bytes, buffered %d", len(out), len(f.buf))
	}
	f.Feed(AckLine(1 << 40))
	if err := c.WaitRoom(context.Background(), 1000, 101, 100, 20*time.Millisecond); !errors.Is(err, ErrNoCredit) {
		t.Errorf("a forged credit opened room beyond the window: %v", err)
	}
	if err := c.WaitRoom(context.Background(), 1000, 100, 100, time.Second); err != nil {
		t.Errorf("a credit of everything sent leaves the window: %v", err)
	}
	junk := bytes.Repeat([]byte{ackTag[0]}, 1<<20)
	if out := f.Feed(junk); len(out) != len(junk) || len(f.buf) != 0 {
		t.Errorf("a megabyte with no newline: passed %d, buffered %d", len(out), len(f.buf))
	}
}
