package sandboxremote

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// endOrderProc records the calls EndStream makes. halfBlocks makes the
// stdin close wait until the stream is cut and released (a send that flow
// control holds keeps the send lock until then); halfNever makes it never
// return.
type endOrderProc struct {
	Process
	mu         sync.Mutex
	calls      []string
	ends       chan struct{}
	cut        chan struct{}
	released   chan struct{}
	halfBlocks bool
	halfNever  bool
}

func newEndOrderProc(endsAtOnce bool) *endOrderProc {
	p := &endOrderProc{ends: make(chan struct{}), cut: make(chan struct{}), released: make(chan struct{})}
	if endsAtOnce {
		close(p.ends)
	}
	return p
}

func (p *endOrderProc) note(s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, s)
}

func (p *endOrderProc) got() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.calls, ",")
}

func (p *endOrderProc) CloseWrite() error {
	if p.halfNever {
		select {}
	}
	if p.halfBlocks {
		<-p.released
		p.note("close_write_after_cut")
		return errors.New("the stream was cut")
	}
	p.note("close_write")
	return nil
}

func (p *endOrderProc) Wait(ctx context.Context) (int, error) {
	p.note("wait")
	select {
	case <-p.ends:
		return 0, nil
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

func (p *endOrderProc) Kill(context.Context) error {
	p.note("kill")
	select {
	case <-p.cut:
	default:
		close(p.cut)
	}
	return nil
}

func (p *endOrderProc) Close() error {
	p.note("close")
	select {
	case <-p.released:
	default:
		close(p.released)
	}
	return nil
}

// cutOnly is a stream with no separate stdin close.
type cutOnly struct{ *endOrderProc }

func (cutOnly) CloseWrite() {} // not the HalfCloser shape

// TestEndStreamOrder (lane FX6, FX6-A1): the stdin side is closed first,
// the stream is given what is left of the bound to end, then it is cut and
// released; a half-close held behind a send is bounded and released by the
// cut, and EndStream waits for it, so nothing it started outlives it; a
// half-close that never returns is reported, never waited on forever.
func TestEndStreamOrder(t *testing.T) {
	cases := []struct {
		name    string
		proc    func() *endOrderProc
		want    string
		wantErr error
	}{
		{"ends on its own", func() *endOrderProc { return newEndOrderProc(true) }, "close_write,wait,kill,close", nil},
		{"never ends: bounded wait, then the cut", func() *endOrderProc { return newEndOrderProc(false) }, "close_write,wait,kill,close", nil},
		{"half-close held behind a send: bounded, released by the cut", func() *endOrderProc {
			p := newEndOrderProc(false)
			p.halfBlocks = true
			return p
		}, "kill,close,close_write_after_cut", nil},
		{"half-close never returns: reported", func() *endOrderProc {
			p := newEndOrderProc(false)
			p.halfNever = true
			return p
		}, "kill,close", ErrHalfCloseStuck},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.proc()
			start := time.Now()
			err := EndStream(context.Background(), p, 50*time.Millisecond)
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("EndStream took %v", d)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err %v, want %v", err, tc.wantErr)
			}
			if got := p.got(); got != tc.want {
				t.Fatalf("calls %q, want %q", got, tc.want)
			}
		})
	}
	c := cutOnly{newEndOrderProc(false)}
	if err := EndStream(context.Background(), c, time.Hour); err != nil { // returns at once
		t.Fatal(err)
	}
	if got := c.got(); got != "kill,close" {
		t.Fatalf("a stream with no stdin close: calls %q, want kill,close", got)
	}
}

// hangKill is a stream whose Kill hangs until its context ends (a vendor
// Kill that is an HTTP call with no timeout of its own).
type hangKill struct{ *endOrderProc }

func (p hangKill) Kill(ctx context.Context) error {
	p.note("kill")
	<-ctx.Done()
	return ctx.Err()
}

// TestEndStreamBoundsTheCut (lane FX6, FX6-R3): a hung Kill cannot hold
// the run's end: EndStream's cut is bounded by its wait.
func TestEndStreamBoundsTheCut(t *testing.T) {
	p := hangKill{newEndOrderProc(true)}
	start := time.Now()
	if err := EndStream(context.Background(), p, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a hung Kill held EndStream %v", d)
	}
	if got := p.got(); got != "close_write,wait,kill,close" {
		t.Fatalf("calls %q", got)
	}
}

// TestEndStreamDoneContextStillCuts (fold audit N6): a ctx that is already
// done skips the wait for a clean end, and the stream is still cut and
// released, so a cancelled caller never leaves it open.
func TestEndStreamDoneContextStillCuts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := newEndOrderProc(false) // never ends on its own
	start := time.Now()
	if err := EndStream(ctx, p, time.Hour); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a done ctx still waited %v", d)
	}
	if got := p.got(); !strings.Contains(got, "kill,close") || strings.Contains(got, "wait") {
		t.Fatalf("calls %q, want the cut and the release and no wait", got)
	}
}
