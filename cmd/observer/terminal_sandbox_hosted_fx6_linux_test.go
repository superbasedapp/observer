//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// relayCtxBox is a fake client that keeps the context the relay stream
// (the one exec with a streaming stdin) was opened on; every other exec
// answers exit 0.
type relayCtxBox struct {
	sandboxremote.Client
	relayCtx context.Context
	cut      atomic.Int32
	// halfCloses counts the relay stream's stdin closes: the mux conn's
	// close is one (FX6-R2).
	halfCloses atomic.Int32
}

func (b *relayCtxBox) WriteFiles(context.Context, string, []sandboxremote.UploadFile) error {
	return nil
}

func (b *relayCtxBox) Exec(ctx context.Context, _ string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	if !spec.Stdin {
		return doneProc{Reader: strings.NewReader(""), code: 0}, nil
	}
	b.relayCtx = ctx
	return &cutCountProc{doneProc: doneProc{Reader: strings.NewReader("")}, cut: &b.cut, halfCloses: &b.halfCloses}, nil
}

// cutCountProc is a relay stream that refuses the handshake's first write
// and counts its cuts.
type cutCountProc struct {
	doneProc
	cut, halfCloses *atomic.Int32
}

func (p *cutCountProc) Kill(context.Context) error { p.cut.Add(1); return nil }

func (p *cutCountProc) CloseWrite() error { p.halfCloses.Add(1); return nil }

// TestHostedRelayStreamOutlivesTheRunContext (lane FX6, FX6-A1): the relay
// stream is opened on a context the run's end does not cancel, so the run's
// end cannot reset it before keepRelay closes it cleanly; a stream whose
// handshake fails is still cut.
func TestHostedRelayStreamOutlivesTheRunContext(t *testing.T) {
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	v.UploadViaExec = false
	box := &relayCtxBox{}
	r := &hostedRun{
		plan:   hostedPlanFile{RunID: "r1", Provider: v.ID, ObserverDir: t.TempDir(), Root: "/home/dev/app"},
		t:      hostedTerm{out: io.Discard},
		now:    time.Now,
		vendor: v, client: box,
	}
	r.layout = v.Layout(r.plan.Root)
	run, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, _, err := r.startRelay(run, nil); err == nil {
		t.Fatal("a stream that refused the handshake started a relay")
	}
	if box.relayCtx == nil {
		t.Fatal("no relay stream was opened")
	}
	if box.cut.Load() == 0 {
		t.Error("a relay stream whose handshake failed was not cut")
	}
	if box.halfCloses.Load() == 0 {
		t.Error("the mux conn of a failed handshake was not closed (FX6-R2)")
	}
	cancel()
	if err := box.relayCtx.Err(); err != nil {
		t.Fatalf("the run's end cancelled the relay stream's context (%v): the stream is reset before its clean close", err)
	}
}

// TestHostedRelayStartedLine (lane FX6, F-P8-2): the relay log names a
// process handle only when the vendor has one.
func TestHostedRelayStartedLine(t *testing.T) {
	for pid, want := range map[string]string{
		"":    "the relay process started; waiting for its ready",
		"412": "the relay process started (pid 412); waiting for its ready",
	} {
		if got := hostedRelayStartedLine(pid); got != want {
			t.Errorf("pid %q: %q, want %q", pid, got, want)
		}
	}
}

// hangKillProc is a vendor process whose Kill hangs until its context ends
// (an HTTP Kill with no timeout of its own).
type hangKillProc struct {
	doneProc
	deadline atomic.Bool
}

func (p *hangKillProc) Kill(ctx context.Context) error {
	_, ok := ctx.Deadline()
	p.deadline.Store(ok)
	<-ctx.Done()
	return ctx.Err()
}

// TestHostedKillIsBounded (lane FX6, FX6-R3): a vendor Kill that hangs
// cannot hold the run's end: every cut at the run's end and in startRelay
// is bounded by hostedRelayCloseWait, even after the run's context ended.
func TestHostedKillIsBounded(t *testing.T) {
	old := hostedRelayCloseWait
	hostedRelayCloseWait = 50 * time.Millisecond
	t.Cleanup(func() { hostedRelayCloseWait = old })
	run, cancel := context.WithCancel(context.Background())
	cancel() // the run is over
	p := &hangKillProc{}
	start := time.Now()
	hostedKill(run, p)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a hung Kill held the run's end %v", d)
	}
	if !p.deadline.Load() {
		t.Error("the Kill had no deadline")
	}
}
