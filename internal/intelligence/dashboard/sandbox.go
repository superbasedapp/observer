package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// handleTerminalSandbox serves GET /api/terminal/sandbox — the B9 sandbox
// probe surface (plan §5, mirroring the B5 GET /api/terminal/launch/models
// fail-soft pattern). It ALWAYS returns HTTP 200: an old daemon build 404s
// this route entirely (unknown path), while a live daemon always 200s with
// an honest verdict — including when the sandbox feature itself is absent
// (nil seam), which reports {"available":false,"verdict":"disabled_by_config",
// "reason":"…"} rather than an error status. This is deliberately DIFFERENT
// from handleTerminalLaunch's fail-CLOSED sandbox validation: that handler
// answers "can I honour a sandbox request RIGHT NOW" (and refuses the launch
// with 501/403/400 when it can't); this endpoint answers "what can this
// daemon do at all" — a read, never a refusal.
//
// The read is bounded (lane L2): the probe runs vendor and host checks, and
// a page must never wait on one without end, so a probe that has not
// answered within sandboxProbeDeadline answers probe_timed_out while it
// keeps running, and a probe that panics answers probe_failed.
func (s *Server) handleTerminalSandbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.SandboxProber == nil {
		writeJSON(w, SandboxAvailability{
			Available: false,
			Verdict:   VerdictDisabledByConfig,
			Reason:    "sandbox support is not enabled on this daemon",
		})
		return
	}
	av, ok := s.sandboxProbe.probe(r.Context(), s.opts.SandboxProber, sandboxProbeDeadline)
	if !ok {
		// The client went away; there is nobody to answer.
		return
	}
	writeJSON(w, av)
}

// sandboxProbeDeadline is how long one GET /api/terminal/sandbox waits for
// the probe. The probe's own checks carry shorter per-check timeouts (bwrap's
// are 5 s each); this bounds their sum and anything that has none.
var sandboxProbeDeadline = 20 * time.Second

// sandboxProbeRunLimit bounds the background probe itself, so a stuck check
// cannot hold the one in-flight slot for the daemon's life.
var sandboxProbeRunLimit = 2 * time.Minute

// sandboxProbeFlights holds the one in-flight probe the read route waits on.
// Every read that arrives while a probe runs waits on the same one, so a page
// that keeps polling a stuck probe never starts a second.
type sandboxProbeFlights struct {
	mu  sync.Mutex
	cur *sandboxProbeFlight
}

// sandboxProbeFlight is one running probe; av is written before done closes.
type sandboxProbeFlight struct {
	done chan struct{}
	av   SandboxAvailability
}

// probe returns the prober's answer, the probe_timed_out answer when it has
// not answered within deadline, or ok=false when ctx ended first. The probe
// runs detached from ctx (bounded by sandboxProbeRunLimit), so a closed page
// never aborts a probe another read is waiting on.
func (f *sandboxProbeFlights) probe(ctx context.Context, prober SandboxProber, deadline time.Duration) (SandboxAvailability, bool) {
	f.mu.Lock()
	fl := f.cur
	if fl == nil {
		fl = &sandboxProbeFlight{done: make(chan struct{})}
		f.cur = fl
		go f.run(context.WithoutCancel(ctx), prober, fl)
	}
	f.mu.Unlock()
	t := time.NewTimer(deadline)
	defer t.Stop()
	select {
	case <-fl.done:
		return fl.av, true
	case <-t.C:
		return SandboxAvailability{
			Available: false,
			Verdict:   VerdictProbeTimedOut,
			Reason:    fmt.Sprintf("the sandbox probe did not answer within %s; it keeps running and the next check shows its answer", deadline),
		}, true
	case <-ctx.Done():
		return SandboxAvailability{}, false
	}
}

// run performs one probe and frees the slot. A panic is recovered into the
// probe_failed answer: the probe runs off the request goroutine, where an
// unrecovered panic would stop the daemon.
func (f *sandboxProbeFlights) run(ctx context.Context, prober SandboxProber, fl *sandboxProbeFlight) {
	ctx, cancel := context.WithTimeout(ctx, sandboxProbeRunLimit)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			fl.av = SandboxAvailability{
				Available: false,
				Verdict:   VerdictProbeFailed,
				Reason:    fmt.Sprintf("the sandbox probe stopped with an internal error: %v", p),
			}
		}
		f.mu.Lock()
		if f.cur == fl {
			f.cur = nil
		}
		f.mu.Unlock()
		close(fl.done)
	}()
	fl.av = prober.ProbeSandbox(ctx)
}
