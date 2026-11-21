package sandboxrelayd

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// Executor runs one validated request host-side for run and returns the
// answer the box gets. It is injected by the cmd layer (the hook pipeline
// on the daemon path of internal/hookctx).
type Executor func(ctx context.Context, run RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error)

// PeerCheck vets an accepted connection's peer (PeerSameUser); nil accepts.
type PeerCheck func(c net.Conn) error

// Daemon is the daemon's relay handler: it serves the owner-only link
// endpoint, picks the run from the channel (the link key), and keeps one
// handler state per run.
type Daemon struct {
	// ObserverDir holds the run records.
	ObserverDir string
	// Exec runs a request.
	Exec Executor
	// Rules validate every request again, whatever the helper checked.
	Rules sandboxrelay.RequestRules
	// Conn bounds each link connection; zero is sandboxrelay.DefaultConnLimits.
	Conn sandboxrelay.ConnLimits
	// PerRun caps concurrent requests of one run (zero: 4).
	PerRun int
	// MaxConns caps concurrent link connections (zero: 64).
	MaxConns int
	// ExecTimeout bounds one execution (zero: 60s).
	ExecTimeout time.Duration
	// Peer vets each accepted connection.
	Peer PeerCheck
	// Heartbeat is how often the handler pings the waiting peer while a
	// request runs (zero: sandboxrelay.HeartbeatInterval; negative: off).
	Heartbeat time.Duration
	// Gated reports whether a hook request is a gate event (its answer can
	// block the tool). A replayed gate event is refused; nil treats every
	// request as gated, so nothing is replayed.
	Gated func(req sandboxrelay.HookRequest) bool
	// SessionOwner looks up the project the node already records for a
	// session id; nil skips the lookup (the cross-run claim still holds).
	SessionOwner SessionOwner
	// Rate is the per-run token bucket (zero fields: DefaultRunRate).
	Rate RunRate
	// MaxSessions caps the session ids one run may speak for (zero:
	// DefaultMaxSessions).
	MaxSessions int
	// Now is the clock of the rate bucket (nil: time.Now).
	Now func() time.Time
	// CloneOrigin maps a project root the node recorded for a session to
	// the project it is a managed clone of ("" when it is not a clone), so
	// a session a clone run spoke for counts as its project's; nil: no
	// clone is recognised.
	CloneOrigin func(root string) string
	// OnHealth receives a run's capture health each time it is lowered (a
	// refused, rate-limited, dropped or replayed event, hook drift, missed
	// heartbeats), so the run's evidence can record it; nil records
	// nothing outside the handler state. It is called off the answer path,
	// from one goroutine per run, with the latest health (changes that
	// arrive while a call runs are coalesced into the next call), so a slow
	// write never delays an answer or a heartbeat (P-040).
	OnHealth func(run RunRecord, h Health)
	// OnRunEnd is called once the daemon ended a run (EndRun: its record is
	// gone, or its helper died), after the run's last OnHealth call
	// returned, so state kept beside the handler for the run (the run
	// pill's live health) can go with it; nil: nothing.
	OnRunEnd func(run RunRecord)
	// OnEgressRefusal receives each egress refusal the run's host helper
	// reports (egress.go, lane N1), already validated, with the run taken
	// from the channel; nil drops them. It is called on the link's
	// goroutine before the answer, so it must not block (queue and
	// return).
	OnEgressRefusal func(run RunRecord, rep sandboxrelay.EgressRefusalReport)
	// OnPruned is called with each run record the sweep removed because its
	// helper died (PruneDeadRunRecords), as the record was, whether or not
	// the daemon held state for the run, so the stored run it belongs to
	// can be ended (live check 2026-10-22, D7); nil: nothing.
	OnPruned func(run RunRecord)
	// OnSweep is called at the end of every Sweep, after the dead helpers'
	// records were pruned, so what those runs left elsewhere can be swept
	// with them (their credential files, tracker F-055); nil: nothing.
	OnSweep func()
	// LegacyRefusal renders a refusal for a box that sent a version 1
	// request (its decoder refuses the Refused field): the exit code and
	// output that box would itself have produced for the refusal. nil
	// answers exit 2 with the reason on stderr.
	LegacyRefusal func(req sandboxrelay.HookRequest, why sandboxrelay.Refusal) sandboxrelay.HookResponse
	// BodyDeadline bounds a whole request message on the link from its
	// first frame (zero: DefaultBodyDeadline). The helper opens the link
	// only once the request's header passed, so a box that then drips the
	// body holds a link connection for this long at most (P-032).
	BodyDeadline time.Duration
	// SweepInterval is how often Serve ends the runs whose record is gone
	// (zero: DefaultSweepInterval; negative: never).
	SweepInterval time.Duration
	// Drift compares each run's transcript with the gate events it sent
	// (gatedrift.go); nil: no comparison.
	Drift *GateDrift
	// FreshStore keeps, per run, the sessions the run claimed fresh, so a
	// re-claim after the run's claims were dropped (a re-adoption of the
	// same run, a daemon restart) is fresh again (audit FU3-R1); nil keeps
	// freshness in memory only.
	FreshStore FreshSessions
	// Log receives one line for each connection the daemon closes without
	// an answer and each request it refuses, with the run id the handshake
	// proved ("" when no handshake did, a failed one included: the id a
	// peer claims is not its until the secret check passes, fold audit
	// N4), so a refusal is never silent
	// in the daemon's log (Windows 11 Pro run 3, 2026-10-22); nil: nothing.
	Log func(runID, reason string)

	mu   sync.Mutex
	runs map[string]*RunState
	// sessions maps a session id to the run that first spoke for it.
	sessions map[string]string
	// fresh holds the claimed session ids the node did not record when
	// their run first claimed them (a session the run itself started, not
	// one it resumed; F-003 audit FU3-A1). Cleared with the claim.
	fresh map[string]bool
	// inflight counts health deliveries in flight (FlushHealth). A
	// WaitGroup does not fit: a delivery may start (Add from zero) while
	// FlushHealth waits, which the WaitGroup contract forbids.
	inflight flushCounter
}

// flushCounter counts goroutines in flight and lets a caller wait until
// none is. Unlike sync.WaitGroup, start may run concurrently with wait.
type flushCounter struct {
	mu   sync.Mutex
	n    int
	idle chan struct{} // closed when n drops to zero; nil while n is zero
}

func (c *flushCounter) start() {
	c.mu.Lock()
	if c.n == 0 {
		c.idle = make(chan struct{})
	}
	c.n++
	c.mu.Unlock()
}

func (c *flushCounter) done() {
	c.mu.Lock()
	c.n--
	if c.n == 0 {
		close(c.idle)
		c.idle = nil
	}
	c.mu.Unlock()
}

// wait returns once nothing that started before or during the wait is
// still in flight.
func (c *flushCounter) wait() {
	for {
		c.mu.Lock()
		ch := c.idle
		c.mu.Unlock()
		if ch == nil {
			return
		}
		<-ch
	}
}

// RunState is the per-run handler state (one per run, created on the
// run's first request).
type RunState struct {
	// run is the record the run's latest connection was identified with
	// (guarded by Daemon.mu), handed to OnRunEnd.
	run  RunRecord
	sem  chan struct{}
	rate *bucket
	// refusalSem is the one-slot budget of egress refusal reports, apart
	// from sem (serveEgressRefusal).
	refusalSem chan struct{}
	// sessionCount is the number of session ids this run claimed (guarded
	// by Daemon.mu).
	sessionCount int
	Served       atomic.Int64
	Refused      atomic.Int64
	// Bound counts requests the binding refused with an answer (a path
	// outside the run, another project's session, the rate, a replayed
	// gate event); RateLimited counts the rate's share of them.
	Bound       atomic.Int64
	RateLimited atomic.Int64
	// Replayed counts capture-only events the box spooled while the relay
	// was down; a nonzero count means the run was capture_degraded.
	Replayed atomic.Int64
	// FreshSkipped counts fresh session ids the run claimed that the daemon
	// did not persist for being longer than MaxFreshSessionID (tracker
	// F-039); never fatal to the request.
	FreshSkipped atomic.Int64
	// health is what lowered the run's capture (Health).
	health runHealth
	// drift is the run's transcript-versus-gate comparison; noDrift is set
	// once the run's tool turned out to declare none (both guarded by
	// Daemon.mu).
	drift   *driftState
	noDrift bool
}

// Health returns what lowered the run's capture so far.
func (st *RunState) Health() Health { return st.health.snapshot() }

// DefaultBodyDeadline is the link's per-message deadline: an 8 MiB body
// crosses a local socket in well under 100 ms, so 2 s is generous and still
// a fifth of the box channel's own 10 s.
const DefaultBodyDeadline = 2 * time.Second

// DefaultSweepInterval is how often the daemon looks for ended runs.
const DefaultSweepInterval = 30 * time.Second

// ErrBusy is returned when a run already has PerRun requests in flight.
var ErrBusy = errors.New("sandboxrelayd: run busy")

func (d *Daemon) state(rec RunRecord) *RunState {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.runs == nil {
		d.runs = map[string]*RunState{}
	}
	st, ok := d.runs[rec.RunID]
	if !ok {
		n := d.PerRun
		if n <= 0 {
			n = 4
		}
		st = &RunState{sem: make(chan struct{}, n), refusalSem: make(chan struct{}, 1), rate: &bucket{rate: d.Rate.withDefaults()}}
		d.runs[rec.RunID] = st
	}
	st.run = rec
	return st
}

// Run returns the handler state of runID, if it has served anything.
func (d *Daemon) Run(runID string) (*RunState, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.runs[runID]
	return st, ok
}

func (d *Daemon) conn() sandboxrelay.ConnLimits {
	l := d.Conn
	if l == (sandboxrelay.ConnLimits{}) {
		l = sandboxrelay.DefaultConnLimits
	}
	body := d.BodyDeadline
	if body <= 0 {
		body = DefaultBodyDeadline
	}
	if l.MessageDeadline <= 0 || body < l.MessageDeadline {
		l.MessageDeadline = body
	}
	return l
}

func params(p sandboxrelay.Purpose, c sandboxrelay.ConnLimits) sandboxrelay.Params {
	return sandboxrelay.Params{Purpose: p, Limits: sandboxrelay.DefaultLimits, Conn: c, Rand: rand.Reader}
}

// ServeConn answers one link connection: handshake, one request, one
// response.
func (d *Daemon) ServeConn(ctx context.Context, c net.Conn) error {
	defer func() { _ = c.Close() }()
	var rec RunRecord
	s, err := sandboxrelay.Accept(c, params(sandboxrelay.PurposeLink, d.conn()), func(id string) ([]byte, error) {
		r, err := ReadRun(d.ObserverDir, id)
		if err != nil {
			return nil, err
		}
		rec = r
		return r.LinkSecret, nil
	})
	if err != nil {
		// A link that closed before its hello carried no request (a
		// readiness check dials and hangs up), so it is not a warning; any
		// other handshake failure is (Windows 11 Pro run 4, where the CLI's
		// relay gate logged one per launch with no run id). The line names
		// no run: the id the peer claimed is not proven until a frame from
		// it verifies under the run's secret, and a run's id routes the line into that run's kept
		// relay log, which one box could otherwise fill for another run
		// (fold audit N4), so it goes to the daemon's own log only.
		if !errors.Is(err, sandboxrelay.ErrNoHello) {
			d.log("", "closed a helper's link whose handshake failed: %v", err)
		}
		return fmt.Errorf("sandboxrelayd.ServeConn: %w", err)
	}
	defer s.Release()
	st := d.state(rec)
	err = d.serveRequest(ctx, s, rec, st)
	if err != nil {
		// The run's channel was identified, so a request that did not
		// complete is an event the run lost; a refusal report is no hook
		// event, so its failure lowers nothing.
		if !errors.Is(err, errEgressRefusalReport) {
			d.lower(rec, st, 0, CauseDropped)
		}
		// Accept checks no secret: the handshake is complete only once a
		// frame from the peer verifies under the run's secret. A link that
		// failed before then (a peer with the wrong secret hangs up when the
		// daemon's open frame does not verify on its side) proved no run,
		// so its line, like a failed hello's, names none (fold audit N4).
		// Residual, named in the fold's marker: the lowering above still
		// counts against the claimed run.
		if !s.PeerProven() {
			d.log("", "closed a helper's link whose handshake failed (no frame verified under the run's secret): %v", err)
			return err
		}
		d.log(rec.RunID, "closed the link without an answer: %v", err)
	}
	return err
}

// log writes one line to Log (nil: nothing).
func (d *Daemon) log(runID, format string, a ...any) {
	if d.Log != nil {
		d.Log(runID, fmt.Sprintf(format, a...))
	}
}

// serveRequest reads, binds and answers one request of an identified run.
func (d *Daemon) serveRequest(ctx context.Context, s *sandboxrelay.Session, rec RunRecord, st *RunState) error {
	// The whole message is read before the run's slot is taken, under the
	// link's short body deadline, so a body dripped after a valid header
	// never holds one of the run's PerRun slots (P-032).
	msg, err := s.Recv(sandboxrelay.StreamHook, sandboxrelay.MaxMessage)
	if err != nil {
		st.Refused.Add(1)
		return fmt.Errorf("sandboxrelayd.ServeConn: %w", err)
	}
	req, err := sandboxrelay.DecodeHookRequest(msg, d.Rules)
	if err != nil {
		st.Refused.Add(1)
		return fmt.Errorf("sandboxrelayd.ServeConn: %w", err)
	}
	// A refusal report never takes one of the run's hook slots: it has its
	// own one-slot budget (serveEgressRefusal), so a box provoking refusals
	// can neither push a hook request into busy nor lower the run's capture.
	if req.Kind == sandboxrelay.KindEgressRefusal {
		return d.serveEgressRefusal(s, rec, st, req)
	}
	select {
	case st.sem <- struct{}{}:
	default:
		st.Refused.Add(1)
		return ErrBusy
	}
	defer func() { <-st.sem }()
	if req.Kind == sandboxrelay.KindRunHealth {
		return d.serveHealthReport(s, rec, st, req)
	}
	// A box that works in a fixed path of its own names it; the run's
	// map rewrites it to the host's directory before the binding and the
	// confined reads see it (pathmap.go).
	req.Stdin = mapPayloadPaths(req.Stdin, rec.PathMap)
	// The request header's working directory is a box path too (G4-R7):
	// mapped the same way, so a hook run from a subdirectory of the box's
	// workspace runs in that subdirectory of the run's directory. A cwd
	// under no prefix is left as written (the executor then falls back to
	// the run's workspace, as for any cwd outside the roots).
	if mapped, ok := MapBoxPath(rec.PathMap, req.Cwd); ok {
		req.Cwd = mapped
	}
	facts := readRunPayloadFacts(req.Stdin, d.Rules.Syntax(), rec.HomeIsThisMachines())
	refusal, row := d.bind(ctx, st, rec, req, facts)
	d.observeDrift(st, rec, req, facts, refusal == "")
	if refusal != "" {
		// The class, the payload key and the run, never a value or the body
		// (lane FX6, F-P7-5: a path refusal named no key anywhere).
		key := ""
		if refusal == sandboxrelay.RefusedPath {
			key = " key=" + pathRefusalKey(bindInput{run: rec, facts: facts})
		}
		d.log(rec.RunID, "refused a %s request: %s (%s)%s", req.Kind, refusal, row, key)
		st.Bound.Add(1)
		cause := CauseRefused
		if refusal == sandboxrelay.RefusedRate {
			st.RateLimited.Add(1)
			cause = CauseRateLimited
		}
		d.lower(rec, st, 0, cause)
		out, err := sandboxrelay.EncodeHookResponse(d.refusalAnswer(req, refusal))
		if err != nil {
			return fmt.Errorf("sandboxrelayd.ServeConn: %w", err)
		}
		if err := s.Send(sandboxrelay.StreamHook, out); err != nil {
			return fmt.Errorf("sandboxrelayd.ServeConn: %w", err)
		}
		closeAnswered(s)
		return nil
	}
	if req.Replay {
		st.Replayed.Add(1)
		d.lower(rec, st, 0, CauseReplayed)
	}
	timeout := d.ExecTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ectx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stopBeat := heartbeat(s, d.Heartbeat)
	resp, err := d.Exec(ectx, rec, req)
	// The heartbeats this side missed are counted where they are waited
	// for: the helper reads the same gaps on the link and reports them
	// (counting them here too would count each one twice).
	stopBeat()
	if err != nil {
		st.Refused.Add(1)
		return fmt.Errorf("sandboxrelayd.ServeConn: exec: %w", err)
	}
	resp.V = req.V
	out, err := sandboxrelay.EncodeHookResponse(resp)
	if err != nil {
		return fmt.Errorf("sandboxrelayd.ServeConn: %w", err)
	}
	if err := s.Send(sandboxrelay.StreamHook, out); err != nil {
		return fmt.Errorf("sandboxrelayd.ServeConn: %w", err)
	}
	st.Served.Add(1)
	closeAnswered(s)
	return nil
}

// closeAnswered closes the hook stream after its answer was sent, on the
// daemon's link and on the host helper's box side. The peer hangs up as
// soon as it has read the answer, so the close frame can meet a closed
// link; that loses no event (the answer was the last frame the request
// needed), so it is neither logged (it is the normal case under load) nor
// counted as a dropped event. Before lane LEFT-SBX it lowered the run
// "dropped" whenever the peer hung up first, which made the drift tests
// and TestSlowHealthWriteHoldsNoAnswerOrHeartbeat flake under -race.
func closeAnswered(s *sandboxrelay.Session) {
	_ = s.CloseStream(sandboxrelay.StreamHook)
}

// serveHealthReport applies the host helper's health report (lowering
// only) and answers it.
func (d *Daemon) serveHealthReport(s *sandboxrelay.Session, rec RunRecord, st *RunState, req sandboxrelay.HookRequest) error {
	rep, err := DecodeHealthReport(req.Stdin)
	if err != nil {
		st.Refused.Add(1)
		return fmt.Errorf("sandboxrelayd.ServeConn: %w", err)
	}
	var causes []DegradedCause
	if rep.HooksDrifted {
		causes = append(causes, CauseHooksDrifted)
	}
	if rep.Dropped > 0 {
		causes = append(causes, CauseDropped)
	}
	d.lower(rec, st, rep.MissedHeartbeats, causes...)
	out, err := sandboxrelay.EncodeHookResponse(sandboxrelay.HookResponse{V: req.V})
	if err != nil {
		return fmt.Errorf("sandboxrelayd.ServeConn: %w", err)
	}
	if err := s.Send(sandboxrelay.StreamHook, out); err != nil {
		return fmt.Errorf("sandboxrelayd.ServeConn: %w", err)
	}
	return s.CloseStream(sandboxrelay.StreamHook)
}

// lower records what lowered rec's capture and, when that changed its
// health, has the run's delivery goroutine hand the new health to OnHealth.
// It never waits for OnHealth (a database write): the caller answers the
// request and starts its heartbeats at once.
func (d *Daemon) lower(rec RunRecord, st *RunState, missed int, causes ...DegradedCause) {
	if _, changed := st.health.lower(missed, causes...); !changed || d.OnHealth == nil {
		return
	}
	if st.health.markDirty(rec) {
		d.inflight.start()
		go d.deliverHealth(st)
	}
}

// deliverHealth is a run's delivery goroutine: it hands OnHealth the latest
// health until nothing new is waiting, then runs the run-end hook when the
// run ended meanwhile.
func (d *Daemon) deliverHealth(st *RunState) {
	defer d.inflight.done()
	for {
		rec, h, onEnd, ok := st.health.takeDirty()
		if !ok {
			if onEnd != nil {
				onEnd(rec)
			}
			return
		}
		d.OnHealth(rec, h)
	}
}

// FlushHealth waits until every health change made so far reached OnHealth
// (and every run-end hook those deliveries owed ran). For tests and an
// orderly shutdown; a caller must not lower a run while it waits.
func (d *Daemon) FlushHealth() { d.inflight.wait() }

// refusalAnswer is the answer to a refused request in the request's own
// version: a Refused answer for a box that reads one, else the exit code
// and output the box would have produced (LegacyRefusal).
func (d *Daemon) refusalAnswer(req sandboxrelay.HookRequest, why sandboxrelay.Refusal) sandboxrelay.HookResponse {
	if req.V != sandboxrelay.LegacyHookVersion {
		return sandboxrelay.HookResponse{V: req.V, Refused: why}
	}
	var resp sandboxrelay.HookResponse
	if d.LegacyRefusal != nil {
		resp = d.LegacyRefusal(req, why)
	} else {
		resp = sandboxrelay.HookResponse{Exit: 2, Stderr: []byte("observer: the sandbox relay refused this event (" + string(why) + ")\n")}
	}
	resp.V, resp.Refused = sandboxrelay.LegacyHookVersion, ""
	return resp
}

// heartbeat pings s while a request is worked on (interval zero: the
// default; negative: off) and returns the stop.
func heartbeat(s *sandboxrelay.Session, interval time.Duration) func() {
	if interval < 0 {
		return func() {}
	}
	return s.Heartbeat(interval)
}

// clientConn lowers a server-side limit set to a waiting client's: silence
// for three heartbeats of a server that heartbeats every interval means it
// is gone.
func clientConn(l sandboxrelay.ConnLimits, interval time.Duration) sandboxrelay.ConnLimits {
	if interval < 0 {
		return l
	}
	if interval == 0 {
		interval = sandboxrelay.HeartbeatInterval
	}
	if idle := 3 * interval; idle < l.IdleTimeout {
		l.IdleTimeout = idle
	}
	return l
}

// Serve accepts link connections on ln until ctx ends.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	maxConns := d.MaxConns
	if maxConns <= 0 {
		maxConns = 64
	}
	if every := d.SweepInterval; every >= 0 {
		if every == 0 {
			every = DefaultSweepInterval
		}
		go func() {
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					d.Sweep()
				}
			}
		}()
	}
	if d.Drift != nil && d.Drift.Interval >= 0 {
		every := d.Drift.Interval
		if every == 0 {
			every = DefaultDriftInterval
		}
		go func() {
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-t.C:
					d.CheckDrift(now)
				}
			}
		}()
	}
	return serve(ctx, ln, maxConns, d.Peer, func(why string) { d.log("", "%s", why) }, func(c net.Conn) { _ = d.ServeConn(ctx, c) })
}

// serve is the shared accept loop: a connection over the cap, or one whose
// peer the check refuses, is closed at once, and drop (nil: nothing) says
// why.
func serve(ctx context.Context, ln net.Listener, maxConns int, peer PeerCheck, drop func(why string), handle func(net.Conn)) error {
	dropped := func(why string) {
		if drop != nil {
			drop(why)
		}
	}
	slots := make(chan struct{}, maxConns)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if peer != nil {
			if err := peer(c); err != nil {
				_ = c.Close()
				dropped("closed a connection before its handshake: the peer check refused it: " + err.Error())
				continue
			}
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = c.Close()
			dropped(fmt.Sprintf("closed a connection before its handshake: %d connections are already open", maxConns))
			continue
		}
		go func() {
			defer func() { <-slots }()
			handle(c)
		}()
	}
}

// Forwarder is the host helper's side of the box channel: it verifies every
// frame the box sends under the run's box key, validates the request, and
// forwards it on the link to the daemon under the run's link key. It also
// watches what only the host side can see and reports it to the daemon as
// the run's health: the box's hook registration read from the host side of
// its mount (sandbox plan section 5.2, continuous verification), the
// heartbeats the daemon or this helper missed, and the events lost between
// the box and the daemon.
type Forwarder struct {
	Run RunRecord
	// DialDaemon reaches the daemon's link endpoint.
	DialDaemon func(ctx context.Context) (net.Conn, error)
	Rules      sandboxrelay.RequestRules
	Conn       sandboxrelay.ConnLimits
	Peer       PeerCheck
	// MaxConns caps concurrent box connections (zero: 8).
	MaxConns int
	// Heartbeat is how often the helper pings the box while the daemon
	// works, and the interval the daemon pings the helper at (zero:
	// sandboxrelay.HeartbeatInterval; negative: off).
	Heartbeat time.Duration
	// HookProbe reads the run's tool hook registration from the host side
	// (nil: no verification). The first read, when Serve starts and before
	// the box runs, is the launch's registration; later reads that lost
	// any of it mark the run hooks_drifted (HookDrift).
	HookProbe func() (HookRegistration, error)
	// HookInterval is how often the registration is read again (zero:
	// DefaultHookInterval; negative: only before each spooled replay).
	HookInterval time.Duration
	// DaemonAddr names the daemon's relay endpoint in a hop answer (the
	// helper's address of its upstream; "" names none).
	DaemonAddr string

	pending pendingHealth
	// served counts box connections ServeConn finished (their health, if
	// any, already handed to pending), so a test can wait for them.
	served   atomic.Int64
	hookMu   sync.Mutex
	hookBase *HookRegistration
	drifted  bool
}

// DefaultHookInterval is how often the helper re-reads the box's hook
// registration.
const DefaultHookInterval = 15 * time.Second

func (f *Forwarder) conn() sandboxrelay.ConnLimits {
	if f.Conn == (sandboxrelay.ConnLimits{}) {
		return sandboxrelay.DefaultConnLimits
	}
	return f.Conn
}

// beat is the daemon's heartbeat interval as the helper expects it (zero:
// none).
func (f *Forwarder) beat() time.Duration {
	switch {
	case f.Heartbeat < 0:
		return 0
	case f.Heartbeat == 0:
		return sandboxrelay.HeartbeatInterval
	}
	return f.Heartbeat
}

// ServeConn relays one box connection. The request is forwarded to the
// daemon cut-through (sandboxrelay.Session.Forward): the daemon is reached
// only once the request's header passed the schema, each frame goes on as
// soon as it verified under the box key, and the last one only after the
// whole request passed DecodeHookRequest. A box may not send the helper's
// own run_health kind.
func (f *Forwarder) ServeConn(ctx context.Context, box net.Conn) error {
	defer f.served.Add(1)
	defer func() { _ = box.Close() }()
	s, err := sandboxrelay.Accept(box, params(sandboxrelay.PurposeBox, f.conn()), func(id string) ([]byte, error) {
		if id != f.Run.RunID {
			return nil, errors.New("the box channel speaks only for its own run")
		}
		return f.Run.BoxSecret, nil
	})
	if err != nil {
		return fmt.Errorf("sandboxrelayd.Forwarder: %w", err)
	}
	defer s.Release()
	var link *sandboxrelay.Session
	err = f.relay(ctx, s, &link)
	var hop *sandboxrelay.HopError
	if errors.As(err, &hop) {
		// The box was answered with the hop: let it read the answer before
		// the connection closes (a close with unread request bytes may reset
		// the connection and lose the answer).
		drainBox(box)
	}
	missed := s.MissedBeats()
	if link != nil {
		missed += link.MissedBeats()
		link.Release()
	}
	dropped := 0
	if err != nil {
		dropped = 1
	}
	if f.pending.add(false, missed, dropped) {
		go f.flushHealth(ctx)
	}
	return err
}

// relay forwards one request and its answer; *link is the daemon session
// once opened.
func (f *Forwarder) relay(ctx context.Context, s *sandboxrelay.Session, link **sandboxrelay.Session) error {
	boxRules := f.Rules
	boxRules.Kinds = sandboxrelay.BoxKind
	var dc net.Conn
	defer func() {
		if dc != nil {
			_ = dc.Close()
		}
	}()
	linkParams := params(sandboxrelay.PurposeLink, clientConn(f.conn(), f.Heartbeat))
	linkParams.ExpectBeat = f.beat()
	refuse := func(err error) error {
		return &sandboxrelay.HopError{Hop: sandboxrelay.HopHelperRequest, Detail: err.Error()}
	}
	l, _, err := s.Forward(sandboxrelay.StreamHook, sandboxrelay.MaxMessage, sandboxrelay.ForwardChecks{
		Head: func(sofar []byte) (bool, error) {
			done, err := sandboxrelay.CheckHookRequestHead(sofar, boxRules)
			if err != nil {
				return false, refuse(err)
			}
			if done && sandboxrelay.RequestHeadReplay(sofar) {
				// Verify the registration before a spooled event is
				// honoured (sandbox plan section 5.2).
				f.CheckHooks(ctx)
			}
			return done, nil
		},
		Whole: func(msg []byte) error {
			if _, err := sandboxrelay.DecodeHookRequest(msg, boxRules); err != nil {
				return refuse(err)
			}
			return nil
		},
	}, func() (*sandboxrelay.Session, error) {
		c, err := f.DialDaemon(ctx)
		if err != nil {
			return nil, &sandboxrelay.HopError{Hop: sandboxrelay.HopDaemonConnect, Addr: f.DaemonAddr, Detail: err.Error()}
		}
		dc = c
		ls, err := sandboxrelay.Dial(bounded(ctx, c), linkParams, f.Run.RunID, f.Run.LinkSecret)
		if err != nil {
			return nil, &sandboxrelay.HopError{Hop: sandboxrelay.HopDaemonLink, Addr: f.DaemonAddr, Detail: err.Error()}
		}
		return ls, nil
	})
	*link = l
	if err != nil {
		return f.answerHop(s, err)
	}
	stopBeat := heartbeat(s, f.Heartbeat)
	resp, err := l.Recv(sandboxrelay.StreamHook, sandboxrelay.MaxMessage)
	stopBeat()
	if err != nil {
		return f.answerHop(s, &sandboxrelay.HopError{Hop: sandboxrelay.HopDaemonAnswer, Addr: f.DaemonAddr, Detail: err.Error()})
	}
	if _, err := sandboxrelay.DecodeHookResponse(resp); err != nil {
		return f.answerHop(s, &sandboxrelay.HopError{Hop: sandboxrelay.HopDaemonAnswer, Addr: f.DaemonAddr, Detail: "its answer is refused: " + err.Error()})
	}
	if err := s.Send(sandboxrelay.StreamHook, resp); err != nil {
		return err
	}
	// The box hangs up once it has read the answer (closeAnswered).
	closeAnswered(s)
	return nil
}

// Serve accepts box connections until ctx ends. With a HookProbe it first
// reads the launch's hook registration, then re-reads it every
// HookInterval.
func (f *Forwarder) Serve(ctx context.Context, ln net.Listener) error {
	n := f.MaxConns
	if n <= 0 {
		n = 8
	}
	if f.HookProbe != nil {
		f.ReadLaunchHooks()
		go f.WatchHooks(ctx)
	}
	return serve(ctx, ln, n, f.Peer, nil, func(c net.Conn) { _ = f.ServeConn(ctx, c) })
}

// WatchHooks re-reads the run's hook registration every HookInterval
// (zero: DefaultHookInterval) until ctx ends, reporting the run
// hooks_drifted the first time a read lost what the launch had
// (CheckHooks). It returns at once with no HookProbe or a negative
// interval. Serve runs it; a helper that serves box connections through
// ServeConn on a port of its own (the Windows MXC helper) must run it too,
// after ReadLaunchHooks, or no drift is ever seen mid-run (Windows 11 Pro
// run 3 RERUN2, D3).
func (f *Forwarder) WatchHooks(ctx context.Context) {
	every := f.HookInterval
	if f.HookProbe == nil || every < 0 {
		return
	}
	if every == 0 {
		every = DefaultHookInterval
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.CheckHooks(ctx)
		}
	}
}

// answerHop answers the box with the hop its request failed on, when err
// names one (the helper refused the request, or its upstream to the daemon
// failed), so the box names the hop instead of reading an EOF (Windows 11 Pro
// run 3, 2026-10-22). Any other error is the box's own stream failing, and
// nothing is sent. It returns err, wrapped.
func (f *Forwarder) answerHop(s *sandboxrelay.Session, err error) error {
	var hop *sandboxrelay.HopError
	if errors.As(err, &hop) && hop.Hop.OnWire() {
		msg, eerr := sandboxrelay.EncodeHookResponse(sandboxrelay.HookResponse{
			Hop: hop.Hop, HopAddr: sandboxrelay.HopText(hop.Addr), HopDetail: sandboxrelay.HopText(hop.Detail),
		})
		if eerr == nil && s.Send(sandboxrelay.StreamHook, msg) == nil {
			_ = s.CloseStream(sandboxrelay.StreamHook)
		}
	}
	return fmt.Errorf("sandboxrelayd.Forwarder: %w", err)
}

// boxDrain bounds how long the helper reads what is left of a box's request
// after answering it with a hop.
const boxDrain = 2 * time.Second

// drainBox reads, and drops, what the box still sends until it closes or
// boxDrain passes.
func drainBox(box net.Conn) {
	_ = box.SetReadDeadline(time.Now().Add(boxDrain))
	_, _ = io.Copy(io.Discard, io.LimitReader(box, sandboxrelay.MaxMessage))
}

// ReadLaunchHooks takes the launch's hook registration, the baseline later
// reads are compared with, unless it was already taken. The helper calls it
// before it releases the box, so nothing the box does can be the baseline;
// Serve calls it too, for a caller that did not.
func (f *Forwarder) ReadLaunchHooks() {
	if f.HookProbe == nil {
		return
	}
	f.hookMu.Lock()
	defer f.hookMu.Unlock()
	if f.hookBase != nil {
		return
	}
	if base, err := f.HookProbe(); err == nil {
		f.hookBase = &base
	}
}

// CheckHooks re-reads the hook registration and, the first time it lost
// anything the launch had, reports the run hooks_drifted to the daemon
// before it returns. It reports whether the run has drifted.
func (f *Forwarder) CheckHooks(ctx context.Context) bool {
	f.hookMu.Lock()
	base, already := f.hookBase, f.drifted
	f.hookMu.Unlock()
	if already {
		return true
	}
	if base == nil || f.HookProbe == nil {
		return false
	}
	now, err := f.HookProbe()
	if err != nil {
		return false
	}
	if drifted, _ := HookDrift(*base, now); !drifted {
		return false
	}
	f.hookMu.Lock()
	f.drifted = true
	f.hookMu.Unlock()
	f.pending.add(true, 0, 0)
	f.flushHealth(ctx)
	return true
}

// HooksDrifted reports whether the helper saw the registration drift.
func (f *Forwarder) HooksDrifted() bool {
	f.hookMu.Lock()
	defer f.hookMu.Unlock()
	return f.drifted
}

// healthTimeout bounds one health report's round trip.
const healthTimeout = 5 * time.Second

// flushHealth sends what is waiting to the daemon as a run_health request
// (one sender at a time; a failed send is kept for the next).
func (f *Forwarder) flushHealth(ctx context.Context) {
	for {
		rep, ok := f.pending.take()
		if !ok {
			return
		}
		err := f.sendHealth(ctx, rep)
		f.pending.done(rep, err)
		if err != nil {
			return
		}
	}
}

func (f *Forwarder) sendHealth(ctx context.Context, rep HealthReport) error {
	body, err := EncodeHealthReport(rep)
	if err != nil {
		return err
	}
	tool := f.Run.Tool
	if tool == "" {
		tool = "relay"
	}
	msg, err := sandboxrelay.EncodeHookRequest(sandboxrelay.HookRequest{Kind: sandboxrelay.KindRunHealth, Args: []string{tool}, Stdin: body})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	_, err = LinkRoundTrip(ctx, f.DialDaemon, f.Run, msg, f.conn())
	return err
}

// LinkRoundTrip sends one request message to the daemon on the link and
// returns the validated response message.
func LinkRoundTrip(ctx context.Context, dial func(ctx context.Context) (net.Conn, error), run RunRecord, msg []byte, c sandboxrelay.ConnLimits) ([]byte, error) {
	dc, err := dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("reach the daemon: %w", err)
	}
	defer func() { _ = dc.Close() }()
	ls, err := sandboxrelay.Dial(bounded(ctx, dc), params(sandboxrelay.PurposeLink, c), run.RunID, run.LinkSecret)
	if err != nil {
		return nil, err
	}
	defer ls.Release()
	if err := ls.Send(sandboxrelay.StreamHook, msg); err != nil {
		return nil, err
	}
	resp, err := ls.Recv(sandboxrelay.StreamHook, sandboxrelay.MaxMessage)
	if err != nil {
		return nil, err
	}
	if _, err := sandboxrelay.DecodeHookResponse(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// BoxRoundTrip is the box-side client: it dials the run's relay socket in
// sockDir, speaks for rec's run with its box secret, and returns the host's
// answer. ctx bounds the whole round trip.
func BoxRoundTrip(ctx context.Context, sockDir string, rec BoxRecord, req sandboxrelay.HookRequest, c sandboxrelay.ConnLimits) (sandboxrelay.HookResponse, error) {
	msg, err := sandboxrelay.EncodeHookRequest(req)
	if err != nil {
		return sandboxrelay.HookResponse{}, err
	}
	var d net.Dialer
	addr := filepath.Join(sockDir, rec.Socket)
	conn, err := d.DialContext(ctx, "unix", addr)
	if err != nil {
		return sandboxrelay.HookResponse{}, &sandboxrelay.HopError{Hop: sandboxrelay.HopBoxConnect, Addr: addr, Detail: err.Error()}
	}
	return boxRoundTripAt(ctx, conn, addr, rec, msg, c)
}

// BoxRoundTripConn is BoxRoundTrip over a connection the caller already
// opened to the run's relay (the MXC row's loopback port, after its
// upgrade; lane SBX-P6), with msg an encoded request. It closes conn.
func BoxRoundTripConn(ctx context.Context, conn net.Conn, rec BoxRecord, msg []byte, c sandboxrelay.ConnLimits) (sandboxrelay.HookResponse, error) {
	addr := ""
	if a := conn.RemoteAddr(); a != nil {
		addr = a.String()
	}
	return boxRoundTripAt(ctx, conn, addr, rec, msg, c)
}

// boxRoundTripAt is the round trip over conn to the helper at addr. A
// failure names its hop (*sandboxrelay.HopError): the helper closing the
// stream without an answer, or the hop the helper answered with.
func boxRoundTripAt(ctx context.Context, conn net.Conn, addr string, rec BoxRecord, msg []byte, c sandboxrelay.ConnLimits) (sandboxrelay.HookResponse, error) {
	defer func() { _ = conn.Close() }()
	closedHop := func(err error) *sandboxrelay.HopError {
		return &sandboxrelay.HopError{Hop: sandboxrelay.HopBoxClosed, Addr: addr, Detail: err.Error()}
	}
	closed := func(err error) error { return closedHop(err) }
	s, err := sandboxrelay.Dial(bounded(ctx, conn), params(sandboxrelay.PurposeBox, c), rec.RunID, rec.BoxSecret)
	if err != nil {
		// The stream closed during the handshake: the request never left
		// the box, so a caller that redials may try again (lane SBX-UPD,
		// finding H1).
		return sandboxrelay.HookResponse{}, nothingSentError{closedHop(err)}
	}
	defer s.Release()
	if err := s.Send(sandboxrelay.StreamHook, msg); err != nil {
		return sandboxrelay.HookResponse{}, closed(err)
	}
	raw, err := s.Recv(sandboxrelay.StreamHook, sandboxrelay.MaxMessage)
	if err != nil {
		return sandboxrelay.HookResponse{}, closed(err)
	}
	resp, err := sandboxrelay.DecodeHookResponse(raw)
	if err != nil {
		return sandboxrelay.HookResponse{}, closed(fmt.Errorf("the helper's answer is refused: %w", err))
	}
	if herr := resp.HopErr(); herr != nil {
		var hop *sandboxrelay.HopError
		if errors.As(herr, &hop) && hop.Addr == "" {
			// The helper names no address of its own: it is the one at addr.
			hop.Addr = addr
		}
		return resp, herr
	}
	return resp, nil
}

// deadlineConn caps every deadline the protocol sets at the caller's
// context deadline, so one absolute bound covers the whole round trip.
type deadlineConn struct {
	net.Conn
	dl time.Time
}

func (c deadlineConn) clamp(t time.Time) time.Time {
	if t.IsZero() || c.dl.Before(t) {
		return c.dl
	}
	return t
}

func (c deadlineConn) SetReadDeadline(t time.Time) error { return c.Conn.SetReadDeadline(c.clamp(t)) }

func (c deadlineConn) SetWriteDeadline(t time.Time) error { return c.Conn.SetWriteDeadline(c.clamp(t)) }

// bounded wraps c with ctx's deadline, when it has one.
func bounded(ctx context.Context, c net.Conn) sandboxrelay.Conn {
	if dl, ok := ctx.Deadline(); ok {
		return deadlineConn{Conn: c, dl: dl}
	}
	return c
}

// ErrNothingSent marks a relay failure that happened before the request
// left the box (the helper closed the stream during the handshake), so
// retrying it never repeats a request. errors.As still finds the hop.
var ErrNothingSent = errors.New("sandboxrelayd: the request was not sent")

// nothingSentError is a hop failure before anything was sent.
type nothingSentError struct{ *sandboxrelay.HopError }

// Unwrap exposes both the hop and ErrNothingSent.
func (e nothingSentError) Unwrap() []error { return []error{e.HopError, ErrNothingSent} }
