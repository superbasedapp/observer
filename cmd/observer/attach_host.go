//go:build !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// attach_host.go adapts the terminal application service (internal/termsvc) +
// the PTY manager (internal/termsession) to the attach-socket Host interface
// (internal/attachsock). It is the ONE cmd-side seam that lets an
// `observer <tool> --attach` client have the daemon spawn a PTY through the
// SAME termsession.Manager the dashboard drives (session-attach design §2.1) —
// so the operator's terminal becomes viewer #1 and the dashboard can attach as
// viewer #2 over the existing /ws/launch/<handle> fan-out with zero new
// fan-out code.
//
// The Host does not own the PTY lifecycle or the run identity: termsvc mints
// the run and spawns through the shared manager; the manager's OnExit closure
// (cmd/observer/attach_standalone.go, wired in buildTerminalStack) is the primary,
// single owner that records a run's exit via svc.EndRunByHandle. This adapter
// reuses THAT SAME method on the attach path's own honest close (see
// attachSession.Detach); the call is idempotent (EndRunByHandle dedupes by
// handle), so it never double-records regardless of which fires first.

// attachLauncher is the launch seam the attach Host depends on. It is satisfied
// by *termsvc.Service; a small interface keeps the Host unit-testable with a
// stub (no store / no real PTY).
type attachLauncher interface {
	// LaunchAttachable mints a KindAttach run and spawns a daemon-owned PTY.
	LaunchAttachable(ctx context.Context, req termsvc.AttachRequest) (termsvc.LaunchResult, error)
	// EndRunByHandle records a run's exit keyed by PTY handle (idempotent).
	EndRunByHandle(ctx context.Context, handle string, exitCode int)
}

// markAttachEnding records child_exit as the end reason of an attach run
// the host tears down because its wiring failed, so the -1 it then records
// is not read as a stop from outside (Windows 11 Pro run 4, N3). A launcher
// without the seam (a test stub) records nothing more.
func markAttachEnding(l attachLauncher, handle string) {
	if m, ok := l.(endingMarker); ok {
		m.MarkEnding(handle, termrun.EndChildExit)
	}
}

// endingMarker is the end-reason seam *termsvc.Service offers.
type endingMarker interface {
	MarkEnding(handle, reason string) bool
}

// attachPTYManager is the PTY-manager seam the attach Host depends on. It is
// satisfied by *termsession.Manager. The concrete Subscribe/AcquireWriterLocal
// return types (*Subscription / *WriterLease) are used directly because the
// Host is thin glue over them; the testable decision logic lives in
// attachSession, which takes plain function/reader fields.
type attachPTYManager interface {
	Subscribe(handle string) (*termsession.Subscription, error)
	AcquireWriterLocal(handle string) (*termsession.WriterLease, error)
	Unsubscribe(sub *termsession.Subscription)
	ExitStatus(handle string) (exited bool, code int, ok bool)
	// Close terminates a session's PTY (kill + remove), the SAME idempotent
	// funnel the dashboard DELETE admin path routes through
	// (termsession.Manager.Close → terminate). Used to tear down a
	// just-spawned child when post-spawn wiring fails, so no run record ever
	// claims an exit while the child still runs (B3-3).
	Close(handle string)
}

// attachHost implements attachsock.Host over a terminal service + PTY manager.
type attachHost struct {
	svc attachLauncher
	mgr attachPTYManager
	// audit, when non-nil, records a metadata-only spawn-time audit row (F4,
	// session-attach design §3.5) once an attach PTY is fully wired, so an
	// attach spawn that no client ever reaches over the websocket still leaves
	// exactly one terminal_attach row. Metadata only — run id, tool, handle.
	audit func(runID, tool, handle string)
	// hub, when non-nil, sources per-run correlated-session announcements (from
	// the trusted OOB/correlation feed) that the server relays to an
	// AutoResumeCapable client as frameCorrelated frames, AND maintains the
	// daemon-wide live-session view the double-spawn guard consults (resilient-
	// attach Layer 1). Nil disables both (no auto-resume plumbing).
	hub *attachHub
	// resumable, when non-nil, validates a daemon-death AUTO-resume target
	// against the sessions the RESUMED daemon rediscovered as orphans (attach
	// runs with no recorded end + a correlated session id). Nil accepts any
	// auto-resume target (validation disabled).
	resumable func(sessionID string) bool
	// resumeGuard single-flights the resume liveness-check + spawn per session
	// id, mirroring the dashboard resume route's acquireResumeLock (R2-3) so two
	// concurrent resumes of the same session can't both pass the check and both
	// spawn.
	resumeGuard attachResumeGuard
	// attachDir is the attach socket's directory (owner-only 0700). When set, a
	// resume additionally takes a DURABLE cross-process flock claim there so a
	// bare `observer <tool> --resume <id>` run during daemon downtime and the
	// daemon's own attach-resume can't both drive the same session (review
	// finding H3). Empty (tests / no DB) disables the flock layer; the in-memory
	// hub.sessionLive guard still applies.
	attachDir string
	// supersedeResumed, when non-nil, is called after a successful AUTO-resume
	// spawn to stamp the old rediscovered orphan rows end_reason='resumed' so they
	// can never be re-offered across a later restart (review finding H2). It is
	// keyed by the PREDECESSOR run ids (resolved via resumePredecessors) — ALL of
	// the session's startup-eligible orphans, NOT the session — so the fresh
	// replacement run, which can correlate to the same session via OOB before this
	// stamp runs, is never superseded (finding: wrong-run supersede), while older
	// same-session orphans are all retired (round-4 multi-orphan finding). Nil
	// disables superseding (tests / no DB).
	supersedeResumed func(runIDs []string)
	// resumePredecessors, when non-nil, resolves an auto-resume target's session
	// id to ALL of its rediscovered startup-eligible PREDECESSOR run ids, newest
	// first (ok=false / empty when the session is not a rediscovered orphan). A
	// session can carry MORE THAN ONE eligible orphan — historical duplicates or
	// prior stamp failures — and a successful resume must supersede EVERY one, or
	// the older rows stay offerable on every future restart (round-4 multi-orphan
	// finding). It is the run-id source supersedeResumed stamps by; wired
	// alongside supersedeResumed via withDurableResume. Nil disables superseding.
	resumePredecessors func(sessionID string) (runIDs []string, ok bool)
	// resumeAuthority, when non-nil, is the DURABLE store-backed double-spawn
	// authority: it reports whether the store already holds a LIVE run correlated
	// to the resume target session. Unlike the hub's in-memory live view — fed by
	// reserve() (attach-host-spawned runs only) + the LOSSY correlation feed — it
	// catches EVERY persisted live correlation, including a dashboard resume (or
	// any dashboard-spawned run that correlates to an AI session) that never rides
	// the attach hub and never takes the resume flock (round-5 finding 1). The
	// conflict check is hub-fast-path OR this authority; the in-memory map covers
	// only the sub-second window before an attach-host spawn's correlation is
	// persisted (via reserve). Nil disables it (tests / no DB) — the in-memory
	// guard then stands alone.
	//
	// It is passed the target session's rediscovered startup PREDECESSOR run ids
	// to EXCLUDE (review finding 1: self-blocking authority): those crash-orphan
	// rows are correlated + NULL-ended but are NOT live drivers — they are the
	// very predecessors rediscovery offered for auto-resume — so counting them as
	// live would refuse every crash-orphan recovery. A genuinely distinct live run
	// (a dashboard run, not in the predecessor set) is still caught.
	resumeAuthority func(sessionID string, excludeRunIDs []string) bool
	// reclaimOnInput enables native-terminal writer reclaim (Feature 1): when
	// true, a revoked attach session re-acquires the local writer through the
	// normal AcquireWriterLocal funnel on a non-ESC keystroke. Resolved from
	// [terminal.attach].reclaim_on_input at the boundary (never a tool-name
	// branch) and threaded in via withReclaim; false leaves the attachSession's
	// reacquire hook nil, so the server sees no working Reclaimer and keeps the
	// fence-and-notify behavior.
	reclaimOnInput bool
}

// newAttachHost builds an attach-socket Host over a terminal service and PTY
// manager. Both must be non-nil. audit may be nil (auditing disabled). The
// resilient-attach Layer-1 plumbing (correlation hub + orphan validator) is
// wired separately via withResume, so this constructor's signature stays stable
// for the surfaces (and tests) that don't need it.
func newAttachHost(svc attachLauncher, mgr attachPTYManager, audit func(runID, tool, handle string)) *attachHost {
	return &attachHost{svc: svc, mgr: mgr, audit: audit}
}

// withResume wires the resilient-attach Layer-1 plumbing: the correlation hub
// (per-run correlated-session delivery + the daemon-wide live view the double-
// spawn guard reads) and the daemon-death orphan validator. Both may be nil to
// leave auto-resume disabled. Returns the host for chaining. Additive so the
// 3-arg constructor stays unchanged for callers that don't opt in.
func (h *attachHost) withResume(hub *attachHub, resumable func(sessionID string) bool) *attachHost {
	h.hub = hub
	h.resumable = resumable
	return h
}

// withDurableResume wires the H3 cross-process resume flock (attachDir), the H2
// orphan-supersede callback (keyed by predecessor run id), and the predecessor
// resolver that supplies that run id. All may be zero/nil to leave the durable
// layer off (tests / no DB) — the in-memory hub guard still applies. Additive so
// the existing constructors stay unchanged. Returns the host for chaining.
func (h *attachHost) withDurableResume(attachDir string, supersede func(runIDs []string), predecessors func(sessionID string) ([]string, bool)) *attachHost {
	h.attachDir = attachDir
	h.supersedeResumed = supersede
	h.resumePredecessors = predecessors
	return h
}

// withResumeAuthority wires the DURABLE store-backed double-spawn authority
// (round-5 finding 1): a resume is refused whenever the store already holds a
// live run correlated to the target session — even one the in-memory attach hub
// never observed (a dashboard resume). Additive so the existing constructors and
// tests stay unchanged; nil leaves the conflict check on the in-memory hub guard
// alone. Returns the host for chaining.
func (h *attachHost) withResumeAuthority(authority func(sessionID string, excludeRunIDs []string) bool) *attachHost {
	h.resumeAuthority = authority
	return h
}

// withReclaim enables native-terminal writer reclaim (Feature 1) when on is
// true. It maps the [terminal.attach].reclaim_on_input capability onto the host
// at the boundary (CLAUDE.md #3 — no tool-name branch downstream): with it off
// the attachSession is built with a nil reacquire hook, so the server's
// Reclaimer.ReclaimWriter always reports reclaim unavailable and today's
// fence-and-notify behavior is byte-identical. Additive so existing constructors
// stay unchanged. Returns the host for chaining.
func (h *attachHost) withReclaim(on bool) *attachHost {
	h.reclaimOnInput = on
	return h
}

// resumeConflict reports whether a resume of sessionID must be refused because a
// run is already driving it. It consults the hub's in-memory live view (the FAST
// PATH — covers the sub-second window before an attach-host spawn persists its
// correlation, via reserve) OR the durable store authority (which catches EVERY
// persisted live correlation, including dashboard resumes the hub never sees —
// round-5 finding 1). Either positive is a conflict.
//
// The store authority treats every NULL-ended correlated row as a live driver,
// so it would otherwise match the very predecessor orphan rediscovery just
// offered and self-block the auto-resume (review finding 1). We therefore pass it
// this session's rediscovered startup PREDECESSOR run ids to EXCLUDE — the crash
// orphans SQL can't tell apart from a live run — so a genuinely distinct live run
// (a dashboard run, not in this set) still conflicts while the predecessor never
// self-blocks.
func (h *attachHost) resumeConflict(sessionID string) bool {
	if h.hub != nil && h.hub.sessionLive(sessionID) {
		return true
	}
	if h.resumeAuthority != nil {
		var exclude []string
		if h.resumePredecessors != nil {
			if ids, ok := h.resumePredecessors(sessionID); ok {
				exclude = ids
			}
		}
		if h.resumeAuthority(sessionID, exclude) {
			return true
		}
	}
	return false
}

// validateAttachCapability enforces IPC capability grounding (A7/B4) for an
// untrusted socket-supplied spawn request BEFORE anything is launched: the tool
// must declare an Attach capability in the integration registry — the ONE owner
// of adapter capabilities — whose Subcommand matches the requested one, so a
// caller can't drive the daemon to launch an arbitrary `observer <x>` verb the
// operator never grounded as attachable. termsvc stays registry-free; this
// check lives at the daemon boundary (CLAUDE.md #3 — branch on the capability
// shape, not the tool name).
func validateAttachCapability(req attachsock.SpawnRequest) error {
	capab, ok := integration.For(req.Tool)
	if !ok || capab.Attach == nil {
		return fmt.Errorf("attach: tool %q has no grounded attach capability", req.Tool)
	}
	if capab.Attach.Subcommand != req.Subcommand {
		return fmt.Errorf("attach: subcommand %q does not match tool %q's grounded attach subcommand %q",
			req.Subcommand, req.Tool, capab.Attach.Subcommand)
	}
	// Resume defense in depth (attach-all-launchers §3): a socket client is
	// untrusted, so refuse a resume spawn (manual --resume OR an AutoResume) for
	// a tool with no grounded native resume. The 17 ResumeNone launchers now
	// attachable have no `--resume` argv, so composing one for their inner
	// launcher would fail with a cobra unknown-flag error inside the PTY. Branch
	// on the capability SHAPE, never the tool name (CLAUDE.md #3). The client
	// gate + resumableSessionSet already prevent this; this is the daemon-side
	// backstop against a spoofed request.
	if req.ResumeSession != "" && capab.Resume.Kind != integration.ResumeNative {
		return fmt.Errorf("attach: tool %q has no native resume capability", req.Tool)
	}
	return nil
}

// LaunchAttachable spawns a daemon-owned PTY for req and returns a live Session
// wired to a fresh viewer subscription (replay-then-tail) plus the loopback
// writer lease. On any wiring failure after the spawn it best-effort tears down
// what it acquired so a failed attach never leaks a viewer or a held lease.
func (h *attachHost) LaunchAttachable(ctx context.Context, req attachsock.SpawnRequest) (attachsock.Session, error) {
	// IPC capability enforcement (A7/B4): the socket-supplied request is
	// untrusted input; refuse a tool/subcommand the operator never grounded as
	// attachable BEFORE spawning anything (see validateAttachCapability).
	if err := validateAttachCapability(req); err != nil {
		return nil, err
	}

	// Resume guard (resilient-attach Layer 1). When this attach resumes a
	// session, single-flight the whole check+spawn+reserve per session id so two
	// concurrent resumes of the same session can't both pass. An AUTO-resume
	// (daemon-death reattach) is additionally validated against the sessions the
	// resumed daemon rediscovered as orphans — a run that recorded its end is
	// NOT resumable-by-restart. A manual `--attach --resume` skips that gate
	// (resuming a cleanly-closed session is legitimate) but still contributes to
	// the double-spawn liveness view.
	//
	// resumeClaim holds the DURABLE cross-process flock (H3) once acquired. It is
	// released by the deferred guard below on ANY failure before the session is
	// committed, and otherwise handed to the attachSession's release closure so
	// it lives exactly as long as the resumed run. Release is idempotent.
	var resumeClaim *attachsock.ResumeClaim
	spawnCommitted := false
	defer func() {
		if !spawnCommitted {
			resumeClaim.Release()
		}
	}()
	if req.ResumeSession != "" {
		release := h.resumeGuard.acquire(req.ResumeSession)
		defer release()
		if req.AutoResume && h.resumable != nil && !h.resumable(req.ResumeSession) {
			return nil, fmt.Errorf("%w: %q", attachsock.ErrResumeNotResumable, req.ResumeSession)
		}
		if h.resumeConflict(req.ResumeSession) {
			return nil, fmt.Errorf("%w: %q", attachsock.ErrResumeConflict, req.ResumeSession)
		}
		// Durable cross-process claim (H3): a bare launcher resuming the same
		// session during daemon downtime holds this flock; a held claim here
		// means a resume is already in progress in another process. Gated on
		// attachDir (off in tests / no-DB), where the in-memory guard suffices.
		if h.attachDir != "" {
			claim, ok, cerr := attachsock.AcquireResumeClaim(h.attachDir, req.ResumeSession)
			if cerr != nil {
				return nil, cerr
			}
			if !ok {
				return nil, fmt.Errorf("%w: %q", attachsock.ErrResumeConflict, req.ResumeSession)
			}
			resumeClaim = claim
		}
	}

	res, err := h.svc.LaunchAttachable(ctx, termsvc.AttachRequest{
		Tool:       req.Tool,
		Subcommand: req.Subcommand,
		Dir:        req.Dir,
		Rows:       req.Rows,
		Cols:       req.Cols,
		ExtraEnv:   req.Env,
		ExtraArgs:  req.ExtraArgs,
	})
	if err != nil {
		return nil, err
	}
	handle := res.Handle

	// Finding 2 (tombstone eviction): pin this run's exit tombstone for the whole
	// in-flight spawn window. If the child exits before the post-spawn
	// reserve/releaseOnExit registration lands (exit-before-registration), its
	// NotifyExit records a tombstone those steps must still consult; a flood of
	// >bound OTHER exits in that window would otherwise evict it (count-only bound)
	// and reopen the stuck-live / parked-flock races. The pin holds until
	// LaunchAttachable returns (the in-flight window closes, via the deferred
	// unpin); after that the tombstone is count-bounded again, so a MAXIMALLY-
	// delayed correlation arriving past 1024+ further post-exit exits can still
	// refuse a future resume until restart — an availability residual only, never a
	// double spawn (see exitTombstoneBound).
	if h.hub != nil {
		h.hub.pinTombstone(res.RunID)
		defer h.hub.unpinTombstone(res.RunID)
	}

	sub, err := h.mgr.Subscribe(handle)
	if err != nil {
		// The PTY is live but we could not attach a viewer. Do NOT record a
		// fabricated exit while the child keeps running (B3-3): TERMINATE the
		// just-spawned child through the SAME funnel the dashboard DELETE path
		// uses (Manager.Close → terminate), THEN record the now-real exit and
		// surface the failure. EndRunByHandle dedupes by handle, so this stays
		// consistent with the manager's own OnExit.
		markAttachEnding(h.svc, handle)
		h.mgr.Close(handle)
		h.svc.EndRunByHandle(ctx, handle, -1)
		return nil, err
	}
	lease, err := h.mgr.AcquireWriterLocal(handle)
	if err != nil {
		// Same as above: release the viewer, terminate the child so the -1 we
		// record is TRUE (not a claim made while it lived), then surface the
		// failure (B3-3).
		h.mgr.Unsubscribe(sub)
		markAttachEnding(h.svc, handle)
		h.mgr.Close(handle)
		h.svc.EndRunByHandle(ctx, handle, -1)
		return nil, err
	}

	// Spawn-time audit (F4): the PTY is spawned and fully wired (viewer + local
	// writer lease), so record the metadata-only terminal_attach row now — at
	// SPAWN, not on a later websocket attach — so an attach a client never joins
	// still leaves exactly one audit row.
	//
	// F3: emit it DETACHED (fire-and-forget). The audit sink waits up to 3s on a
	// contended SQLite writer; the attach PTY is already spawned and fully wired,
	// so blocking the socket handshake on the audit violates the "never blocks
	// the spawn" contract. Detaching at the call site keeps the guarantee
	// regardless of the sink implementation; the sink owns its own bounded
	// context and its failure stays ignored. Args are value-copied strings.
	if h.audit != nil {
		go h.audit(res.RunID, req.Tool, handle)
	}

	// Resilient-attach Layer 1: register a per-run correlation listener so the
	// server can relay this run's correlated session id to an AutoResumeCapable
	// client, and — for a resume — optimistically mark the resume target live so
	// a concurrent double-spawn is caught before the async correlation lands.
	// unregister on Detach closes the listener channel (ending the relay); the
	// daemon-wide live view is driven off the DIRECT NotifyExit seam (not the
	// feed), so it clears reliably even when the client detaches while the child
	// lives on, and even when the feed drops the exit event.
	var corr <-chan attachsock.CorrelatedSession
	if h.hub != nil {
		corr = h.hub.register(res.RunID)
		if req.ResumeSession != "" {
			h.hub.reserve(req.ResumeSession, res.RunID)
		}
		// Tie the durable resume flock to the run's TRUE exit (H3), not to a
		// client detach that leaves the child alive: releaseOnExit fires it on
		// NotifyExit. Ownership moves to the hub, so the session release closure
		// (fired on detach) must NOT also release it — nil it out here.
		if resumeClaim != nil {
			h.hub.releaseOnExit(res.RunID, resumeClaim.Release)
			resumeClaim = nil
		}
	}
	runID := res.RunID

	// On a successful AUTO-resume spawn, supersede the rediscovered predecessor
	// orphan rows (end_reason='resumed') so they can't be re-offered across a
	// later restart (H2). See supersedeResumedPredecessors for the by-predecessor
	// stamping + the wrong-run-supersede guard.
	h.supersedeResumedPredecessors(req, runID)

	// Ownership of the durable resume claim transfers to the session's release
	// closure below; stop the deferred failure-release from firing.
	spawnCommitted = true

	sess := &attachSession{
		handle: handle,
		runID:  res.RunID,
		output: sub,
		corr:   corr,
		// The current writer lease drives Write/Resize; on a Feature-1 reclaim it
		// is swapped under leaseMu for a freshly re-acquired one. *WriterLease
		// satisfies attachLease.
		lease: lease,
		exit:  func() (int, bool) { exited, code, ok := h.mgr.ExitStatus(handle); return code, exited && ok },
		release: func() {
			h.mgr.Unsubscribe(sub)
			if h.hub != nil {
				h.hub.unregister(runID)
			}
			// Fallback ONLY when the hub is disabled (no run-exit signal to hang
			// the flock release on): release the claim on detach. In production
			// the hub owns release-on-exit (set above, resumeClaim niled), so
			// this is a nil-safe no-op there. Idempotent regardless.
			resumeClaim.Release()
		},
		endRun: func(code int) { h.svc.EndRunByHandle(context.Background(), handle, code) },
	}
	// Native-terminal reclaim (Feature 1): when [terminal.attach].reclaim_on_input
	// is on, wire the reacquire hook so a fenced write re-takes the local writer
	// through the SAME AcquireWriterLocal funnel the dashboard uses (so the
	// standing-remote-takeover hook keeps firing). Off ⇒ nil hook ⇒ the server's
	// Reclaimer reports reclaim unavailable and the fence-and-notify path stands.
	if h.reclaimOnInput {
		sess.reacquire = func() (attachLease, error) {
			l, err := h.mgr.AcquireWriterLocal(handle)
			if err != nil {
				return nil, err
			}
			return l, nil
		}
	}
	return sess, nil
}

// supersedeResumedPredecessors stamps every startup-eligible predecessor orphan
// row of an AUTO-resume as end_reason='resumed' (H2) so it can't be re-offered
// across a later restart. It stamps by the exact PREDECESSOR run ids resolved
// from the rediscovery map — never by session — and defensively excludes runID
// (the fresh run just spawned here) so a resolver quirk can never mislabel the
// live replacement 'resumed' (which would block its own shutdown sweep + restart
// offer — the wrong-run-supersede class). All of this session's eligible
// predecessors are stamped, not just the newest, so older historical duplicates
// and prior stamp-failure rows don't stay offerable on every future restart
// (round-4 multi-orphan finding). Best-effort; a no-op unless this is an
// AUTO-resume with both resume hooks wired.
func (h *attachHost) supersedeResumedPredecessors(req attachsock.SpawnRequest, runID string) {
	if !req.AutoResume || req.ResumeSession == "" || h.supersedeResumed == nil || h.resumePredecessors == nil {
		return
	}
	predRunIDs, ok := h.resumePredecessors(req.ResumeSession)
	if !ok || len(predRunIDs) == 0 {
		return
	}
	ids := make([]string, 0, len(predRunIDs))
	for _, id := range predRunIDs {
		if id != runID {
			ids = append(ids, id)
		}
	}
	if len(ids) > 0 {
		h.supersedeResumed(ids)
	}
}

// --- resilient-attach Layer 1: correlation hub + resume guard --------------

// correlateKindPrefix is the termfeed Kind prefix the Service publishes a
// run→session correlation under ("term:correlate:<source>"). The hub keys off
// it to learn a run's correlated agent session id from the SAME trusted feed
// the status hub consumes — no new store read, no termsvc change.
const correlateKindPrefix = "term:correlate:"

// exitKind is the termfeed Kind a run's daemon-observed exit is published under.
// Post round-4 the hub no longer derives CORRECTNESS from it — liveness, flock
// release, and tombstones ride the DIRECT NotifyExit seam (fired from
// termsvc.EndRunByHandle) instead, which the lossy feed can never drop. drain
// still recognises the kind only to IGNORE it explicitly, documenting that the
// feed is advisory here.
const exitKind = "term:exit"

// minCorrelationConfidence gates which correlations the hub acts on. It mirrors
// termrun.MinLinkConfidence ("links attach only once established"): a weak
// heuristic guess is NOT surfaced as an auto-resume target and does NOT mark a
// session live, so the ABSTAIN rule holds — only a genuinely-established
// correlation ever becomes a resume target.
const minCorrelationConfidence = termrun.MinLinkConfidence

// correlationConfidence maps a feed correlation source token to the same
// confidence internal/termrun assigns it, so the hub's gate matches the
// Service's SessionForRun gate. An unknown source scores 0 (never trusted).
func correlationConfidence(source string) float64 {
	switch termrun.Source(source) {
	case termrun.SourceOOB:
		return 0.95
	case termrun.SourceDiscovered:
		return 0.75
	case termrun.SourceMarker:
		return 0.70
	case termrun.SourceHeuristic:
		return 0.40
	default:
		return 0
	}
}

// hubListener is a per-run correlation delivery channel plus the last session id
// delivered (dedup, so an unchanged re-observation does not re-emit a frame).
type hubListener struct {
	ch   chan attachsock.CorrelatedSession
	last string
}

// attachHub bridges the daemon's trusted correlation feed to the attach socket
// (resilient-attach Layer 1). It (a) delivers a run's correlated session id to
// a per-run listener the attach server relays as a frameCorrelated frame, and
// (b) maintains a daemon-wide live-session view the double-spawn guard consults.
//
// The two halves have DIFFERENT trust sources by design (round-4). (a) is
// ADVISORY and rides the feed subscription (term:correlate events) — a dropped
// event only staleness a "Jump in" hint. (b) is CORRECTNESS and rides the DIRECT
// NotifyExit seam (fired from termsvc.EndRunByHandle), never the feed, so
// liveness / flock release / tombstones cannot be corrupted by a feed overflow,
// an attacker-paddable PTY-hint event sharing the queue, or the pre-registration
// gap where no term:exit is ever produced. The hub still never reads the store on
// the hot path and never reaches into termsvc's internals.
type attachHub struct {
	feed   *termfeed.Feed
	sub    *termfeed.Sub
	logger *slog.Logger // optional; nil disables the feed-loss advisory note
	// nowFunc sources the current time for tombstone timestamps AND the
	// age-floor eviction check. Defaults to time.Now (newAttachHub); a test
	// seam overrides it to age entries deterministically without sleeping.
	nowFunc func() time.Time

	stopOnce sync.Once

	mu sync.Mutex
	// runToSession maps a live run id → its bound session id (reserved at spawn
	// for a resume, or learned from a correlation), for liveness cleanup on exit.
	runToSession map[string]string
	// live counts live runs per session id (the double-spawn guard reads it).
	live map[string]int
	// confirmed holds a run's established correlation (>= min confidence), so a
	// listener registered after the correlation landed still gets it.
	confirmed map[string]attachsock.CorrelatedSession
	// listeners are the per-run correlation delivery channels.
	listeners map[string]*hubListener
	// exitCallbacks are per-run cleanups fired ONCE when the run's exit lands via
	// NotifyExit (the direct seam). The durable resume flock registers here so it is
	// released on the RUN's true exit — not on a client detach that leaves the
	// child alive (H3): tying release to detach would free the claim while the
	// resumed run keeps running under the daemon, reopening the double-spawn hole.
	exitCallbacks map[string]func()
	// exited holds per-run EXIT TOMBSTONES keyed by RUN id. NotifyExit records one
	// for EVERY ended run (round-5 finding 2) — both the fast-exit run whose exit
	// raced the post-spawn reserve/releaseOnExit registration AND the normal
	// tracked run — so a stale correlation event still queued in the LOSSY feed can
	// never resurrect a run's liveness after its exit. reserve consults it so it
	// never recreates liveness for an already-exited run; releaseOnExit consults it
	// so it fires the flock-release callback immediately instead of parking it for
	// a second exit that will never come; and onCorrelate consults it so a late
	// correlation never resurrects liveness (finding c + round-5 finding 2). Keyed
	// by RUN id (unique per spawn) so a predecessor's tombstone can never confuse a
	// legitimate next resume of the same SESSION. Drained toward
	// exitTombstoneBound by shedTombstonesLocked (oldest ELIGIBLE first: unpinned
	// AND older than tombstoneMinAge) — with transient overshoot while entries are
	// pinned or young; see exitTombstoneBound for the true size invariant.
	exited map[string]time.Time
	// pinned holds the run ids whose exit tombstone must NOT be evicted because an
	// in-flight attach spawn may still consult it (review finding 2). The attach
	// host pins a run for its whole LaunchAttachable window (pinTombstone) and
	// unpins on return (unpinTombstone); shedTombstonesLocked skips pinned ids when
	// shedding, so an exit-before-registration tombstone (or a delayed correlation)
	// survives a flood of >bound other exits. Keyed by RUN id; a transient set
	// bounded by the number of concurrent in-flight spawns.
	//
	// The pin is a BELT to the age-floor's SUSPENDERS (round-7 finding 1):
	// termsvc.LaunchAttachable can reconcile a fast child exit and call NotifyExit
	// BEFORE it returns — so the tombstone exists before the host's pin lands. The
	// age floor (tombstoneMinAge) protects that just-written tombstone through the
	// pre-pin window regardless of the pin, so a flood in the descheduling gap
	// can't evict it out from under the imminent pin.
	pinned map[string]struct{}
}

// exitTombstoneBound is the TARGET size shedTombstonesLocked drains the
// attachHub.exited tombstone map back down to. NotifyExit records a tombstone for
// EVERY ended run (round-5 finding 2), so the map grows once per run exit —
// INCLUDING every dashboard run — and a naive count-only bound could evict a
// tombstone an in-flight attach spawn still needs (review finding 2). Eviction is
// therefore doubly gated: shedding NEVER evicts a tombstone that is PINNED for an
// in-flight spawn window (pinTombstone/unpinTombstone) OR younger than
// tombstoneMinAge (the pre-pin age floor, round-7 finding 1). The bound is 1024 (a
// map entry + timestamp is cheap) to widen the count safety margin.
//
// TRUE size invariant (round-7 findings 1+2, round-8 finding 1 — honest
// convergence): each shed invocation is a SINGLE PASS (one scan collecting
// eligible entries, sorted oldest-first, batch-deleting as many as possible
// toward the target bound), driven from every tombstone INSERTION
// (tombstoneLocked), every unpin (unpinTombstone), and every correlation
// CONSULT (onCorrelate) — so common runtime traffic, not
// just insertion/unpin, drains the map back toward exitTombstoneBound. But
// convergence is strictly EVENT-DRIVEN: there is no timer or goroutine that
// walks the map on its own. Under TOTAL quiescence after a burst (no further
// exit, unpin, or correlation activity), the map does NOT keep converging as
// entries merely age past tombstoneMinAge — no pass ever runs to notice — so
// it retains its high-water entry count indefinitely. A map entry (an id
// string plus a timestamp) runs to the order of tens of bytes, so the nominal
// bound of 1024 entries is on the order of 100KB, not "a few KB at most" — and
// overshoot past that bound has NO hard cap: it is bounded only by how much
// real exit churn lands within the floor window, plus however many tombstones
// are pinned for in-flight spawns at the time. Reads are keyed per-run lookups
// (reserve/releaseOnExit/onCorrelate) except for the shed pass itself, which DOES
// walk the whole map — so "nothing walks it for size" is misleading too; the
// walk exists, it just only runs on the event-driven triggers above, not on a
// timer. Honest residual: after 1024+ further post-exit exits past a run's
// unpin AND floor-age, a MAXIMALLY-delayed correlation for it can still refuse
// a future resume until the daemon restarts — an availability residual only,
// NEVER a double spawn.
const exitTombstoneBound = 1024

// tombstoneMinAge is the eviction age floor (round-7 finding 1): a tombstone
// younger than this is NEVER shed, even past exitTombstoneBound. It closes the
// pre-pin window — termsvc.LaunchAttachable can reconcile a fast child exit and
// call NotifyExit (writing the tombstone) BEFORE it returns, so the tombstone
// exists before the attach host's pinTombstone runs; if the host goroutine is
// descheduled in that gap while 1024+ other exits arrive, a count-only bound would
// evict the just-written tombstone and reopen the stuck-live / parked-flock races.
// 60s is generous versus any plausible descheduling of the few statements between
// NotifyExit and the pin (the tombstone is at most milliseconds old when the pin
// lands), so the window is safe without relying on the pin winning the race.
const tombstoneMinAge = 60 * time.Second

// newAttachHub subscribes to the correlation feed and starts the drain loop.
// logger may be nil (the feed-loss advisory note is then suppressed).
func newAttachHub(feed *termfeed.Feed, logger *slog.Logger) *attachHub {
	h := &attachHub{
		feed:          feed,
		sub:           feed.Subscribe(),
		logger:        logger,
		nowFunc:       time.Now,
		runToSession:  make(map[string]string),
		live:          make(map[string]int),
		confirmed:     make(map[string]attachsock.CorrelatedSession),
		listeners:     make(map[string]*hubListener),
		exitCallbacks: make(map[string]func()),
		exited:        make(map[string]time.Time),
		pinned:        make(map[string]struct{}),
	}
	go h.drain()
	return h
}

// drain consumes feed events for ADVISORY correlation state ONLY. Post round-4
// the hub's correctness (liveness / flock release / tombstones) rides the DIRECT
// NotifyExit seam, not this subscription, so a dropped feed event can no longer
// corrupt it: at worst a run's correlated-session HINT (the dashboard "Jump in"
// affordance) is briefly stale until the next observation re-publishes it. drain
// therefore only processes correlate events, explicitly ignores exit events, and
// checks Sub.Lost purely to NOTE the degraded advisory freshness — it clears NO
// state on loss (there is no correctness to resynchronize here anymore).
func (h *attachHub) drain() {
	var lastLost uint64
	for ev := range h.sub.C() {
		if lost := h.sub.Lost(); lost != lastLost {
			h.noteFeedLoss(lost - lastLost)
			lastLost = lost
		}
		switch {
		case ev.RunID == "":
			// nothing to attribute
		case ev.Kind == exitKind:
			// Ignored on purpose: exits drive correctness through NotifyExit, not
			// the feed (see exitKind's doc). Recognised only so it is a documented
			// no-op rather than an accidental fall-through.
		case strings.HasPrefix(ev.Kind, correlateKindPrefix) && ev.SessionID != "":
			source := strings.TrimPrefix(ev.Kind, correlateKindPrefix)
			conf := correlationConfidence(source)
			if conf < minCorrelationConfidence {
				continue // ABSTAIN: a weak guess is not a resume target
			}
			h.onCorrelate(ev.RunID, ev.SessionID, source, conf)
		}
	}
}

// noteFeedLoss records that the advisory correlation feed dropped n events under
// overflow. It deliberately clears NO hub state: correctness rides NotifyExit, so
// a loss only means a correlated-session hint may lag until re-observed. Advisory
// only — a debug line, never an error.
func (h *attachHub) noteFeedLoss(n uint64) {
	if h.logger != nil {
		h.logger.Debug("attach hub: correlation feed dropped events (advisory correlation may lag until re-observed; liveness/flock correctness is unaffected)", "dropped", n)
	}
}

// onCorrelate records an established run→session correlation: it updates the
// liveness view and delivers the id to a registered listener (dedup by id).
func (h *attachHub) onCorrelate(runID, sessionID, source string, conf float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Finding (c): refuse to recreate liveness (or cache a confirmation) for a run
	// the DIRECT exit seam already marked exited. A correlation can legitimately
	// land AFTER a run's exit — the feed is async and lossy, and NotifyExit may
	// have fired first via the reconcile — and resurrecting live[sessionID] here
	// would leave the double-spawn guard stuck true forever. The tombstone is the
	// authoritative "this run is gone" signal, consulted under the SAME single lock
	// acquisition as the liveness mutation it guards.
	//
	// Snapshotted BEFORE the shed pass below (round-9 finding 1): shedding evicts
	// the OLDEST eligible tombstone, and under a flood of newer exits this run's
	// own tombstone can legitimately be that oldest entry — target exits, 1024+
	// newer tombstones arrive and age past the floor, and THIS correlation is the
	// very shed-triggering event, so a post-shed dead-check would look up a
	// tombstone the shed pass just evicted and miss, permanently resurrecting
	// liveness for a run that has already exited. Checking first (still under the
	// same lock acquisition) makes the dead-check immune to the shed pass it
	// precedes.
	_, dead := h.exited[runID]
	// Round-8 finding 1 (shed trigger): a correlation consult is activity too, so
	// run the shed pass here — already under the lock, no new locking, no timer.
	// Without this, shedding only fires on tombstone insertion/unpin, and a
	// quiescent daemon (no further exits) never converges an oversized map even
	// once entries age past tombstoneMinAge; correlation traffic is the common
	// case that keeps the map draining under ordinary activity.
	h.shedTombstonesLocked()
	if dead {
		return
	}
	if prev := h.runToSession[runID]; prev != sessionID {
		if prev != "" {
			h.decLiveLocked(prev)
		}
		h.runToSession[runID] = sessionID
		h.live[sessionID]++
	}
	c := attachsock.CorrelatedSession{SessionID: sessionID, Source: source, Confidence: conf}
	h.confirmed[runID] = c
	if l := h.listeners[runID]; l != nil && l.last != sessionID {
		l.last = sessionID
		select {
		case l.ch <- c:
		default: // never block the feed drain; the buffer holds the latest
		}
	}
}

// NotifyExit is the DIRECT, reliable per-run exit seam (resilient-attach
// round-4). It is called synchronously from termsvc.EndRunByHandle (via
// Options.OnRunExit) the moment a run's exit is recorded — from the Manager's
// OnExit closure, from launch()'s pre-registration reconcile, or from the attach
// host's honest-close — so the hub's liveness / flock-release / tombstone
// correctness never depends on a term:exit surviving the lossy status feed. It
// clears the run's liveness + correlation state, fires the parked flock-release
// callback, and records a per-run exit tombstone for EVERY ended run (round-5
// finding 2) — the tracked run as well as the fast-exit run whose exit raced the
// post-spawn reserve/releaseOnExit registration — so a later reserve never
// resurrects liveness, a later releaseOnExit fires immediately, and a stale
// correlation event still queued in the lossy feed can never resurrect the run's
// liveness after its exit. The listener channel is NOT closed here — it
// is closed on unregister (Detach), so a client that detached while the child
// lived on still had its relay end there. Idempotent per run: a second call for
// an already-cleared run tombstones (harmlessly) or no-ops.
func (h *attachHub) NotifyExit(runID string) {
	if runID == "" {
		return
	}
	h.mu.Lock()
	if sid, ok := h.runToSession[runID]; ok {
		h.decLiveLocked(sid)
		delete(h.runToSession, runID)
	}
	// Tombstone EVERY ended run — the tracked branch above AND the untracked
	// fast-exit branch — under this SAME lock (round-5 finding 2). Tombstoning
	// only the untracked run left a hole for the tracked one: with the ordering
	// reserve → (correlation event queued in the lossy feed) → NotifyExit → late
	// onCorrelate, the queued correlation would find NO tombstone and resurrect
	// live[sessionID] PERMANENTLY (no second exit signal ever comes, so every
	// future resume of the session is refused until the daemon restarts). Now a
	// tracked run is tombstoned too, so onCorrelate/reserve/releaseOnExit all see
	// the authoritative "this run is gone" signal regardless of ordering. Keyed by
	// RUN id (unique per spawn) so a predecessor's tombstone never confuses a
	// legitimate next resume of the same SESSION.
	h.tombstoneLocked(runID)
	delete(h.confirmed, runID)
	fn := h.exitCallbacks[runID]
	delete(h.exitCallbacks, runID)
	h.mu.Unlock()
	if fn != nil {
		fn() // release the durable resume flock on the run's true exit (H3)
	}
}

// tombstoneLocked records a per-run exit tombstone (timestamped via nowFunc) and
// runs a shed pass to drain the map back toward exitTombstoneBound. Must be called
// under h.mu.
func (h *attachHub) tombstoneLocked(runID string) {
	h.exited[runID] = h.nowFunc()
	h.shedTombstonesLocked()
}

// shedTombstonesLocked drains attachHub.exited back down to exitTombstoneBound,
// evicting ONLY eligible entries: unpinned (no in-flight spawn may still need it,
// review finding 2) AND older than tombstoneMinAge (past the pre-pin age floor,
// round-7 finding 1), oldest-eligible-first, draining to the bound in one call
// (round-7 finding 2 — a single-eviction-per-add shed left an oversized baseline
// permanently once an overshoot happened). Round-9 finding 2: this is a SINGLE
// pass — one O(n) scan collects every eligible entry, then one sort orders them
// oldest-first, then it deletes the (len(exited)-bound) oldest of those — rather
// than the previous approach's full O(n) rescan-for-the-oldest PER eviction
// (O(n×excess) under the hub-wide lock when draining a large aged overshoot).
// When fewer eligible entries exist than the overshoot, it deletes all of them
// (matching the old loop's "ran out of eligible candidates" exit) and the map
// stays transiently oversized; a later shed pass — from tombstoneLocked
// (insertion), unpinTombstone, OR onCorrelate (a correlation consult, round-8
// finding 1 — common runtime traffic converges the map too, not just
// insertion/unpin) — drains it further as pins clear and entries age.
// Convergence is event-driven, not time-driven: with no further activity of any
// of those three kinds, no pass runs and the map does not shrink on its own.
// Must be called under h.mu.
func (h *attachHub) shedTombstonesLocked() {
	overshoot := len(h.exited) - exitTombstoneBound
	if overshoot <= 0 {
		return
	}
	now := h.nowFunc()
	type tombstone struct {
		id string
		at time.Time
	}
	eligible := make([]tombstone, 0, overshoot)
	for id, at := range h.exited {
		if _, isPinned := h.pinned[id]; isPinned {
			continue // never evict a tombstone an in-flight spawn may still need
		}
		if now.Sub(at) < tombstoneMinAge {
			continue // age floor: too young to safely evict (pre-pin window)
		}
		eligible = append(eligible, tombstone{id: id, at: at})
	}
	if len(eligible) == 0 {
		return // all candidates pinned or younger than the floor: grow transiently
	}
	sort.Slice(eligible, func(i, j int) bool { return eligible[i].at.Before(eligible[j].at) })
	if overshoot > len(eligible) {
		overshoot = len(eligible)
	}
	for _, t := range eligible[:overshoot] {
		delete(h.exited, t.id)
	}
}

// pinTombstone marks runID's exit tombstone un-evictable for the duration of an
// in-flight attach spawn (review finding 2). While pinned, tombstoneLocked never
// sheds it even past exitTombstoneBound, so the post-spawn
// reserve/releaseOnExit/onCorrelate for this run always find the authoritative
// "this run is gone" signal even under a flood of concurrent exits. Idempotent.
func (h *attachHub) pinTombstone(runID string) {
	if runID == "" {
		return
	}
	h.mu.Lock()
	h.pinned[runID] = struct{}{}
	h.mu.Unlock()
}

// unpinTombstone releases a pin taken by pinTombstone (review finding 2),
// returning the run's tombstone to the count-bounded pool. Called when the
// in-flight spawn window closes (LaunchAttachable returns). It runs a shed pass so
// a cleared pin lets a map that overshot the bound (because its candidates were all
// pinned/young) drain back down — otherwise the oversized baseline would persist
// forever (round-7 finding 2). Idempotent.
func (h *attachHub) unpinTombstone(runID string) {
	if runID == "" {
		return
	}
	h.mu.Lock()
	delete(h.pinned, runID)
	h.shedTombstonesLocked()
	h.mu.Unlock()
}

// releaseOnExit registers fn to fire once when runID's daemon-observed exit
// lands (H3 flock release). If the run already EXITED before this registration —
// either it is no longer tracked live, or its exit landed with no live entry and
// left a tombstone (the fast-exit race) — fn fires immediately so the claim can
// never leak past the run and no callback is parked for a second exit that will
// never come. Idempotent per run: a second registration replaces the first (only
// one claim per run exists).
func (h *attachHub) releaseOnExit(runID string, fn func()) {
	if fn == nil {
		return
	}
	h.mu.Lock()
	_, tracked := h.runToSession[runID]
	_, dead := h.exited[runID]
	if dead || !tracked {
		h.mu.Unlock()
		fn()
		return
	}
	h.exitCallbacks[runID] = fn
	h.mu.Unlock()
}

// decLiveLocked decrements a session's live-run count, removing the key at zero.
func (h *attachHub) decLiveLocked(sessionID string) {
	if h.live[sessionID] <= 1 {
		delete(h.live, sessionID)
		return
	}
	h.live[sessionID]--
}

// reserve optimistically marks a resume target's run live at spawn — BEFORE the
// asynchronous correlation lands — so a concurrent double-spawn of the same
// session is caught by sessionLive. Idempotent per run id.
func (h *attachHub) reserve(sessionID, runID string) {
	if sessionID == "" || runID == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// The run already exited before this reserve (its NotifyExit was processed
	// first): do NOT recreate liveness for a dead run, or sessionLive would stay
	// stuck true and block every later resume (finding: fast-exit race). The
	// tombstone is left in place for the paired releaseOnExit to consult.
	if _, dead := h.exited[runID]; dead {
		return
	}
	if _, ok := h.runToSession[runID]; !ok {
		h.runToSession[runID] = sessionID
		h.live[sessionID]++
	}
}

// sessionLive reports whether any live run is bound to sessionID (the double-
// spawn guard).
func (h *attachHub) sessionLive(sessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.live[sessionID] > 0
}

// register creates a per-run correlation listener and returns its channel. If a
// correlation already landed for the run, it is delivered immediately.
func (h *attachHub) register(runID string) <-chan attachsock.CorrelatedSession {
	l := &hubListener{ch: make(chan attachsock.CorrelatedSession, 4)}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.listeners[runID] = l
	if c, ok := h.confirmed[runID]; ok {
		l.last = c.SessionID
		l.ch <- c // fits: fresh buffered channel
	}
	return l.ch
}

// unregister removes + closes a run's listener (ends the server relay). Safe to
// call for an unknown run id.
func (h *attachHub) unregister(runID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if l := h.listeners[runID]; l != nil {
		delete(h.listeners, runID)
		close(l.ch)
	}
}

// stop unsubscribes from the feed, ending the drain loop. Idempotent.
func (h *attachHub) stop() {
	h.stopOnce.Do(func() { h.feed.Unsubscribe(h.sub) })
}

// resumeGate is a reference-counted per-session single-flight gate (mirrors the
// dashboard resume route's resumeGate, R2-3).
type resumeGate struct {
	mu   sync.Mutex
	refs int
}

// attachResumeGuard single-flights resume check+spawn per session id, so two
// concurrent resumes of the same session serialize (the second observes the
// first's now-live run and is refused). Different session ids never contend.
type attachResumeGuard struct {
	mu    sync.Mutex
	gates map[string]*resumeGate
}

// acquire blocks until this caller holds the gate for sessionID and returns its
// releaser. The last releaser drops the gate so idle sessions leave no entry.
func (g *attachResumeGuard) acquire(sessionID string) func() {
	g.mu.Lock()
	if g.gates == nil {
		g.gates = make(map[string]*resumeGate)
	}
	gate := g.gates[sessionID]
	if gate == nil {
		gate = &resumeGate{}
		g.gates[sessionID] = gate
	}
	gate.refs++
	g.mu.Unlock()

	gate.mu.Lock()
	return func() {
		gate.mu.Unlock()
		g.mu.Lock()
		gate.refs--
		if gate.refs == 0 {
			delete(g.gates, sessionID)
		}
		g.mu.Unlock()
	}
}

// writeMappingRevoked calls the lease's Write and maps termsession's
// ErrNotWriter (the lease was fenced out — revoked, taken over, or expired,
// while the PTY session lives on) to attachsock.ErrWriterRevoked so the server
// relays a non-fatal notice instead of tearing the session down (A5).
func writeMappingRevoked(write func([]byte) (int, error), p []byte) (int, error) {
	n, err := write(p)
	if errors.Is(err, termsession.ErrNotWriter) {
		return n, attachsock.ErrWriterRevoked
	}
	return n, err
}

// attachLease is the subset of *termsession.WriterLease attachSession drives
// (Write/Resize a live PTY, Release the lease). A small interface keeps
// attachSession testable in isolation with a stub lease, and lets a Feature-1
// reclaim swap one lease for a freshly re-acquired one.
type attachLease interface {
	Write(p []byte) (int, error)
	Resize(rows, cols uint16) error
	Release()
}

// errReclaimDisabled is returned by attachSession.ReclaimWriter when reclaim is
// off ([terminal.attach].reclaim_on_input=false → nil reacquire hook). The
// attach server treats any reclaim error as "reclaim unavailable" and falls back
// to the non-fatal revoked notice — so the disabled path is byte-identical to
// the pre-Feature-1 behavior.
var errReclaimDisabled = errors.New("attach: writer reclaim is disabled")

// attachSession implements attachsock.Session over a viewer subscription + a
// writer lease. Its fields are plain funcs/readers/interfaces so the type is
// testable in isolation with stubs (the deliverable-(a) unit test).
type attachSession struct {
	handle string
	runID  string
	output io.Reader
	exit   func() (int, bool)
	// release runs the non-lease cleanup on Detach (unsubscribe the viewer, hub
	// unregister, durable-resume flock release). The CURRENT writer lease is
	// released separately by Detach off s.lease, so a Feature-1 reclaim swap is
	// honored on teardown.
	release func()
	endRun  func(exitCode int)
	// corr, when non-nil, delivers this run's correlated-session announcements
	// (resilient-attach Layer 1). The attach server relays them to an
	// AutoResumeCapable client. Closed by the hub on unregister (in release).
	corr <-chan attachsock.CorrelatedSession

	// leaseMu guards lease across a Feature-1 reclaim swap. lease is the CURRENT
	// writer lease Write/Resize drive; reacquire re-takes the local writer lease
	// through the manager (nil ⇒ reclaim disabled).
	leaseMu   sync.Mutex
	lease     attachLease
	reacquire func() (attachLease, error)

	once sync.Once
}

// currentLease returns the live writer lease under the swap lock.
func (s *attachSession) currentLease() attachLease {
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	return s.lease
}

// ReclaimWriter satisfies attachsock.Reclaimer (Feature 1). It re-acquires the
// local writer lease through the SAME AcquireWriterLocal funnel the dashboard
// uses — so a standing-remote-takeover still fires its hook — and swaps it in as
// the session's live lease, releasing the superseded (already-fenced) lease. The
// server calls it only after a fenced write whose first byte is a real key (not
// ESC), then re-delivers the chunk through the fresh lease. Returns
// errReclaimDisabled when reclaim is off (nil reacquire), so the server keeps the
// fence-and-notify behavior.
func (s *attachSession) ReclaimWriter() error {
	if s.reacquire == nil {
		return errReclaimDisabled
	}
	nl, err := s.reacquire()
	if err != nil {
		return err
	}
	s.leaseMu.Lock()
	old := s.lease
	s.lease = nl
	s.leaseMu.Unlock()
	// Release the superseded lease (already revoked by the re-acquire's local
	// takeover); idempotent and outside the swap lock so it never blocks a
	// concurrent Write's brief lease read.
	if old != nil {
		old.Release()
	}
	return nil
}

// ReclaimAvailable satisfies attachsock.ReclaimAvailabler: a real keystroke can
// reclaim the writer only when a reacquire hook is wired
// ([terminal.attach].reclaim_on_input on). Lets the server word the takeover
// notice honestly — offering "press a key to take control back" only when that
// gesture will actually reclaim.
func (s *attachSession) ReclaimAvailable() bool {
	return s.reacquire != nil
}

// CorrelatedSessions satisfies attachsock.CorrelationSource. It returns the
// per-run correlation channel (nil when the hub is disabled — the server's
// relay treats a nil channel as "no correlations", so no frame is ever sent).
func (s *attachSession) CorrelatedSessions() <-chan attachsock.CorrelatedSession {
	return s.corr
}

// Handle returns the opaque PTY handle (also the dashboard join key).
func (s *attachSession) Handle() string { return s.handle }

// RunID returns the run identity minted for this attach launch.
func (s *attachSession) RunID() string { return s.runID }

// Output returns the replay-then-tail reader over the PTY ring.
func (s *attachSession) Output() io.Reader { return s.output }

// Write forwards raw bytes (the client's keystrokes) to the PTY through the
// current lease, mapping termsession's ErrNotWriter (the lease was fenced out —
// revoked, taken over, or expired, while the PTY session lives on) to
// attachsock.ErrWriterRevoked so the server can reclaim or relay a non-fatal
// notice instead of tearing the session down (A5). attachsock never imports
// termsession — the mapping lives here, at the boundary.
func (s *attachSession) Write(p []byte) (int, error) {
	return writeMappingRevoked(s.currentLease().Write, p)
}

// Resize resizes the PTY through the current lease. A fenced lease returns
// ErrNotWriter, mapped to attachsock.ErrWriterRevoked at the boundary (the
// server logs it; resize does not carry the reclaim gesture — a keystroke does).
func (s *attachSession) Resize(rows, cols uint16) error {
	err := s.currentLease().Resize(rows, cols)
	if errors.Is(err, termsession.ErrNotWriter) {
		return attachsock.ErrWriterRevoked
	}
	return err
}

// ExitCode returns the child's exit code once known.
func (s *attachSession) ExitCode() (int, bool) { return s.exit() }

// Detach releases the writer lease and unsubscribes the viewer WITHOUT killing
// the child — the PTY lives on for the dashboard and other viewers. It is
// idempotent (guarded by sync.Once) so the attach server can call it on both
// child-exit and client-drop paths safely.
//
// When the child has already exited by the time we detach, we record the run's
// exit honestly through the SAME svc.EndRunByHandle the dashboard path uses
// (idempotent with the shared manager's OnExit — see the file header). On a
// clean detach with the child still alive we record nothing; the manager's
// OnExit will record the real exit when it eventually happens.
func (s *attachSession) Detach() {
	s.once.Do(func() {
		if s.exit != nil && s.endRun != nil {
			if code, exited := s.exit(); exited {
				s.endRun(code)
			}
		}
		// Release the CURRENT lease (honoring any Feature-1 reclaim swap) before
		// the non-lease cleanup.
		if l := s.currentLease(); l != nil {
			l.Release()
		}
		if s.release != nil {
			s.release()
		}
	})
}
