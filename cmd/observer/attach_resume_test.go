//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestIsDaemonGone pins which Attach errors drive the auto-resume loop: only a
// definitive daemon exit or an ambiguous connection loss. An input stall, a
// clean nil, and a server error must NOT (they report as today).
func TestIsDaemonGone(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"daemon exited", attachsock.ErrDaemonExited, true},
		{"conn lost", attachsock.ErrConnLost, true},
		{"wrapped conn lost", errors.New("x: " + attachsock.ErrConnLost.Error()), false}, // not wrapped via %w
		{"input stalled", attachsock.ErrInputStalled, false},
		{"nil", nil, false},
		{"server error", &attachsock.ServerError{Code: attachsock.CodeResumeConflict}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDaemonGone(tc.err); got != tc.want {
				t.Errorf("isDaemonGone(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestResumeIDFromExtraArgs pins extraction of a manual `--resume <id>` from the
// launcher argv head (never from the `--` tool remainder).
func TestResumeIDFromExtraArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"none", []string{"--proxy", "http://p"}, ""},
		{"present", []string{"--claude-path", "/c", "--resume", "sess-1"}, "sess-1"},
		{"only in tool remainder is ignored", []string{"--", "--resume", "not-ours"}, ""},
		{"head wins over remainder", []string{"--resume", "sess-2", "--", "--resume", "x"}, "sess-2"},
		{"dangling flag", []string{"--resume"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resumeIDFromExtraArgs(tc.args); got != tc.want {
				t.Errorf("resumeIDFromExtraArgs(%v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

// TestInjectResumeArg pins that the auto-resume argv rewrite preserves proxy
// state (escape hatch + overrides + wrapper flags) and the tool remainder, while
// replacing any stale `--resume` and appending `--resume <id>` in the head.
func TestInjectResumeArg(t *testing.T) {
	cases := []struct {
		name string
		args []string
		id   string
		want []string
	}{
		{
			"empty", nil, "s1",
			[]string{"--resume", "s1"},
		},
		{
			"preserves proxy + wrapper flags",
			[]string{"--no-proxy-route", "--proxy", "http://p", "--claude-path", "/c"},
			"s2",
			[]string{"--no-proxy-route", "--proxy", "http://p", "--claude-path", "/c", "--resume", "s2"},
		},
		{
			"replaces stale resume, keeps tool remainder",
			[]string{"--resume", "old", "--", "--model", "x"},
			"s3",
			[]string{"--resume", "s3", "--", "--model", "x"},
		},
		{
			"inserts before tool remainder",
			[]string{"--config", "/c.toml", "--", "exec", "hi"},
			"s4",
			[]string{"--config", "/c.toml", "--resume", "s4", "--", "exec", "hi"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := injectResumeArg(tc.args, tc.id)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("arg[%d] = %q, want %q (got %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

// TestResumeSpawnPreservesProxyState pins that the composed auto-resume spawn
// carries the SAME proxy env as the original launch, the rewritten resume argv,
// and the resume metadata (ResumeSession + AutoResume) the daemon guards on.
func TestResumeSpawnPreservesProxyState(t *testing.T) {
	in := attachLaunch{
		tool:      "claude-code",
		proxyEnv:  []string{"ANTHROPIC_BASE_URL=http://127.0.0.1:8820"},
		extraArgs: []string{"--claude-path", "/opt/claude"},
	}
	spawn := resumeSpawn(in, "claude", "/work", "sess-9")
	if spawn.Tool != "claude-code" || spawn.Subcommand != "claude" || spawn.Dir != "/work" {
		t.Fatalf("spawn identity = %+v", spawn)
	}
	if len(spawn.Env) != 1 || spawn.Env[0] != "ANTHROPIC_BASE_URL=http://127.0.0.1:8820" {
		t.Fatalf("proxy env not preserved: %v", spawn.Env)
	}
	if spawn.ResumeSession != "sess-9" || !spawn.AutoResume {
		t.Fatalf("resume metadata = {ResumeSession:%q AutoResume:%v}, want {sess-9 true}", spawn.ResumeSession, spawn.AutoResume)
	}
	want := []string{"--claude-path", "/opt/claude", "--resume", "sess-9"}
	if len(spawn.ExtraArgs) != len(want) {
		t.Fatalf("extra args = %v, want %v", spawn.ExtraArgs, want)
	}
	for i := range want {
		if spawn.ExtraArgs[i] != want[i] {
			t.Fatalf("arg[%d] = %q, want %q", i, spawn.ExtraArgs[i], want[i])
		}
	}
}

// TestPromptProceed pins the prompt-with-timeout classification: Ctrl-C skips,
// everything else (timeout, Enter, any key) auto-proceeds.
func TestPromptProceed(t *testing.T) {
	cases := []struct {
		name string
		b    byte
		n    int
		err  error
		want bool
	}{
		{"timeout/deadline", 0, 0, errPromptTimeout, true},
		{"enter", 0x0d, 1, nil, true},
		{"any key", 'y', 1, nil, true},
		{"ctrl-c skips", 0x03, 1, nil, false},
		{"eof proceeds", 0, 0, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := promptProceed(tc.b, tc.n, tc.err); got != tc.want {
				t.Errorf("promptProceed(%d,%d,%v) = %v, want %v", tc.b, tc.n, tc.err, got, tc.want)
			}
		})
	}
}

var errPromptTimeout = errors.New("i/o timeout")

// TestWaitForDaemon exercises the bounded reattach poll: it returns true once the
// injected dialer succeeds, and false when the cap elapses with no daemon.
func TestWaitForDaemon(t *testing.T) {
	t.Run("returns when daemon comes back", func(t *testing.T) {
		var calls int
		dial := func(string) (net.Conn, error) {
			calls++
			if calls >= 3 {
				c, _ := net.Pipe()
				return c, nil
			}
			return nil, errors.New("refused")
		}
		if !waitForDaemon(context.Background(), "/x.sock", 5*time.Second, dial) {
			t.Fatal("expected waitForDaemon to succeed once the dialer returns a conn")
		}
	})
	t.Run("gives up at the cap", func(t *testing.T) {
		dial := func(string) (net.Conn, error) { return nil, errors.New("refused") }
		start := time.Now()
		if waitForDaemon(context.Background(), "/x.sock", 300*time.Millisecond, dial) {
			t.Fatal("expected waitForDaemon to give up when the daemon never returns")
		}
		if time.Since(start) > 3*time.Second {
			t.Fatalf("waitForDaemon overshot its cap badly: %s", time.Since(start))
		}
	})
	t.Run("aborts immediately on ctx cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		dial := func(string) (net.Conn, error) { return nil, errors.New("refused") }
		if waitForDaemon(ctx, "/x.sock", 60*time.Second, dial) {
			t.Fatal("a canceled ctx must make waitForDaemon return false immediately")
		}
	})
}

// TestResumableSessionSet is the rediscovery gate: only KindAttach runs with NO
// recorded end AND a correlated session id are auto-resumable-by-restart. A run
// that recorded its end (child-exit) is excluded; a death-orphaned run is
// included; non-attach and uncorrelated runs are excluded.
func TestResumableSessionSet(t *testing.T) {
	ended := time.Now().UTC()
	runs := []store.TerminalRunSummary{
		// (1) crash-orphaned attach (no reason, no end), correlated → RESUMABLE.
		// Tool is a ResumeNative tool (claude-code) so the capability gate admits
		// it (attach-all-launchers §3 — only natively-resumable tools are offered).
		{RunID: "r1", Tool: "claude-code", Kind: string(termrun.KindAttach), EndedAt: nil, BestSessionID: "sess-orphan"},
		// (2) attach that recorded a natural child-exit → NOT resumable.
		{RunID: "r2", Tool: "claude-code", Kind: string(termrun.KindAttach), EndedAt: &ended, EndReason: store.EndReasonChildExit, BestSessionID: "sess-exited"},
		// (3) attach, no correlation yet → nothing to resume.
		{RunID: "r3", Kind: string(termrun.KindAttach), EndedAt: nil, BestSessionID: ""},
		// (4) a non-attach kind (fresh) orphan → not an attach, excluded.
		{RunID: "r4", Kind: string(termrun.KindFresh), EndedAt: nil, BestSessionID: "sess-fresh"},
		// (5) a resume-kind orphan → excluded (only KindAttach is auto-resumable).
		{RunID: "r5", Kind: string(termrun.KindResume), EndedAt: nil, BestSessionID: "sess-resume"},
		// (6) graceful-shutdown orphan whose racing OnExit ALSO set ended_at:
		//     the durable reason makes it RESUMABLE despite ended_at != nil (H2).
		{RunID: "r6", Tool: "claude-code", Kind: string(termrun.KindAttach), EndedAt: &ended, EndReason: store.EndReasonDaemonShutdown, BestSessionID: "sess-shutdown"},
		// (7) an already-superseded orphan (resumed) → NEVER re-offer, even
		//     though ended_at is nil (H2).
		{RunID: "r7", Tool: "claude-code", Kind: string(termrun.KindAttach), EndedAt: nil, EndReason: store.EndReasonResumed, BestSessionID: "sess-resumed"},
		// (8)+(9) TWO eligible orphans for the SAME session (a historical
		//     duplicate / a prior stamp failure): both must be collected, newest
		//     first, so a successful resume supersedes ALL of them (round-4
		//     multi-orphan finding). Input is newest-first, so r8 precedes r9.
		{RunID: "r8", Tool: "claude-code", Kind: string(termrun.KindAttach), EndedAt: nil, BestSessionID: "sess-multi"},
		{RunID: "r9", Tool: "claude-code", Kind: string(termrun.KindAttach), EndedAt: &ended, EndReason: store.EndReasonDaemonShutdown, BestSessionID: "sess-multi"},
		// (10) a resume-kind run the FIX-2 sibling sweep stamped 'daemon_shutdown'
		//      at graceful shutdown. Offerability is UNAFFECTED: the resume-offer
		//      gate is kind='attach'-scoped, so a non-attach run carrying the same
		//      resumable reason is STILL excluded — the sibling hygiene stamp never
		//      leaks a non-attach run into the auto-resume set.
		{RunID: "r10", Kind: string(termrun.KindResume), EndedAt: nil, EndReason: store.EndReasonDaemonShutdown, BestSessionID: "sess-resume-shutdown"},
	}
	set := resumableSessionSet(runs)
	// Each resumable session maps to the LIST of its eligible PREDECESSOR run ids
	// (used by the supersede-by-run-ids stamp), newest first.
	for sess, wantRuns := range map[string][]string{
		"sess-orphan":   {"r1"},
		"sess-shutdown": {"r6"},
		"sess-multi":    {"r8", "r9"}, // BOTH eligible orphans, newest first
	} {
		got := set[sess]
		if len(got) != len(wantRuns) {
			t.Errorf("session %q predecessors = %v, want %v", sess, got, wantRuns)
			continue
		}
		for i := range wantRuns {
			if got[i] != wantRuns[i] {
				t.Errorf("session %q predecessor[%d] = %q, want %q (got %v)", sess, i, got[i], wantRuns[i], got)
			}
		}
	}
	for _, no := range []string{"sess-exited", "sess-fresh", "sess-resume", "sess-resumed", "sess-resume-shutdown", ""} {
		if _, ok := set[no]; ok {
			t.Errorf("session %q must NOT be resumable-by-restart", no)
		}
	}
	if len(set) != 3 {
		t.Fatalf("resumable set = %v, want exactly {sess-orphan, sess-shutdown, sess-multi}", set)
	}
}

// TestResumableSessionSetSkipsResumeNoneTools pins the attach-all-launchers §3
// capability gate: a KindAttach orphan with a correlated session id is offered
// for auto-resume ONLY when its tool grounds native resume. A ResumeNone tool
// (openclaw — attachable/launchable but with no non-interactive resume surface
// grounded) is excluded even though its run is a correlated crash orphan, so
// the daemon never composes a `--resume` its inner launcher can't parse. A
// ResumeNative tool (claude-code) in the same shape is still offered.
//
// The ResumeNone fixture was cursor until 2026-07-25, when cursor's native
// `--resume <chatId>` was live-confirmed and promoted to ResumeNative.
func TestResumableSessionSetSkipsResumeNoneTools(t *testing.T) {
	// Sanity-pin the fixture's capability assumptions so this test fails loudly
	// if the registry grounding ever changes underneath it.
	if c, _ := integration.For("openclaw"); c.Resume.Kind == integration.ResumeNative {
		t.Fatal("fixture assumes openclaw is ResumeNone")
	}
	if c, _ := integration.For("claude-code"); c.Resume.Kind != integration.ResumeNative {
		t.Fatal("fixture assumes claude-code is ResumeNative")
	}
	runs := []store.TerminalRunSummary{
		// ResumeNone tool, correlated crash orphan → EXCLUDED by the gate.
		{RunID: "cu1", Tool: "openclaw", Kind: string(termrun.KindAttach), EndedAt: nil, BestSessionID: "sess-openclaw"},
		// ResumeNative tool, same shape → INCLUDED.
		{RunID: "cc1", Tool: "claude-code", Kind: string(termrun.KindAttach), EndedAt: nil, BestSessionID: "sess-claude"},
		// A tool with no registry row at all → EXCLUDED (For returns ok=false).
		{RunID: "zz1", Tool: "not-a-real-tool", Kind: string(termrun.KindAttach), EndedAt: nil, BestSessionID: "sess-unknown"},
	}
	set := resumableSessionSet(runs)
	if _, ok := set["sess-openclaw"]; ok {
		t.Error("a ResumeNone tool's orphan must NOT be auto-resumable")
	}
	if _, ok := set["sess-unknown"]; ok {
		t.Error("an unknown tool's orphan must NOT be auto-resumable")
	}
	if got := set["sess-claude"]; len(got) != 1 || got[0] != "cc1" {
		t.Errorf("claude-code orphan = %v, want [cc1]", got)
	}
	if len(set) != 1 {
		t.Fatalf("resumable set = %v, want exactly {sess-claude}", set)
	}
}

// TestValidateAttachCapabilityRejectsResumeForResumeNone pins the daemon-side
// defense in depth (attach-all-launchers §3): an untrusted socket spawn that
// carries a ResumeSession for a ResumeNone tool is refused BEFORE launch, so a
// spoofed AutoResume/ResumeSession can't drive the daemon to compose a
// `--resume` argv the inner launcher can't parse. A non-resume spawn for the
// same tool passes; a resume spawn for a ResumeNative tool passes.
func TestValidateAttachCapabilityRejectsResumeForResumeNone(t *testing.T) {
	// A ResumeNone tool with a resume request → refused.
	err := validateAttachCapability(attachsock.SpawnRequest{
		Tool: "openclaw", Subcommand: "openclaw", ResumeSession: "sess-x",
	})
	if err == nil || !strings.Contains(err.Error(), "no native resume capability") {
		t.Fatalf("resume spawn for a ResumeNone tool err = %v, want a no-native-resume rejection", err)
	}
	// The SAME tool WITHOUT a resume request → allowed (plain attach is fine).
	if err := validateAttachCapability(attachsock.SpawnRequest{
		Tool: "openclaw", Subcommand: "openclaw",
	}); err != nil {
		t.Fatalf("plain (non-resume) attach for a ResumeNone tool must pass, got %v", err)
	}
	// A ResumeNative tool WITH a resume request → allowed.
	if err := validateAttachCapability(attachsock.SpawnRequest{
		Tool: "claude-code", Subcommand: "claude", ResumeSession: "sess-y",
	}); err != nil {
		t.Fatalf("resume spawn for a ResumeNative tool must pass, got %v", err)
	}
}

// TestNativeResumeHintResumeNoneMentionsContinueFrom pins the honest
// degraded-mortality copy (attach-all-launchers §3): for a launchable ResumeNone
// tool the daemon-exit hint points at the manual `observer <verb> --continue-from`
// handover fork (the real mortality backstop), not a native-resume command the
// tool doesn't have. A ResumeNative tool still gets its native `--resume` hint.
func TestNativeResumeHintResumeNoneMentionsContinueFrom(t *testing.T) {
	// openclaw: launchable, ResumeNone → the --continue-from degraded hint,
	// naming its launch verb. (Was cursor until 2026-07-25, when cursor's
	// native `--resume <chatId>` was live-confirmed → ResumeNative.)
	oc, _ := integration.For("openclaw")
	got := nativeResumeHint(oc)
	if !strings.Contains(got, "--continue-from") || !strings.Contains(got, "observer openclaw") {
		t.Errorf("openclaw hint = %q, want it to mention `observer openclaw --continue-from`", got)
	}
	// claude-code: ResumeNative → the native --resume hint, NOT --continue-from.
	cc, _ := integration.For("claude-code")
	got = nativeResumeHint(cc)
	if !strings.Contains(got, "--resume") || strings.Contains(got, "--continue-from") {
		t.Errorf("claude-code hint = %q, want a native `--resume` hint", got)
	}
}

// TestAttachHubExitBeforeRegistration is finding-3 case (a) at the STATE-MACHINE
// level: a run whose exit is signalled (via the DIRECT NotifyExit seam) BEFORE
// the post-spawn reserve/releaseOnExit registration must NOT leave a stuck-live
// session or a parked (never-fired) flock release. The exit tombstone makes
// reserve skip recreating liveness and releaseOnExit fire immediately, so the
// flock is released, sessionLive is false, and a subsequent resume can proceed.
// It drives NotifyExit directly (the real producer entry point). That the
// PRODUCER actually reaches NotifyExit on a fast child exit — even when the
// pre-registration gap means no term:exit is ever produced — is proven
// end-to-end by TestAttachHubExitReconciledThroughProducer.
func TestAttachHubExitBeforeRegistration(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	const sid, run = "sess-fast", "run-fast"
	// Exit lands first (no live entry) → records a tombstone.
	hub.NotifyExit(run)
	// Post-spawn reserve arrives AFTER the exit: must not recreate liveness.
	hub.reserve(sid, run)
	if hub.sessionLive(sid) {
		t.Fatal("reserve after a raced exit must not mark the session live")
	}
	// Post-spawn releaseOnExit arrives AFTER the exit: must fire immediately.
	released := false
	hub.releaseOnExit(run, func() { released = true })
	if !released {
		t.Fatal("releaseOnExit after a raced exit must fire the flock release immediately")
	}
	// A subsequent resume of the same session sees it free.
	if hub.sessionLive(sid) {
		t.Fatal("session must be free for a subsequent resume after the raced exit")
	}
}

// TestAttachHubExitAfterRegistration is finding-3 case (b): the NORMAL ordering
// (reserve + releaseOnExit before the exit) is unchanged — the callback PARKS
// while the run is live and fires on the real exit, which also clears liveness.
func TestAttachHubExitAfterRegistration(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	const sid, run = "sess-normal", "run-normal"
	hub.reserve(sid, run)
	if !hub.sessionLive(sid) {
		t.Fatal("reserve must mark the session live")
	}
	fired := false
	hub.releaseOnExit(run, func() { fired = true })
	if fired {
		t.Fatal("releaseOnExit must PARK while the run is live, not fire early")
	}
	hub.NotifyExit(run)
	if !fired {
		t.Fatal("the real exit must fire the parked flock release")
	}
	if hub.sessionLive(sid) {
		t.Fatal("the real exit must clear liveness")
	}
}

// TestAttachHubTombstoneDoesNotLeakAcrossRuns is finding-3 case (c): a
// predecessor run's exit tombstone must NOT confuse a DISTINCT next run of the
// SAME session (tombstones are keyed by run id, unique per spawn). The new run
// reserves liveness normally and its releaseOnExit parks.
func TestAttachHubTombstoneDoesNotLeakAcrossRuns(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	const sid = "sess-shared"
	// Predecessor run raced its exit → tombstone for run-old.
	hub.NotifyExit("run-old")
	// A fresh resume of the SAME session with a DISTINCT run id must reserve
	// liveness normally despite the predecessor's tombstone.
	hub.reserve(sid, "run-new")
	if !hub.sessionLive(sid) {
		t.Fatal("a distinct new run must mark the session live despite a predecessor's tombstone")
	}
	fired := false
	hub.releaseOnExit("run-new", func() { fired = true })
	if fired {
		t.Fatal("the new run's releaseOnExit must park (the run is live), not fire on the predecessor's tombstone")
	}
}

// exitedPTY is a fake PTY whose child has ALREADY exited: Wait returns
// immediately and Read is at EOF. Driven through the REAL termsession.Manager it
// reproduces the fast-exit / pre-registration race that the reconcile closes.
type exitedPTY struct{}

func (exitedPTY) Read([]byte) (int, error)    { return 0, io.EOF }
func (exitedPTY) Write(b []byte) (int, error) { return len(b), nil }
func (exitedPTY) Resize(uint16, uint16) error { return nil }
func (exitedPTY) Wait() (int, error)          { return 0, nil }
func (exitedPTY) Close() error                { return nil }
func (exitedPTY) Kill() error                 { return nil }

type exitedSpawner struct{}

func (exitedSpawner) Spawn(termsession.Spec) (termsession.PTY, error) { return exitedPTY{}, nil }

// TestAttachHubExitReconciledThroughProducer is the round-4 REAL-PRODUCER proof
// the reviewer asked for: it wires the SAME pieces `observer start` assembles — a
// real termsession.Manager (over a child that exits immediately), a real
// termsvc.Service with ExitStatus + OnRunExit=hub.NotifyExit, and the hub — then
// spawns and lets the PRODUCER drive the exit. No test code calls NotifyExit. The
// hub must clear liveness and fire the parked flock release off the direct seam,
// even though the child exits so fast that the pre-registration gap can mean no
// term:exit is ever produced (the reconcile inside launch() is the backstop).
func TestAttachHubExitReconciledThroughProducer(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	var svc *termsvc.Service
	mgr := termsession.NewManager(termsession.Options{
		Spawner:      exitedSpawner{},
		ReapInterval: time.Hour, // don't reap under us during the assertion
		Now:          time.Now,
		// Production OnExit wiring: the daemon-observed exit funnels through
		// EndRunByHandle (which fires OnRunExit). Whichever of this and the
		// launch() reconcile wins the race, the exit is recorded exactly once.
		OnExit: func(se termsession.SessionExit) {
			svc.EndRunByHandle(context.Background(), se.Handle, se.ExitCode)
		},
	})
	t.Cleanup(mgr.Shutdown)

	launcher := &ptyLauncher{mgr: mgr, binPath: "observer"}
	svc = termsvc.New(termsvc.Options{
		Recorder:   assembledRecorder{}, // no-op store (defined in the assembled test)
		Launcher:   launcher,
		Feed:       feed,
		ExitStatus: mgr.ExitStatus,
		OnRunExit:  hub.NotifyExit,
	})

	res, err := svc.LaunchAttachable(context.Background(), termsvc.AttachRequest{
		Tool: "claude-code", Subcommand: "claude",
	})
	if err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}

	// Register the hub state exactly as attachHost does post-spawn: reserve the
	// resume target live, then park the flock release on the run's true exit.
	const sid = "sess-producer"
	hub.reserve(sid, res.RunID)
	released := make(chan struct{}, 1)
	hub.releaseOnExit(res.RunID, func() { released <- struct{}{} })

	// The producer's exit (reconcile and/or OnExit → NotifyExit) must clear the
	// live view and release the parked flock — with NO manual NotifyExit call.
	pollUntil(t, "producer clears liveness via NotifyExit", func() bool { return !hub.sessionLive(sid) })
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("the producer's exit never released the parked flock via the direct seam")
	}
}

// TestAttachHostSupersedesAllSessionOrphans is the round-4 multi-orphan stamp
// flow (finding 3): a successful auto-resume must stamp ALL of the session's
// startup-eligible predecessor orphans, and must GUARD OUT the fresh replacement
// run's own id (which cannot be a startup orphan but must never be superseded).
func TestAttachHostSupersedesAllSessionOrphans(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	resumable := func(string) bool { return true }
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R-new"}}

	var stamped []string
	supersede := func(ids []string) { stamped = append(stamped, ids...) }
	// The resolver returns the fresh run's own id alongside the two real
	// predecessors, to prove the call-site guard filters it out.
	predecessors := func(sid string) ([]string, bool) {
		if sid == "sess-multi" {
			return []string{"R-new", "R1", "R2"}, true
		}
		return nil, false
	}
	host := newAttachHost(launcher, successAttachMgr{}, nil).
		withResume(hub, resumable).
		withDurableResume("", supersede, predecessors) // attachDir="" → no flock

	if _, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{
		Tool: "claude-code", Subcommand: "claude",
		ResumeSession: "sess-multi", AutoResume: true,
	}); err != nil {
		t.Fatalf("LaunchAttachable: %v", err)
	}

	// Both real predecessors stamped; the fresh run's id (R-new) guarded out.
	want := map[string]bool{"R1": true, "R2": true}
	if len(stamped) != 2 {
		t.Fatalf("stamped = %v, want exactly {R1, R2} (R-new must be guarded out)", stamped)
	}
	for _, id := range stamped {
		if !want[id] {
			t.Fatalf("stamped unexpected id %q (want only R1, R2)", id)
		}
	}
}

func pollUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestAttachHubCorrelationDelivery verifies the hub delivers a run's established
// correlation to a registered listener and tracks the session as live off the
// SAME feed the Service publishes on — while ABSTAINING on a below-threshold
// (heuristic) correlation.
func TestAttachHubCorrelationDelivery(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	ch := hub.register("R1")

	// A weak heuristic correlation must be ABSTAINED (no delivery, not live).
	feed.Publish(termfeed.Event{Kind: correlateKindPrefix + string(termrun.SourceHeuristic), RunID: "R1", SessionID: "sess-weak", At: time.Now()})
	select {
	case c := <-ch:
		t.Fatalf("a heuristic correlation must not be delivered as a resume target, got %+v", c)
	case <-time.After(150 * time.Millisecond):
	}
	if hub.sessionLive("sess-weak") {
		t.Fatal("a below-threshold correlation must not mark a session live")
	}

	// An OOB correlation is established → delivered + live.
	feed.Publish(termfeed.Event{Kind: correlateKindPrefix + string(termrun.SourceOOB), RunID: "R1", SessionID: "sess-real", At: time.Now()})
	select {
	case c := <-ch:
		if c.SessionID != "sess-real" || c.Source != string(termrun.SourceOOB) {
			t.Fatalf("delivered %+v, want sess-real/oob", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("established correlation never delivered to the listener")
	}
	pollUntil(t, "sess-real live", func() bool { return hub.sessionLive("sess-real") })

	// Exit clears liveness — via the DIRECT NotifyExit seam, NOT the feed (round-4
	// moved correctness off the lossy feed). A term:exit PUBLISHED on the feed is
	// now deliberately ignored by the hub; the guarantee below is that NotifyExit
	// (which the producer fires from EndRunByHandle) clears the live view.
	feed.Publish(termfeed.Event{Kind: exitKind, RunID: "R1", At: time.Now()})
	if !hub.sessionLive("sess-real") {
		t.Fatal("a feed-published term:exit must NOT clear liveness — correctness rides NotifyExit, not the feed")
	}
	hub.NotifyExit("R1")
	if hub.sessionLive("sess-real") {
		t.Fatal("NotifyExit must clear the session's live view")
	}
}

// TestAttachHostAutoResumeRejectsNonOrphan verifies the AUTO-resume orphan
// validation gate: a daemon-death auto-resume of a session the daemon did NOT
// rediscover as an orphan is refused with ErrResumeNotResumable, before any
// spawn.
func TestAttachHostAutoResumeRejectsNonOrphan(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	resumable := func(id string) bool { return id == "sess-orphan" }
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R"}}
	host := newAttachHost(launcher, successAttachMgr{}, nil).withResume(hub, resumable)

	_, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{
		Tool: "claude-code", Subcommand: "claude",
		ResumeSession: "sess-not-orphan", AutoResume: true,
	})
	if !errors.Is(err, attachsock.ErrResumeNotResumable) {
		t.Fatalf("err = %v, want ErrResumeNotResumable", err)
	}
	// L8: the orphan-validation refusal must happen BEFORE any spawn — assert
	// ZERO LaunchAttachable calls, not merely an absence of recorded exits.
	if n := launcher.launches(); n != 0 {
		t.Fatalf("orphan-validation refusal performed %d LaunchAttachable calls, want 0", n)
	}

	// A valid orphan target passes the gate and spawns.
	if _, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{
		Tool: "claude-code", Subcommand: "claude",
		ResumeSession: "sess-orphan", AutoResume: true,
	}); err != nil {
		t.Fatalf("valid orphan resume err = %v, want nil", err)
	}
}

// TestAttachHostDoubleSpawnGuard verifies the double-spawn guard: when a run is
// already live for the resume target (the operator separately relaunched it), a
// resume of the same session id is refused with ErrResumeConflict rather than
// spawning a duplicate.
func TestAttachHostDoubleSpawnGuard(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	// A concurrent run has already correlated to sess-live (via the feed).
	feed.Publish(termfeed.Event{Kind: correlateKindPrefix + string(termrun.SourceOOB), RunID: "other-run", SessionID: "sess-live", At: time.Now()})
	pollUntil(t, "sess-live becomes live", func() bool { return hub.sessionLive("sess-live") })

	resumable := func(string) bool { return true }
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R"}}
	host := newAttachHost(launcher, successAttachMgr{}, nil).withResume(hub, resumable)

	_, err := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{
		Tool: "claude-code", Subcommand: "claude",
		ResumeSession: "sess-live", AutoResume: true,
	})
	if !errors.Is(err, attachsock.ErrResumeConflict) {
		t.Fatalf("err = %v, want ErrResumeConflict (double-spawn guard)", err)
	}
}

// TestAttachHostResumeSingleFlight is the L8 direct concurrency guard: two
// simultaneous resume requests for the SAME session must serialize through the
// per-session single-flight gate so exactly ONE spawns and the other is refused
// with ErrResumeConflict (never two duplicate spawns of one session). Uses the
// in-memory hub guard only (attachDir unset → no flock), which is exactly the
// single-flight path under test.
func TestAttachHostResumeSingleFlight(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	resumable := func(string) bool { return true }
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R"}}
	host := newAttachHost(launcher, successAttachMgr{}, nil).withResume(hub, resumable)

	const sid = "sess-race"
	var wg sync.WaitGroup
	errs := make([]error, 2)
	start := make(chan struct{})
	for i := range errs {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // release both goroutines as simultaneously as possible
			_, e := host.LaunchAttachable(context.Background(), attachsock.SpawnRequest{
				Tool: "claude-code", Subcommand: "claude",
				ResumeSession: sid, AutoResume: true,
			})
			errs[idx] = e
		}(i)
	}
	close(start)
	wg.Wait()

	// Exactly one success + one ErrResumeConflict.
	conflicts, oks := 0, 0
	for _, e := range errs {
		switch {
		case e == nil:
			oks++
		case errors.Is(e, attachsock.ErrResumeConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error from concurrent resume: %v", e)
		}
	}
	if oks != 1 || conflicts != 1 {
		t.Fatalf("concurrent resume outcomes = {ok:%d conflict:%d}, want {1,1}", oks, conflicts)
	}
	// And exactly ONE spawn ever reached the launcher.
	if n := launcher.launches(); n != 1 {
		t.Fatalf("launcher saw %d spawns, want exactly 1 (single-flight)", n)
	}
}

// TestAttachHostResumeRefusedByStoreAuthority is the round-5 finding-1 fix: a
// dashboard-style run — correlated + PERSISTED into terminal_run_session, LIVE
// (ended_at NULL), but NEVER seen by the attach hub (no feed event, so
// sessionLive is false) — must still block an attach resume of that session. The
// durable store authority (LiveRunForSession) catches it, so the resume is
// REFUSED with ErrResumeConflict rather than duplicating the session. Exercises
// the real store SQL + the host wiring together.
func TestAttachHostResumeRefusedByStoreAuthority(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "authority.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)

	const sid = "sess-dashboard"
	// A live dashboard resume (kind='resume', ended_at NULL) correlated to the
	// session at OOB confidence — persisted, exactly as termsvc.Correlate writes it.
	if err := st.InsertTerminalRun(ctx, store.TerminalRun{RunID: "R-dash", Tool: "claude-code", Kind: "resume"}); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}
	if err := st.UpsertCorrelation(ctx, store.TerminalCorrelation{RunID: "R-dash", SessionID: sid, Confidence: 0.95, Source: "oob"}); err != nil {
		t.Fatalf("UpsertCorrelation: %v", err)
	}

	// The hub NEVER learns about R-dash (no feed event) — the in-memory guard is blind.
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)
	if hub.sessionLive(sid) {
		t.Fatal("precondition: the attach hub must not know about the dashboard run")
	}

	// The authority is the SAME closure buildTerminalStack wires: a real
	// LiveRunForSessionExcluding over the store, gated at MinLinkConfidence.
	authority := func(sessionID string, excludeRunIDs []string) bool {
		live, qerr := st.LiveRunForSessionExcluding(ctx, sessionID, termrun.MinLinkConfidence, excludeRunIDs)
		if qerr != nil {
			t.Fatalf("LiveRunForSessionExcluding: %v", qerr)
		}
		return live
	}

	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R-attach"}}
	host := newAttachHost(launcher, successAttachMgr{}, nil).
		withResume(hub, func(string) bool { return true }). // orphan-validation passes
		withResumeAuthority(authority)

	_, err = host.LaunchAttachable(ctx, attachsock.SpawnRequest{
		Tool: "claude-code", Subcommand: "claude",
		ResumeSession: sid, AutoResume: true,
	})
	if !errors.Is(err, attachsock.ErrResumeConflict) {
		t.Fatalf("err = %v, want ErrResumeConflict (store authority must catch the persisted live run the hub never saw)", err)
	}
	// The refusal must precede any spawn — never a duplicate.
	if n := launcher.launches(); n != 0 {
		t.Fatalf("store-authority refusal performed %d spawns, want 0", n)
	}
}

// TestAttachHubNotifyExitTombstonesTrackedRun is the round-5 finding-2 fix: a run
// that was RESERVED (tracked live) and then exits via NotifyExit must be
// tombstoned so a STALE correlation event still queued in the lossy feed
// (processed by onCorrelate AFTER the exit) cannot resurrect its liveness
// permanently. Ordering: reserve → NotifyExit → late onCorrelate → liveness stays
// false, and a subsequent resume of that session (a distinct run id) succeeds.
func TestAttachHubNotifyExitTombstonesTrackedRun(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	const sid, run = "sess-stale", "run-stale"
	hub.reserve(sid, run)
	if !hub.sessionLive(sid) {
		t.Fatal("reserve must mark the tracked run's session live")
	}
	// The run exits (its correlation event is STILL queued in the lossy feed).
	hub.NotifyExit(run)
	if hub.sessionLive(sid) {
		t.Fatal("NotifyExit must clear the tracked run's liveness")
	}
	// The stale correlation now lands, exactly as onCorrelate would process it off
	// the feed — it must NOT resurrect liveness (the tombstone catches it).
	hub.onCorrelate(run, sid, string(termrun.SourceOOB), 0.95)
	if hub.sessionLive(sid) {
		t.Fatal("a late correlation after NotifyExit must not resurrect a TRACKED run's liveness (round-5 finding 2)")
	}
	// A subsequent resume of the same session (distinct run id) sees it free.
	hub.reserve(sid, "run-fresh")
	if !hub.sessionLive(sid) {
		t.Fatal("a subsequent resume of the session must succeed after the tombstoned exit")
	}
}

// storeAuthorityFor builds the SAME durable authority + predecessor resolver
// buildTerminalStack wires: LiveRunForSessionExcluding gated at MinLinkConfidence,
// and a rediscovery map from session id → predecessor run ids.
func storeAuthorityFor(t *testing.T, ctx context.Context, st *store.Store, redisc map[string][]string) (func(string, []string) bool, func(string) ([]string, bool)) {
	t.Helper()
	authority := func(sessionID string, excludeRunIDs []string) bool {
		live, qerr := st.LiveRunForSessionExcluding(ctx, sessionID, termrun.MinLinkConfidence, excludeRunIDs)
		if qerr != nil {
			t.Fatalf("LiveRunForSessionExcluding: %v", qerr)
		}
		return live
	}
	predecessors := func(s string) ([]string, bool) {
		ids := redisc[s]
		return ids, len(ids) > 0
	}
	return authority, predecessors
}

// TestAttachHostAutoResumeSucceedsForCrashOrphan is review finding-1 (t1): the
// rediscovery→auto-resume flow must NOT self-block. A rediscovered crash orphan
// (end_reason=” + ended_at NULL, correlated) is the predecessor rediscovery
// offers; the durable authority would otherwise match that very row and refuse
// the resume as a conflict. Excluding the predecessor run id lets the resume
// SUCCEED with exactly one spawn.
func TestAttachHostAutoResumeSucceedsForCrashOrphan(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "crash.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)

	const sid, pred = "sess-crash", "R-pred"
	// A crash orphan: kind='attach', end_reason='' (never stamped), ended_at NULL,
	// correlated at OOB confidence — exactly what rediscovery offers.
	if err := st.InsertTerminalRun(ctx, store.TerminalRun{RunID: pred, Tool: "claude-code", Kind: "attach"}); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}
	if err := st.UpsertCorrelation(ctx, store.TerminalCorrelation{RunID: pred, SessionID: sid, Confidence: 0.95, Source: "oob"}); err != nil {
		t.Fatalf("UpsertCorrelation: %v", err)
	}

	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	authority, predecessors := storeAuthorityFor(t, ctx, st, map[string][]string{sid: {pred}})
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R-fresh"}}
	host := newAttachHost(launcher, successAttachMgr{}, nil).
		withResume(hub, func(string) bool { return true }).     // orphan-validation passes
		withDurableResume("", func([]string) {}, predecessors). // no flock; predecessors wired
		withResumeAuthority(authority)

	if _, err := host.LaunchAttachable(ctx, attachsock.SpawnRequest{
		Tool: "claude-code", Subcommand: "claude",
		ResumeSession: sid, AutoResume: true,
	}); err != nil {
		t.Fatalf("auto-resume of a rediscovered crash orphan must SUCCEED, got %v", err)
	}
	if n := launcher.launches(); n != 1 {
		t.Fatalf("crash-orphan auto-resume performed %d spawns, want exactly 1", n)
	}
}

// TestAttachHostAutoResumeRefusedWhenDistinctLiveRunPresent is review finding-1
// (t2): excluding the predecessor must NOT blind the authority to a GENUINELY
// distinct live run for the same session (a dashboard resume). With the
// predecessor excluded but the dashboard run still live + correlated, the resume
// is REFUSED with ErrResumeConflict and never spawns.
func TestAttachHostAutoResumeRefusedWhenDistinctLiveRunPresent(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "distinct.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)

	const sid, pred, dash = "sess-crash", "R-pred", "R-dash"
	// The rediscovered crash-orphan predecessor.
	if err := st.InsertTerminalRun(ctx, store.TerminalRun{RunID: pred, Tool: "claude-code", Kind: "attach"}); err != nil {
		t.Fatalf("InsertTerminalRun pred: %v", err)
	}
	if err := st.UpsertCorrelation(ctx, store.TerminalCorrelation{RunID: pred, SessionID: sid, Confidence: 0.95, Source: "oob"}); err != nil {
		t.Fatalf("UpsertCorrelation pred: %v", err)
	}
	// A DISTINCT genuinely-live run for the SAME session (a dashboard resume),
	// NOT in the predecessor set: kind='resume', end_reason='', ended_at NULL.
	if err := st.InsertTerminalRun(ctx, store.TerminalRun{RunID: dash, Tool: "claude-code", Kind: "resume"}); err != nil {
		t.Fatalf("InsertTerminalRun dash: %v", err)
	}
	if err := st.UpsertCorrelation(ctx, store.TerminalCorrelation{RunID: dash, SessionID: sid, Confidence: 0.95, Source: "oob"}); err != nil {
		t.Fatalf("UpsertCorrelation dash: %v", err)
	}

	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	authority, predecessors := storeAuthorityFor(t, ctx, st, map[string][]string{sid: {pred}})
	launcher := &fakeAttachLauncher{res: termsvc.LaunchResult{Handle: "H", RunID: "R-fresh"}}
	host := newAttachHost(launcher, successAttachMgr{}, nil).
		withResume(hub, func(string) bool { return true }).
		withDurableResume("", func([]string) {}, predecessors).
		withResumeAuthority(authority)

	_, err = host.LaunchAttachable(ctx, attachsock.SpawnRequest{
		Tool: "claude-code", Subcommand: "claude",
		ResumeSession: sid, AutoResume: true,
	})
	if !errors.Is(err, attachsock.ErrResumeConflict) {
		t.Fatalf("err = %v, want ErrResumeConflict (a distinct live run must still conflict even with the predecessor excluded)", err)
	}
	if n := launcher.launches(); n != 0 {
		t.Fatalf("distinct-live-run refusal performed %d spawns, want 0", n)
	}
}

// TestAttachHubYoungTombstoneSurvivesFloodBeforePin is the round-7 finding-1 fix,
// exercised in the PRODUCTION ordering the reviewer flagged: termsvc reconciles a
// fast child exit and calls NotifyExit (writing the tombstone) BEFORE the attach
// host's pinTombstone runs. So the tombstone is created UNPINNED, and a flood of
// >bound OTHER exits can arrive in the pre-pin descheduling gap. Only the AGE
// FLOOR (tombstoneMinAge) — not the pin — protects the just-written tombstone
// through that window.
//
// Round-8 finding 2 (mutation-sensitivity): the ORIGINAL version of this test
// created every flood entry BEFORE the target, so the target was always the
// single NEWEST entry in the map — oldest-first shedding spares the newest entry
// regardless of whether the age floor exists at all, so the test passed even with
// tombstoneMinAge deleted (verified locally: deleting the floor check did NOT
// fail the old body). This version follows the reviewer's recipe so the floor is
// actually load-bearing:
//  1. seed exitTombstoneBound tombstones, then age them PAST the floor (genuinely
//     evictable) via the nowFunc clock seam;
//  2. create the young target via NotifyExit — the production path, not
//     pre-pinned — at the now-aged clock, so it is younger than every seed entry;
//  3. inject exitTombstoneBound MORE exits that are NEWER than the target (created
//     after it) but themselves still YOUNG (no further clock advance).
//
// Oldest-first draining consumes the aged seed entries first. Once those run out,
// WITHOUT the age floor the next-oldest candidate is the target itself (it
// predates every new-flood entry, so it's next in line) and gets evicted. WITH
// the floor, the target and every new-flood entry are all too young to be
// eligible, so shedding stalls (a transient overshoot of exactly one entry) and
// the target survives. Confirmed locally: temporarily deleting the
// `now.Sub(at) < tombstoneMinAge` guard in shedTombstonesLocked makes this test
// FAIL (target evicted, len(exited) drops back to exitTombstoneBound); restoring
// the guard makes it PASS.
func TestAttachHubYoungTombstoneSurvivesFloodBeforePin(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	base := time.Now()
	var clock time.Time
	clock = base
	hub.mu.Lock()
	hub.nowFunc = func() time.Time { return clock }
	hub.mu.Unlock()

	const sid, run = "sess-young", "run-young"

	// 1. Seed exitTombstoneBound OLD tombstones, then age the whole seed past the
	// floor — genuinely evictable by the time the target is written.
	for i := 0; i < exitTombstoneBound; i++ {
		hub.NotifyExit(fmt.Sprintf("seed-%d", i))
	}
	clock = base.Add(2 * tombstoneMinAge)

	// 2. Create the young target via the production path (NotifyExit, not
	// pre-pinned) at the now-aged clock — younger than every seed entry.
	hub.NotifyExit(run)

	// 3. Inject exitTombstoneBound MORE exits, newer than the target (inserted
	// after it) but still young themselves (no further clock advance). Once the
	// aged seed is exhausted, oldest-first draining would next reach for the
	// target if the age floor did not protect it.
	for i := 0; i < exitTombstoneBound; i++ {
		hub.NotifyExit(fmt.Sprintf("new-flood-%d", i))
	}

	hub.mu.Lock()
	_, alive := hub.exited[run]
	sz := len(hub.exited)
	hub.mu.Unlock()
	if !alive {
		t.Fatal("young unpinned tombstone was evicted after the aged seed was exhausted (finding 1 regression: age floor not load-bearing)")
	}
	// All exitTombstoneBound aged seed entries drain (oldest-first, all eligible);
	// the target and the exitTombstoneBound new-flood entries are all too young to
	// be shed, so the map stabilizes one entry above the bound (the last new-flood
	// insertion that found no eligible candidate left to evict).
	if want := exitTombstoneBound + 1; sz != want {
		t.Fatalf("len(exited)=%d, want %d (aged seed fully drained, target + new flood all too young to shed)", sz, want)
	}

	// The pin lands AFTER (as LaunchAttachable does once the run id exists).
	hub.pinTombstone(run)
	// Post-spawn registration: reserve must NOT recreate liveness (tombstone
	// present), releaseOnExit must fire the flock release immediately.
	hub.reserve(sid, run)
	if hub.sessionLive(sid) {
		t.Fatal("reserve after a raced exit must not recreate liveness (young tombstone survived)")
	}
	released := false
	hub.releaseOnExit(run, func() { released = true })
	if !released {
		t.Fatal("releaseOnExit must fire immediately — the young tombstone survived the pre-pin flood")
	}
	hub.unpinTombstone(run)
	if hub.sessionLive(sid) {
		t.Fatal("liveness must be false after the raced exit + registration")
	}
}

// TestAttachHubOvershootDrainsAfterUnpinAndAge is the round-7 finding-2 fix: when
// every eviction candidate is pinned or younger than the floor, the map
// transiently EXCEEDS exitTombstoneBound. The prior one-eviction-per-add shed left
// that oversized baseline forever. Now each shed invocation is a single pass that
// drains as many eligible entries as possible toward the bound, driven from BOTH
// tombstoneLocked and unpinTombstone, so once the pin clears AND the entries age
// past the floor, the next shed pass drains the map back to <= bound.
func TestAttachHubOvershootDrainsAfterUnpinAndAge(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	base := time.Now()
	var clock time.Time
	clock = base
	hub.mu.Lock()
	hub.nowFunc = func() time.Time { return clock }
	hub.mu.Unlock()

	const run = "run-pinned"
	// Pin one run and flood while EVERYTHING is young — no candidate is eligible,
	// so the map overshoots the bound and stays there.
	hub.pinTombstone(run)
	hub.NotifyExit(run)
	for i := 0; i < exitTombstoneBound+64; i++ {
		hub.NotifyExit(fmt.Sprintf("flood-%d", i))
	}
	hub.mu.Lock()
	overshoot := len(hub.exited)
	hub.mu.Unlock()
	if overshoot <= exitTombstoneBound {
		t.Fatalf("precondition: map must overshoot the bound while all entries are young/pinned, got len=%d", overshoot)
	}

	// Age every entry past the floor and clear the pin: the unpinTombstone shed
	// pass must now drain the map back to the bound (the recovery finding 2 owed).
	clock = base.Add(2 * tombstoneMinAge)
	hub.unpinTombstone(run)
	hub.mu.Lock()
	drained := len(hub.exited)
	hub.mu.Unlock()
	if drained > exitTombstoneBound {
		t.Fatalf("map did not drain after unpin + age: len(exited)=%d, want <= %d (finding 2 regression)", drained, exitTombstoneBound)
	}
}

// TestAttachHubOnCorrelateDeadCheckSurvivesSelfShed is the round-9 finding-1 fix.
// onCorrelate ran shedTombstonesLocked BEFORE consulting h.exited[runID] for the
// dead-check, so the shed pass triggered by a correlation could evict the SAME
// run's own tombstone before the dead-check ever looked it up — if that
// tombstone happened to be the map's oldest eligible entry, the check would then
// read "not dead" and permanently resurrect liveness for a run that had already
// exited (no second exit signal ever comes for the same run id).
//
// Exact reproducing sequence (the reviewer's recipe): the target run exits first
// (so its tombstone predates everything else — it's the map's oldest entry),
// exitTombstoneBound MORE exits land right after (newer tombstones, pushing the
// map past the bound), the clock then crosses tombstoneMinAge so every entry —
// target included — becomes shed-eligible with no further activity in between
// (convergence is event-driven; nothing shrinks the map on its own), and finally
// the target's maximally-delayed correlation arrives as the FIRST event since the
// floor expired. That correlation is itself the shed trigger (round-8 finding 1),
// so the shed pass and the dead-check run in the very same call — exercising the
// exact ordering hazard the fix closes.
func TestAttachHubOnCorrelateDeadCheckSurvivesSelfShed(t *testing.T) {
	feed := termfeed.New(termfeed.Options{})
	hub := newAttachHub(feed, nil)
	t.Cleanup(hub.stop)

	base := time.Now()
	var clock time.Time
	clock = base
	hub.mu.Lock()
	hub.nowFunc = func() time.Time { return clock }
	hub.mu.Unlock()

	const sid, run = "sess-selfshed", "run-selfshed"

	// The target: reserved, then exits. Its tombstone is written before anything
	// below, so it is the map's single OLDEST entry.
	hub.reserve(sid, run)
	if !hub.sessionLive(sid) {
		t.Fatal("reserve must mark the tracked run's session live")
	}
	hub.NotifyExit(run)
	if hub.sessionLive(sid) {
		t.Fatal("NotifyExit must clear the tracked run's liveness")
	}

	// Nudge the clock forward before the flood so the target's timestamp is
	// STRICTLY older than every flood entry — without this, all timestamps tie
	// at `base` and oldest-first eviction picks an arbitrary entry (map iteration
	// order), making the repro non-deterministic.
	clock = base.Add(1 * time.Millisecond)

	// exitTombstoneBound MORE exits land right after — newer than the target,
	// pushing the map past the bound while every entry (target included) is
	// still too young to shed.
	for i := 0; i < exitTombstoneBound; i++ {
		hub.NotifyExit(fmt.Sprintf("flood-%d", i))
	}
	hub.mu.Lock()
	sz := len(hub.exited)
	hub.mu.Unlock()
	if sz <= exitTombstoneBound {
		t.Fatalf("precondition: map must overshoot the bound with everything young, got len=%d", sz)
	}

	// The floor expires for every entry, target included, with no intervening
	// exit/unpin/correlation activity — the map stays oversized right up to the
	// correlation delivered below (convergence is event-driven, not time-driven).
	clock = base.Add(2 * tombstoneMinAge)

	// The target's maximally-delayed correlation is the FIRST event since the
	// floor expired: the shed pass it triggers and the dead-check it needs land
	// in the same onCorrelate call, with the target's own tombstone now the
	// oldest eligible candidate in the map.
	hub.onCorrelate(run, sid, string(termrun.SourceOOB), 0.95)

	if hub.sessionLive(sid) {
		t.Fatal("a correlation for an already-exited run must not resurrect liveness, even when that same call sheds the run's own tombstone (round-9 finding 1)")
	}
	// A subsequent resume of the same session (a distinct run id) must still see
	// it free — the double-spawn guard must not be stuck true.
	hub.reserve(sid, "run-selfshed-fresh")
	if !hub.sessionLive(sid) {
		t.Fatal("a subsequent resume of the session must succeed after the self-shed race")
	}
}

// launches returns the number of LaunchAttachable calls observed so far.
// It lives in this unix-only file because it is the sole consumer; keeping it
// in attach_test.go left it flagged unused by lint on a Windows build.
func (f *fakeAttachLauncher) launches() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.launchCalls
}
