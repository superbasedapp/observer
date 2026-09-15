package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/processobs"
	"github.com/marmutapp/superbased-observer/internal/processobs/bridge"
)

// TestProcessHealthRecord pins the boundary mapping from the Observer's
// in-memory health onto the on-disk record the out-of-process surfaces read.
// The network accounting mode/reason pair is the payload that used to be
// discarded here (ETW parity plan §0.4), so each mode gets a row.
func TestProcessHealthRecord(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   processobs.HealthSnapshot
		want diag.ProcessHealth
	}{
		{
			name: "live tcp accounting",
			in: processobs.HealthSnapshot{
				BackendName: "linux_ebpf+poll", BackendUp: true, QueueDepth: 4,
				NetworkAccountingMode: processobs.NetworkAccountingTCP,
			},
			want: diag.ProcessHealth{
				Backend: "linux_ebpf+poll", BackendUp: true, QueueDepth: 4,
				NetworkAccountingMode: processobs.NetworkAccountingTCP,
			},
		},
		{
			name: "unavailable keeps the reason verbatim",
			in: processobs.HealthSnapshot{
				BackendName: "linux_ebpf+poll", BackendUp: true,
				NetworkAccountingMode:   processobs.NetworkAccountingUnavailable,
				NetworkAccountingReason: "missing CAP_BPF/CAP_PERFMON",
			},
			want: diag.ProcessHealth{
				Backend: "linux_ebpf+poll", BackendUp: true,
				NetworkAccountingMode:   processobs.NetworkAccountingUnavailable,
				NetworkAccountingReason: "missing CAP_BPF/CAP_PERFMON",
			},
		},
		{
			name: "off with a config reason",
			in: processobs.HealthSnapshot{
				BackendName: "poll", BackendUp: true,
				NetworkAccountingMode:   processobs.NetworkAccountingOff,
				NetworkAccountingReason: "not enabled ([observer.process.network].process_bytes)",
			},
			want: diag.ProcessHealth{
				Backend: "poll", BackendUp: true,
				NetworkAccountingMode:   processobs.NetworkAccountingOff,
				NetworkAccountingReason: "not enabled ([observer.process.network].process_bytes)",
			},
		},
		{
			name: "backend error travels too",
			in: processobs.HealthSnapshot{
				BackendName: "etw", BackendUp: false,
				LastError:             "ETW session needs elevation (ERROR_ACCESS_DENIED)",
				NetworkAccountingMode: processobs.NetworkAccountingUnavailable,
			},
			want: diag.ProcessHealth{
				Backend: "etw", BackendUp: false,
				LastError:             "ETW session needs elevation (ERROR_ACCESS_DENIED)",
				NetworkAccountingMode: processobs.NetworkAccountingUnavailable,
			},
		},
		{
			// The cross-OS capturer link (W4-A): its counters have no other
			// reader, so a drop here is invisible everywhere downstream.
			name: "a configured transport carries its counters and timestamps",
			in: processobs.HealthSnapshot{
				BackendName: "composite[poll+bridge-listen]", BackendUp: true,
				NetworkAccountingMode: processobs.NetworkAccountingTCP,
				TransportState:        processobs.TransportStateConfigured,
				Transport: processobs.TransportStats{
					Addr: "127.0.0.1:8823", Connections: 2, AuthFailures: 5, Connected: true,
					LastAuthError:     "processobs/bridge: malformed handshake: capturer speaks protocol v2, this daemon speaks v1",
					LastAuthFailureAt: transportTestTime(45),
					LastConnectAt:     transportTestTime(60), LastDisconnectAt: transportTestTime(30),
				},
			},
			want: diag.ProcessHealth{
				Backend: "composite[poll+bridge-listen]", BackendUp: true,
				NetworkAccountingMode: processobs.NetworkAccountingTCP,
				TransportState:        processobs.TransportStateConfigured,
				TransportAddr:         "127.0.0.1:8823",
				TransportConnections:  2, TransportAuthFailures: 5, TransportConnected: true,
				TransportLastAuthError:    "processobs/bridge: malformed handshake: capturer speaks protocol v2, this daemon speaks v1",
				TransportLastConnectAt:    transportTestTime(60),
				TransportLastDisconnectAt: transportTestTime(30),
			},
		},
		{
			// Honesty gate: with no transport configured, nothing about a
			// transport may reach the record — a stray counter would render
			// as a broken capturer link on an install that has no capturer.
			name: "an unconfigured transport contributes nothing",
			in: processobs.HealthSnapshot{
				BackendName: "poll", BackendUp: true,
				NetworkAccountingMode: processobs.NetworkAccountingOff,
				Transport: processobs.TransportStats{
					Addr: "127.0.0.1:8823", Connections: 7, AuthFailures: 7, Connected: true,
					LastConnectAt: transportTestTime(60),
				},
			},
			want: diag.ProcessHealth{
				Backend: "poll", BackendUp: true,
				NetworkAccountingMode: processobs.NetworkAccountingOff,
			},
		},
		{
			// M3: the third state. "The operator asked for the cross-OS feed
			// and it is NOT running" must survive the boundary — it used to
			// have nowhere to go, so it rendered as the same silence as the
			// row above.
			name: "a requested-but-unavailable transport carries its reason and no counters",
			in: processobs.HealthSnapshot{
				BackendName: "composite[poll+bridge]", BackendUp: true,
				NetworkAccountingMode:      processobs.NetworkAccountingOff,
				TransportState:             processobs.TransportStateUnavailable,
				TransportUnavailableReason: "processobs/bridge: listen 127.0.0.1:8823: bind: address already in use",
				// A leftover counters value must NOT ride along: there is no
				// transport, so it has nothing to count.
				Transport: processobs.TransportStats{Addr: "127.0.0.1:8823", AuthFailures: 4},
			},
			want: diag.ProcessHealth{
				Backend: "composite[poll+bridge]", BackendUp: true,
				NetworkAccountingMode:      processobs.NetworkAccountingOff,
				TransportState:             processobs.TransportStateUnavailable,
				TransportUnavailableReason: "processobs/bridge: listen 127.0.0.1:8823: bind: address already in use",
			},
		},
		{
			// Task 9d: the capture-yield half. These counters live in the
			// daemon's memory and used to stop there, which left every
			// out-of-process surface unable to tell an idle box from one
			// discarding every batch. Attributed is DERIVED from the
			// per-tool breakdown, so the two can never disagree.
			name: "drop/attribution counters cross the boundary, with Attributed derived",
			in: processobs.HealthSnapshot{
				BackendName: "poll", BackendUp: true,
				NetworkAccountingMode: processobs.NetworkAccountingOff,
				Unattributed:          412,
				SinkRetained:          250,
				AttributedByTool:      map[string]int64{"claude-code": 9, "codex": 3},
				Dropped: map[processobs.DropReason]int64{
					processobs.DropSinkError:          250,
					processobs.DropSinkRetryExhausted: 500,
					processobs.DropSelfExcluded:       18,
				},
			},
			want: diag.ProcessHealth{
				Backend: "poll", BackendUp: true,
				NetworkAccountingMode: processobs.NetworkAccountingOff,
				Unattributed:          412,
				SinkRetained:          250,
				Attributed:            12,
				AttributedByTool:      map[string]int64{"claude-code": 9, "codex": 3},
				Dropped: map[string]int64{
					"sink_error":           250,
					"sink_retry_exhausted": 500,
					"self_excluded":        18,
				},
			},
		},
		{
			// Absence stays absence: empty maps must not become empty-but-
			// present maps on the record, or a reader cannot distinguish
			// "never reported" from "reported nothing".
			name: "empty counter maps contribute no map at all",
			in: processobs.HealthSnapshot{
				BackendName:           "poll",
				NetworkAccountingMode: processobs.NetworkAccountingOff,
				Dropped:               map[processobs.DropReason]int64{},
				AttributedByTool:      map[string]int64{},
			},
			want: diag.ProcessHealth{
				Backend:               "poll",
				NetworkAccountingMode: processobs.NetworkAccountingOff,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := processHealthRecord(tc.in)
			// DeepEqual, not ==: the record carries counter MAPS since 9d.
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("processHealthRecord() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestPublishProcessHealth_WritesAndCleansUp covers the publisher lifecycle:
// a record appears immediately (so doctor can report a just-started daemon),
// it reflects what the snapshot func returns, and stopping removes it — a
// daemon that has exited must not leave a record doctor would read as live.
func TestPublishProcessHealth_WritesAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")

	stop := publishProcessHealth(context.Background(), dbPath, func() processobs.HealthSnapshot {
		return processobs.HealthSnapshot{
			BackendName:             "linux_ebpf+poll",
			BackendUp:               true,
			NetworkAccountingMode:   processobs.NetworkAccountingUnavailable,
			NetworkAccountingReason: "missing CAP_BPF/CAP_PERFMON",
		}
	}, nil)

	var (
		got diag.ProcessHealth
		ok  bool
	)
	for i := 0; i < 100 && !ok; i++ {
		if got, ok = diag.LatestProcessHealth(dir); !ok {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !ok {
		t.Fatal("no health record published")
	}
	if got.Backend != "linux_ebpf+poll" || got.NetworkAccountingReason != "missing CAP_BPF/CAP_PERFMON" {
		t.Errorf("published record = %+v", got)
	}

	stop()
	if _, ok := diag.LatestProcessHealth(dir); ok {
		t.Error("record survived stop() — a dead daemon would look live to doctor")
	}
	stop() // idempotent
}

// TestPublishProcessHealth_StopsOnContextCancel pins the other exit path: the
// daemon's context is cancelled (ctrl-c) rather than the caller stopping it.
func TestPublishProcessHealth_StopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	stop := publishProcessHealth(ctx, filepath.Join(dir, "observer.db"),
		func() processobs.HealthSnapshot {
			return processobs.HealthSnapshot{BackendName: "poll"}
		}, nil)
	cancel()
	stop() // waits for the publisher goroutine to unwind
	if _, ok := diag.LatestProcessHealth(dir); ok {
		t.Error("record survived context cancellation")
	}
}

// TestPublishProcessHealth_NoDBPath is the fail-open case: with nowhere to
// write, publishing is a no-op that must not panic or block.
func TestPublishProcessHealth_NoDBPath(t *testing.T) {
	t.Parallel()
	publishProcessHealth(context.Background(), "", func() processobs.HealthSnapshot {
		return processobs.HealthSnapshot{}
	}, nil)()
	publishProcessHealth(context.Background(), "/tmp/x.db", nil, nil)()
}

// transportTestTime is a fixed UTC instant, offset by secondsAgo, for the
// transport-mapping rows. Fixed so the ProcessHealth structs stay directly
// comparable (time.Time equality is field equality, not Equal).
func transportTestTime(secondsAgo int) time.Time {
	return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC).Add(-time.Duration(secondsAgo) * time.Second)
}

// TestSelectProcessBackendTransportStatsReachable is the WIRING proof for the
// capturer-link health surface. selectProcessBackend wraps the accept listener
// in a Composite and then DROPS the concrete *bridge.Listener handle, so the
// only route to its counters is the capability forwarded through the composite
// — a route that is easy to break invisibly, because losing it degrades to
// "no transport configured", which renders as silence.
func TestSelectProcessBackendTransportStatsReachable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("no ETW block means no transport at all", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "poll"
		b, _, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()
		if ts, ok := processobs.TransportStatsOf(b); ok {
			t.Fatalf("a poll-only baseline owns no dial-in transport; got %+v", ts)
		}
	})

	t.Run("the listener's counters survive the composite wrapping", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "poll"
		pc.ETW.Enabled = true
		pc.ETW.ListenAddr = "127.0.0.1:0"
		b, _, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()
		ts, ok := processobs.TransportStatsOf(b)
		if !ok {
			t.Fatal("the ETW listener's stats must be reachable through the composite (they have no other reader)")
		}
		// Never connected: real bind address, zero counters. That combination
		// IS the health state an operator whose Scheduled Task never ran sees.
		if ts.Addr == "" || ts.Connections != 0 || ts.AuthFailures != 0 || ts.Connected {
			t.Fatalf("freshly-bound listener stats = %+v", ts)
		}
		// And it survives the boundary mapping the daemon actually publishes.
		rec := processHealthRecord(processobs.HealthSnapshot{
			BackendName: b.Name(), TransportState: processobs.TransportStateConfigured, Transport: ts,
		})
		if !rec.TransportConfigured() || rec.TransportAddr != ts.Addr {
			t.Fatalf("record = %+v", rec)
		}
		if line := rec.TransportLine(time.Now()); !strings.Contains(line, "waiting") {
			t.Fatalf("a never-connected listener must render the waiting line, got %q", line)
		}
	})

	t.Run("a fail-open listener claims no transport but is not silent", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "poll"
		pc.ETW.Enabled = true
		pc.ETW.ListenAddr = "10.1.2.3:8823" // non-loopback → refused
		b, reason, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("a listener failure must not disable capture: %v", err)
		}
		defer b.Close()
		// Still true: no transport exists, so none may be claimed.
		if ts, ok := processobs.TransportStatsOf(b); ok {
			t.Fatalf("a listener that never bound must not report a transport; got %+v", ts)
		}
		// NEW (M3): and the operator must be able to SEE that the feed they
		// asked for is not running. A bind conflict on :8823 is the likeliest
		// way to get here, and it used to print nothing anywhere — identical
		// to an install that never enabled ETW.
		if reason == "" {
			t.Fatal("a requested transport that failed to bind must carry its reason; got silence")
		}
		if !strings.Contains(reason, "10.1.2.3:8823") {
			t.Errorf("the reason must name what failed, got %q", reason)
		}
		rec := processHealthRecord(processobs.HealthSnapshot{
			BackendName:                b.Name(),
			TransportState:             processobs.TransportStateUnavailable,
			TransportUnavailableReason: reason,
		})
		line := rec.TransportLine(time.Now())
		if !strings.Contains(line, "UNAVAILABLE") || !strings.Contains(line, "10.1.2.3:8823") {
			t.Fatalf("the health line must report the requested-but-missing transport, got %q", line)
		}
		// And the three states stay apart: this is neither the silence of an
		// unconfigured install nor the waiting line of a bound listener.
		if strings.Contains(line, "waiting") || line == "" {
			t.Fatalf("unavailable must be distinguishable from none and from never-connected, got %q", line)
		}
	})

	t.Run(`backend = "etw" with the block disabled is a request, not a no-op`, func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "etw"
		pc.ETW.Enabled = false
		b, reason, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()
		if ts, ok := processobs.TransportStatsOf(b); ok {
			t.Fatalf("nothing was started, so nothing may be claimed; got %+v", ts)
		}
		if !strings.Contains(reason, "[observer.process.etw].enabled") {
			t.Errorf("the config gap must be named, got %q", reason)
		}
	})

	// TestSelectProcessBackendRefusalReasonReachesDoctor is the END-TO-END
	// plumbing proof for the refusal reason: a REAL listener refuses a REAL
	// non-token handshake, and the daemon's verbatim reason has to survive
	// Listener → TransportStats → Composite → Health.Snapshot →
	// processHealthRecord → the diag line an operator reads.
	//
	// Every hop on that path is a place the reason can be dropped, and
	// dropping it is invisible: the counter still climbs, so the surface
	// still WARNs — it just goes back to naming the token as the cause.
	t.Run("a non-token refusal reaches the operator line verbatim", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "poll"
		pc.ETW.Enabled = true
		pc.ETW.ListenAddr = "127.0.0.1:0"
		b, _, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()
		ch, serr := b.Start(context.Background())
		if serr != nil {
			t.Fatalf("start: %v", serr)
		}
		go func() {
			for range ch { //nolint:revive // drain
			}
		}()
		ts, ok := processobs.TransportStatsOf(b)
		if !ok || ts.Addr == "" {
			t.Fatalf("no listener address to dial: %+v", ts)
		}

		// A capturer built from an OLDER observer: same token, wire version
		// this daemon does not speak. The exact upgrade-skew case.
		conn, derr := net.DialTimeout("tcp", ts.Addr, 2*time.Second)
		if derr != nil {
			t.Fatalf("dial: %v", derr)
		}
		defer conn.Close()
		if _, werr := fmt.Fprintf(conn, "SBO-PROCESS-BRIDGE/%d whatever-token\n", bridge.WireVersion+1); werr != nil {
			t.Fatalf("write handshake: %v", werr)
		}

		obs := processobs.NewObserver(processobs.Options{Backend: b})
		var line string
		for i := 0; i < 200; i++ {
			rec := processHealthRecord(obs.Health().Snapshot())
			if rec.TransportAuthFailures > 0 {
				line = rec.TransportLine(time.Now())
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if line == "" {
			t.Fatal("the refusal never reached the health record")
		}
		want := fmt.Sprintf("speaks protocol v%d", bridge.WireVersion+1)
		if !strings.Contains(line, want) {
			t.Fatalf("the daemon's verbatim reason did not reach the operator line.\nline: %q\nwant it to contain %q", line, want)
		}
		for _, absent := range []string{"is presenting the wrong", "shared-token mismatch"} {
			if strings.Contains(line, absent) {
				t.Errorf("a wire-version skew was diagnosed as %q:\n%s", absent, line)
			}
		}
	})

	t.Run("no ETW request at all stays completely silent", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "poll"
		b, reason, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()
		if reason != "" {
			t.Fatalf("an install that never asked for the feed must report nothing, got %q", reason)
		}
	})
}

// TestSelectProcessBackendPreservesBackendCapabilities is the H1 regression
// guard, and the reason the unavailable-transport reason is a returned VALUE
// rather than a decorator around the backend.
//
// The decorator embedded processobs.Backend (an INTERFACE), which promotes
// only that interface's method set — so `backend.(processobs.UnattributedCapturer)`
// failed on the wrapper even when the wrapped baseline implemented it. That
// probe is what runProcessObserver uses to force captureUnattributed, and
// config.CaptureUnattributed defaults false, so on both configurations that
// reach this path the daemon silently STOPPED persisting cross-OS process
// rows — on the very path whose purpose is to make a failure loud. The fix
// for a silent bind conflict had introduced a silent capture regression.
//
// Mutation check: reinstate any wrapper here and the subtests below fail.
func TestSelectProcessBackendPreservesBackendCapabilities(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// requiresUnattributed replays the daemon's own probe, verbatim
	// (runProcessObserver). Asserting through the same expression the
	// production code uses is the point: a test that asked the concrete type
	// would have passed throughout the bug.
	requiresUnattributed := func(b processobs.Backend) bool {
		uc, ok := b.(processobs.UnattributedCapturer)
		return ok && uc.RequiresUnattributedCapture()
	}

	t.Run("a failed ETW listener must not cost the baseline its capabilities", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "bridge"
		pc.ETW.Enabled = true
		pc.ETW.ListenAddr = "10.1.2.3:8823" // non-loopback → the listener is refused
		b, reason, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("a listener failure must not disable capture: %v", err)
		}
		defer b.Close()
		if reason == "" {
			t.Fatal("the requested-but-missing transport must still carry its reason")
		}
		if !requiresUnattributed(b) {
			t.Fatal("the cross-OS baseline lost UnattributedCapturer — Windows process rows would stop being persisted, silently")
		}
	})

	t.Run(`backend = "etw" with the block disabled keeps them too`, func(t *testing.T) {
		// The config-typo branch, which carries a reason UNCONDITIONALLY —
		// so it wrapped every baseline, on every host, not just on failure.
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "etw"
		pc.ETW.Enabled = false
		b, reason, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()
		if reason == "" {
			t.Fatal("the config gap must still be reported")
		}
		// This host's auto baseline may or may not include the bridge, so the
		// capability's VALUE is not assertable here — but the identity of the
		// value the caller gets is, and that is the stronger property.
		assertNoBackendWrapper(t, b)
	})

	// The generic guard. The two subtests above name ONE capability; this one
	// fails for any capability, including ones that do not exist yet, by
	// pinning the property that makes losing them impossible: nothing in
	// package main may stand between the caller and the assembled backend.
	// An explicit-forwarding decorator would still be a standing trap
	// (CLAUDE.md rule 6) — it has to be revisited every time a capability is
	// added — so the guard rejects a wrapper outright rather than checking
	// which methods it happens to forward.
	t.Run("no unavailable-transport path introduces a wrapper type", func(t *testing.T) {
		cases := []struct {
			name string
			mut  func(pc *config.ProcessConfig)
		}{
			{"poll baseline, listener refused", func(pc *config.ProcessConfig) {
				pc.Backend = "poll"
				pc.ETW.Enabled, pc.ETW.ListenAddr = true, "10.1.2.3:8823"
			}},
			{"bridge baseline, listener refused", func(pc *config.ProcessConfig) {
				pc.Backend = "bridge"
				pc.ETW.Enabled, pc.ETW.ListenAddr = true, "10.1.2.3:8823"
			}},
			{"both baseline, listener refused", func(pc *config.ProcessConfig) {
				pc.Backend = "both"
				pc.ETW.Enabled, pc.ETW.ListenAddr = true, "10.1.2.3:8823"
			}},
			{"auto baseline, listener refused", func(pc *config.ProcessConfig) {
				pc.Backend = "auto"
				pc.ETW.Enabled, pc.ETW.ListenAddr = true, "10.1.2.3:8823"
			}},
			{"etw backend, block disabled", func(pc *config.ProcessConfig) {
				pc.Backend, pc.ETW.Enabled = "etw", false
			}},
			{"listener bound, no reason at all", func(pc *config.ProcessConfig) {
				pc.Backend = "poll"
				pc.ETW.Enabled, pc.ETW.ListenAddr = true, "127.0.0.1:0"
			}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				pc := config.Default().Observer.Process
				pc.Enabled = true
				tc.mut(&pc)
				b, _, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
				if err != nil {
					t.Fatalf("select: %v", err)
				}
				defer b.Close()
				assertNoBackendWrapper(t, b)
			})
		}
	})

	// And the reason still has to REACH the surfaces without the wrapper —
	// otherwise this fix would have traded H1 for the silence M3 removed.
	t.Run("the reason still reaches the health record and the doctor line", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "bridge"
		pc.ETW.Enabled = true
		pc.ETW.ListenAddr = "10.1.2.3:8823"
		b, reason, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()

		obs := processobs.NewObserver(processobs.Options{Backend: b, TransportUnavailableReason: reason})
		snap := obs.Health().Snapshot()
		if snap.TransportState != processobs.TransportStateUnavailable {
			t.Fatalf("TransportState = %q, want unavailable", snap.TransportState)
		}
		rec := processHealthRecord(snap)
		line := rec.TransportLine(time.Now())
		if !strings.Contains(line, "UNAVAILABLE") || !strings.Contains(line, "10.1.2.3:8823") {
			t.Fatalf("the health line must report the requested-but-missing transport, got %q", line)
		}
		// The tri-state stays a tri-state: this is neither the silence of an
		// unconfigured install nor a claimed transport with zero counters.
		if rec.TransportConfigured() {
			t.Fatalf("a transport that never started must not read as configured: %+v", rec)
		}
	})

	// The absent case has to stay absent: an install that asked for nothing
	// must produce "none", not a reason-less "unavailable".
	t.Run("no request at all still resolves to none", func(t *testing.T) {
		pc := config.Default().Observer.Process
		pc.Enabled, pc.Backend = true, "poll"
		b, reason, err := selectProcessBackend(pc, t.TempDir(), logger, &processobs.NetworkAccounting{})
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		defer b.Close()
		snap := processobs.NewObserver(processobs.Options{Backend: b, TransportUnavailableReason: reason}).Health().Snapshot()
		if snap.TransportState != processobs.TransportStateNone {
			t.Fatalf("TransportState = %q, want none", snap.TransportState)
		}
		if line := processHealthRecord(snap).TransportLine(time.Now()); line != "" {
			t.Fatalf("an install with no dial-in transport must print nothing, got %q", line)
		}
	})
}

// assertNoBackendWrapper fails when b (or anything it points at) is a type
// declared in package main. Every real capture backend lives in
// internal/processobs/…, so a main-declared Backend implementation can only
// be a decorator wrapped around one — and a decorator over an embedded
// INTERFACE silently drops every optional capability it does not restate.
func assertNoBackendWrapper(t *testing.T, b processobs.Backend) {
	t.Helper()
	ty := reflect.TypeOf(b)
	for ty != nil && (ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Interface) {
		ty = ty.Elem()
	}
	if ty == nil {
		t.Fatal("selectProcessBackend returned a nil backend")
	}
	// NOTE: reflect reports a main-package type's PkgPath as the package's
	// full IMPORT PATH ("…/cmd/observer"), not "main" — comparing against the
	// literal "main" silently never matches. localPkgMarker pins the right
	// value without hardcoding the module path.
	if ty.PkgPath() == reflect.TypeOf(localPkgMarker{}).PkgPath() {
		t.Fatalf("selectProcessBackend wrapped the backend in %s — a main-declared decorator over an "+
			"embedded Backend interface promotes only Backend's methods, so every optional capability "+
			"(UnattributedCapturer, NetworkSampler, TransportStatsSource, and anything added later) "+
			"becomes invisible to a type assertion. Return the fact beside the backend instead.", ty.String())
	}
}

// localPkgMarker exists only so assertNoBackendWrapper can name THIS
// package's reflect PkgPath without hardcoding the module path.
type localPkgMarker struct{}
