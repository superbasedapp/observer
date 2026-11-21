//go:build !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestLoopbackExposureSources: the daemon's own live boxes and the watched
// sandboxed CLI launches count; an exited terminal, an unwatched history
// row (a daemon-death orphan), an ended row and a box with its own network
// namespace do not; a failure to read the live boxes refuses (fail closed).
func TestLoopbackExposureSources(t *testing.T) {
	ended := time.Now()
	hostBox := &dashapi.LaunchIsolation{Class: "process", Backend: "bwrap", EgressTier: "host"}
	netnsBox := &dashapi.LaunchIsolation{Class: "process", Backend: "bwrap", EgressTier: "internet"}
	cases := []struct {
		name    string
		snap    []dashapi.LaunchInfo
		hist    []store.TerminalRunSummary
		histErr error
		watched map[string]bool
		wantRun string // "" = not exposed
	}{
		{name: "nothing live"},
		{name: "own netns box", snap: []dashapi.LaunchInfo{{RunID: "r-a", Isolation: netnsBox}}},
		{name: "host-tier terminal", snap: []dashapi.LaunchInfo{{RunID: "r-a", Isolation: hostBox}}, wantRun: "r-a"},
		{name: "exited host-tier terminal", snap: []dashapi.LaunchInfo{{RunID: "r-a", Isolation: hostBox, Exited: true}}},
		{
			name: "watched CLI host-tier run", hist: []store.TerminalRunSummary{{RunID: "r-cli", IsolationClass: "process", Stack: "bwrap", EgressTier: "host"}},
			watched: map[string]bool{"r-cli": true}, wantRun: "r-cli",
		},
		{
			name: "watched CLI MXC run", hist: []store.TerminalRunSummary{{RunID: "r-mxc", IsolationClass: "process", Stack: "mxc-process", EgressTier: "proxy_only"}},
			watched: map[string]bool{"r-mxc": true}, wantRun: mxcWant(),
		},
		{name: "orphan row nobody watches", hist: []store.TerminalRunSummary{{RunID: "r-old", IsolationClass: "process", Stack: "bwrap", EgressTier: "host"}}},
		{
			name: "a kept marker gates whatever end its row records", hist: []store.TerminalRunSummary{{RunID: "r-cli", IsolationClass: "process", Stack: "bwrap", EgressTier: "host", EndedAt: &ended, EndReason: "daemon_shutdown"}},
			watched: map[string]bool{"r-cli": true}, wantRun: "r-cli",
		},
		{
			name: "read error fails closed with a live terminal too", snap: []dashapi.LaunchInfo{{RunID: "r-a", Isolation: netnsBox}},
			histErr: errors.New("db locked"), watched: map[string]bool{"r-cli": true}, wantRun: "could not be read",
		},
		{name: "read error fails closed", histErr: errors.New("db locked"), watched: map[string]bool{"r-cli": true}, wantRun: "could not be read"},
		{name: "no marker: no database read, so a busy database refuses nothing", histErr: errors.New("database is locked (SQLITE_BUSY)")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reads := 0
			src := loopbackExposureSources{
				snapshot: func() []dashapi.LaunchInfo { return tc.snap },
				markers: func() []sandboxCLIMarker {
					var ms []sandboxCLIMarker
					for id := range tc.watched {
						ms = append(ms, sandboxCLIMarker{RunID: id, Path: "/obs/relay/cli-end/" + id + ".watch", PID: 42})
					}
					return ms
				},
				runRows: func(context.Context, []string) ([]store.TerminalRunSummary, error) {
					reads++
					return tc.hist, tc.histErr
				},
				sweep: func(ms []sandboxCLIMarker, _ map[string]cliRunState) []sandboxCLIMarker { return ms },
			}
			reason, exposed := src.check(context.Background())
			if len(tc.watched) == 0 && reads != 0 {
				t.Fatalf("no marker, yet the database was read %d times (fixes-3 C)", reads)
			}
			if tc.wantRun == "" {
				if exposed {
					t.Fatalf("exposed: %s", reason)
				}
				return
			}
			if !exposed || !strings.Contains(reason, tc.wantRun) {
				t.Fatalf("reason %q exposed %v, want run %s", reason, exposed, tc.wantRun)
			}
		})
	}
}

// mxcWant is the MXC case's expectation: exposed through the registry row's
// relay capability in a build with the sandbox; a build without it has no
// registry and no boxes.
func mxcWant() string {
	if sandboxRowHostLoopbackRelay("mxc-process") {
		return "r-mxc"
	}
	return ""
}

// TestLoopbackExposureNamesTheMarker (fixes-3 B): a CLI box's refusal names
// the marker that keeps it counted and the command to remove it.
func TestLoopbackExposureNamesTheMarker(t *testing.T) {
	src := loopbackExposureSources{
		markers: func() []sandboxCLIMarker {
			return []sandboxCLIMarker{{RunID: "r-cli", Path: "/obs/relay/cli-end/r-cli.watch", PID: 42}}
		},
		runRows: func(context.Context, []string) ([]store.TerminalRunSummary, error) {
			return []store.TerminalRunSummary{{RunID: "r-cli", IsolationClass: "process", Stack: "bwrap", EgressTier: "host"}}, nil
		},
		sweep: func(ms []sandboxCLIMarker, _ map[string]cliRunState) []sandboxCLIMarker { return ms },
	}
	reason, exposed := src.check(context.Background())
	if !exposed || !strings.Contains(reason, "/obs/relay/cli-end/r-cli.watch") || !strings.Contains(reason, "remove the marker") {
		t.Fatalf("reason %q does not name the marker and how to clear it", reason)
	}
	// A swept marker no longer gates.
	src.sweep = func([]sandboxCLIMarker, map[string]cliRunState) []sandboxCLIMarker { return nil }
	if reason, exposed := src.check(context.Background()); exposed {
		t.Fatalf("a swept marker still gates: %s", reason)
	}
}
