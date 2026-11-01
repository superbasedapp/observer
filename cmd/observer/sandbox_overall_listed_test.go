//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// TestSandboxOverallFollowsTheListedBackends (Linux live re-check on the
// Docker sandbox 2026-10-23, N4): with `backends = ["process_lite"]` on a
// kernel with no Landlock, `observer sandbox status` printed "Overall:
// available" from the legacy bwrap probe while a launch refused. The overall
// verdict now follows the listed backends: bwrap's answer stands only while
// bwrap is listed.
func TestSandboxOverallFollowsTheListedBackends(t *testing.T) {
	lite, bwrap := sandboxbackend.BackendProcessLite, sandboxbackend.BackendBwrap
	legacy := sandbox.Availability{Available: true, Verdict: sandbox.VerdictAvailable, Backend: bwrap}
	liteRow := dashapi.SandboxBackendAvail{ID: lite, Verdict: "landlock_unavailable", Reason: "the kernel has no usable Landlock (function not implemented)", Beta: true}
	rows := []dashapi.SandboxBackendAvail{{ID: bwrap, Verdict: "disabled_by_config", Reason: "not in the enabled backends list"}, liteRow}
	for _, drivers := range []map[string]sandboxDriver{nil, {lite: nil}} {
		r := &sandboxRuntime{cfg: config.TerminalSandboxConfig{Enabled: true, Backends: []string{lite}}, drivers: drivers}
		av := sandboxPlatformOverall(r.preferDriverInLegacy(legacy, rows), rows, sandboxbackend.HostLinux)
		if av.Available || av.Verdict != liteRow.Verdict || av.Backend != lite || av.Reason != liteRow.Reason {
			t.Fatalf("drivers %v: overall %+v", drivers, av)
		}
		var buf bytes.Buffer
		if err := renderSandboxStatus(&buf, sandboxStatusReport{Enabled: true, Egress: "internet", Host: "linux", Verdict: av.Verdict, Reason: av.Reason, Backends: rows}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), "Overall: available") || !strings.Contains(buf.String(), "Overall: landlock_unavailable: the kernel has no usable Landlock") {
			t.Fatalf("drivers %v: status:\n%s", drivers, buf.String())
		}
	}
	// bwrap listed (alone, after the unavailable row, or by default): its
	// own answer stands, as before.
	bwrapRows := []dashapi.SandboxBackendAvail{{ID: bwrap, Available: true}, liteRow}
	for _, list := range [][]string{{bwrap}, {lite, bwrap}, nil} {
		r := &sandboxRuntime{cfg: config.TerminalSandboxConfig{Enabled: true, Backends: list}, drivers: map[string]sandboxDriver{lite: nil}}
		if av := r.preferDriverInLegacy(legacy, bwrapRows); !av.Available || av.Backend != bwrap {
			t.Fatalf("backends %v: %+v", list, av)
		}
	}
	// The master switch off enables nothing: the legacy answer is kept (the
	// status prints no overall line when off).
	off := &sandboxRuntime{cfg: config.TerminalSandboxConfig{Backends: []string{lite}}}
	if av := off.preferDriverInLegacy(legacy, rows); !av.Available {
		t.Fatalf("off: %+v", av)
	}
}
