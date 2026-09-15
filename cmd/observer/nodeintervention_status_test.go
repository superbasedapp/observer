package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

func TestNodeInterventionReportsCannotOutliveControllerOrEnrollment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux controller identity required")
	}
	ctx := context.Background()
	_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.UserID = "fixture-member" })
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	id, err := intervention.Inspect(ctx, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := nodeInterventionAuthority(ctx, st, id.UID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	base := nodeInterventionStatus{At: time.Now().UTC(), Controller: id, Authority: auth.Authority, State: "partial", ProcessCutoff: "active", ExecutionAdmission: "unavailable", RequestAdmission: "unavailable", Reason: "verified installed processes only"}
	provider := nodeInterventionPostureProvider(ctx, st, dbPath, func() (orgcontract.BudgetPostureRow, bool) {
		return orgcontract.BudgetPostureRow{Coverage: "proxy_only"}, true
	})
	for _, tc := range []struct {
		name   string
		change func(*nodeInterventionStatus)
		want   string
	}{
		{"current", func(*nodeInterventionStatus) {}, "partial"},
		{"stale", func(s *nodeInterventionStatus) { s.At = s.At.Add(-time.Minute) }, "control_unavailable"},
		{"future", func(s *nodeInterventionStatus) { s.At = s.At.Add(time.Minute) }, "control_unavailable"},
		{"different process", func(s *nodeInterventionStatus) { s.Controller.StartTicks++ }, "control_unavailable"},
		{"old enrollment", func(s *nodeInterventionStatus) { s.Authority = "old" }, "control_unavailable"},
		{"unimplemented ready claim", func(s *nodeInterventionStatus) { s.State = "ready" }, "control_unavailable"},
		{"control characters", func(s *nodeInterventionStatus) { s.Reason = "forged\nready" }, "control_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := base
			tc.change(&status)
			if err := writeNodeInterventionStatus(ctx, dbPath, status); err != nil {
				t.Fatal(err)
			}
			got, ok := provider()
			if !ok || got.DirectControl != tc.want || got.Coverage != "proxy_only" {
				t.Fatalf("posture=%+v reported=%v", got, ok)
			}
			if tc.want == "control_unavailable" && !strings.HasPrefix(nodeInterventionStatusLine(ctx, st, dbPath), "unavailable - ") {
				t.Fatal("CLI accepted invalid controller report")
			}
		})
	}
	for _, cutoff := range []string{"degraded", "unavailable"} {
		t.Run("valid report with "+cutoff+" cutoff", func(t *testing.T) {
			status := base
			status.ProcessCutoff = cutoff
			if err := writeNodeInterventionStatus(ctx, dbPath, status); err != nil {
				t.Fatal(err)
			}
			got, ok := provider()
			if !ok || got.DirectControl != orgcontract.DirectControlUnavailable || got.Coverage != "proxy_only" {
				t.Fatalf("unusable process control reported as coverage: %+v, reported=%v", got, ok)
			}
			if line := nodeInterventionStatusLine(ctx, st, dbPath); !strings.Contains(line, "process_cutoff="+cutoff) {
				t.Fatalf("local report lost its diagnostic capability state: %s", line)
			}
		})
	}
	if nodeInterventionStatusPath(dbPath) == nodeInterventionStatusPath(filepath.Join(filepath.Dir(dbPath), "another.db")) {
		t.Fatal("two databases share a controller report")
	}
}

// TestNodeInterventionCaptureReportIsBoundedAndPerActiveTool pins the honesty
// surface added with the accounting-readiness correction (2026-09-14): an
// operator who sees a process stopped must be able to read WHICH tool's
// accounting source failed, without the report growing an unbounded field.
func TestNodeInterventionCaptureReportIsBoundedAndPerActiveTool(t *testing.T) {
	long := strings.Repeat("d", 4096)
	capture := watcher.NodeBudgetCaptureStatus{Sources: map[string]watcher.BudgetCaptureStatus{
		"opencode": {Ready: true, Reason: watcher.BudgetCaptureReasonReady, FilesSeen: 3, FilesProcessed: 3},
		"muse": {
			Reason: watcher.BudgetCaptureReasonParseError,
			Detail: long + "\nwith a control character",
		},
		"fresh": {Reason: watcher.BudgetCaptureReasonMissingRoot, Detail: "no adapter watch root exists"},
		// Structurally unreadable: the allow list excludes the adapter, so
		// nothing on this node ever captures its spend.
		"blocked": {Reason: watcher.BudgetCaptureReasonAllowFiltered, Detail: "the watcher allow list excludes this adapter"},
		// Native usage this node cannot read at all: the DECISION refused it,
		// so the report must too, even though the watcher status looks clean.
		"nonative": {Ready: true, Reason: watcher.BudgetCaptureReasonReady},
	}}
	activeTools := []string{"opencode", "muse", "fresh", "blocked", "nonative", "never-scanned"}
	resolved := make(map[string]nodeInterventionSource, len(activeTools))
	for _, tool := range activeTools {
		resolved[tool] = nodeInterventionResolveSource(tool, true, tool != "nonative", capture.Sources[tool])
	}
	got := nodeInterventionCaptureReport(activeTools, resolved, capture)
	if len(got) != 6 {
		t.Fatalf("capture report = %+v, want one row per active tool", got)
	}
	if got["nonative"].Ready || got["nonative"].Delayed || got["nonative"].Reason != "native_usage_unavailable" {
		t.Fatalf("no-native-usage tool row = %+v; the report must answer as the decision did", got["nonative"])
	}
	if !got["opencode"].Ready || got["opencode"].Delayed ||
		got["opencode"].Reason != watcher.BudgetCaptureReasonReady || got["opencode"].FilesSeen != 3 {
		t.Fatalf("ready tool row = %+v", got["opencode"])
	}
	// A tool with no store on this machine has produced no spend; it is
	// accounting-ready even though no strict catchup ran.
	if !got["fresh"].Ready || got["fresh"].Reason != watcher.BudgetCaptureReasonMissingRoot {
		t.Fatalf("missing-root tool row = %+v", got["fresh"])
	}
	// Ruling 2026-09-15: a parse error against the tail a running tool is
	// writing is DELAYED, not unavailable. It stays ready - the measured total
	// decides - and reports itself delayed with the reason retained.
	if !got["muse"].Ready || !got["muse"].Delayed || got["muse"].Reason != watcher.BudgetCaptureReasonParseError {
		t.Fatalf("delayed tool row = %+v", got["muse"])
	}
	if got["blocked"].Ready || got["blocked"].Delayed ||
		got["blocked"].Reason != watcher.BudgetCaptureReasonAllowFiltered {
		t.Fatalf("structurally unavailable tool row = %+v", got["blocked"])
	}
	if len(got["muse"].Detail) > nodeInterventionCaptureDetailMax ||
		strings.ContainsAny(got["muse"].Detail, "\n\r") {
		t.Fatalf("detail escaped its bound: %d bytes %q", len(got["muse"].Detail), got["muse"].Detail)
	}
	// A tool the pass produced no status for is unavailable, never a silent
	// zero.
	if got["never-scanned"].Ready || got["never-scanned"].Reason != watcher.BudgetCaptureReasonMissingStatus {
		t.Fatalf("unscanned tool row = %+v", got["never-scanned"])
	}
	if nodeInterventionCaptureReport(nil, resolved, capture) != nil {
		t.Fatal("no active tools produced a capture map")
	}

	base := nodeInterventionStatus{
		State: "partial", ProcessCutoff: "active", ExecutionAdmission: "unavailable",
		RequestAdmission: "unavailable", Reason: "ok", Capture: got,
	}
	if !validNodeInterventionStatus(base) {
		t.Fatal("bounded capture report rejected")
	}
	for _, tc := range []struct {
		name    string
		capture map[string]nodeInterventionCaptureStatus
	}{
		{"forged control characters", map[string]nodeInterventionCaptureStatus{"muse": {Reason: "parse\nerror"}}},
		{"unbounded detail", map[string]nodeInterventionCaptureStatus{"muse": {Detail: long}}},
		{"unnamed tool", map[string]nodeInterventionCaptureStatus{"": {Reason: "ready"}}},
		{"negative counters", map[string]nodeInterventionCaptureStatus{"muse": {FilesSeen: -1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := base
			status.Capture = tc.capture
			if validNodeInterventionStatus(status) {
				t.Fatalf("invalid capture report accepted: %+v", tc.capture)
			}
		})
	}

	// The two lists are disjoint: a delayed tool denies nothing, so it must
	// never be reported as an unavailable accounting source (ruling
	// 2026-09-15).
	line := nodeInterventionUnreadyCapture(got)
	if line != "blocked=allow_filtered_adapter, never-scanned=no_capture_status, nonative=native_usage_unavailable" {
		t.Fatalf("status line capture summary = %q", line)
	}
	delayed := nodeInterventionDelayedCapture(got)
	if delayed != "muse=parse_error" {
		t.Fatalf("status line delayed summary = %q", delayed)
	}
	if nodeInterventionUnreadyCapture(map[string]nodeInterventionCaptureStatus{"muse": {Ready: true}}) != "" {
		t.Fatal("a healthy tool appeared in the exception report")
	}
	if nodeInterventionDelayedCapture(map[string]nodeInterventionCaptureStatus{"muse": {Ready: true}}) != "" {
		t.Fatal("a healthy tool appeared in the delayed report")
	}
}

// TestNodeInterventionCaptureUsableIsASanityBoundNotAFreshnessFence pins the
// replacement of the five-second fence. Earlier workloads in a pass can
// consume their TERM/KILL deadlines; a later workload in the same cycle must
// still be decided on the capture result the cycle produced.
func TestNodeInterventionCaptureUsableIsASanityBoundNotAFreshnessFence(t *testing.T) {
	now := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"no pass ran", time.Time{}, false},
		{"same instant", now, true},
		{"after a short term wait", now.Add(-3 * time.Second), true},
		{"after a full supervisor pass", now.Add(-30 * time.Second), true},
		{"just inside the sanity bound", now.Add(-nodeInterventionCaptureMaxAge), true},
		{"beyond the sanity bound", now.Add(-nodeInterventionCaptureMaxAge - time.Second), false},
		{"clock moved backwards", now.Add(time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeInterventionCaptureUsable(tc.at, now); got != tc.want {
				t.Fatalf("usable = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestTruncateNodeInterventionDetailKeepsRunesWhole pins the report against a
// detail that carries a multi-byte local source path. Byte-slicing one cut a
// rune in half; json.Marshal then wrote U+FFFD in its place, three bytes where
// the fragment was one or two, so the field came back OVER the validator's
// bound and every reader rejected the whole report as invalid.
func TestTruncateNodeInterventionDetailKeepsRunesWhole(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		detail string
	}{
		{"ascii under the bound", "stat source /home/dev/.muse/sessions/a.jsonl: permission denied"},
		{"multi-byte path", "stat source /home/dev/Projets/" + strings.Repeat("é", 300) + "/a.jsonl: permission denied"},
		{"multi-byte at every cut offset", strings.Repeat("字", 400)},
		{"four-byte runes", strings.Repeat("🙂", 400)},
		{"mixed widths", strings.Repeat("aé字🙂", 200)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateNodeInterventionDetail(tc.detail)
			if len(got) > nodeInterventionCaptureDetailMax {
				t.Fatalf("detail = %d bytes, want at most %d", len(got), nodeInterventionCaptureDetailMax)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("detail is not valid UTF-8: %q", got)
			}
			// The validator runs on what a reader unmarshals, so the round
			// trip - not just the in-memory string - has to stay in bounds.
			raw, err := json.Marshal(nodeInterventionCaptureStatus{Reason: "x", Detail: got})
			if err != nil {
				t.Fatal(err)
			}
			var back nodeInterventionCaptureStatus
			if err := json.Unmarshal(raw, &back); err != nil {
				t.Fatal(err)
			}
			if len(back.Detail) > nodeInterventionCaptureDetailMax {
				t.Fatalf("marshalled detail grew to %d bytes", len(back.Detail))
			}
			if !validNodeInterventionCapture(map[string]nodeInterventionCaptureStatus{"muse": back}) {
				t.Fatalf("truncated detail failed its own validator: %q", back.Detail)
			}
		})
	}
}

// TestNodeInterventionStatusWriteCadence pins R11 of the accounting-readiness
// correction: an idle controller may rewrite its report on the slower cadence,
// and the reader's freshness bound follows the same split, so a slowed idle
// loop never makes a healthy controller look stale - while a report that
// claims live reconciliation is still held to the fast bound.
func TestNodeInterventionStatusWriteCadence(t *testing.T) {
	base := nodeInterventionStatus{
		At: time.Now().UTC(), State: "partial", ProcessCutoff: "active",
		ExecutionAdmission: "unavailable", RequestAdmission: "unavailable", Reason: "ok",
	}
	first := nodeInterventionStatusFingerprint(base)
	if first == nil {
		t.Fatal("status fingerprint unavailable")
	}
	later := base
	later.At = base.At.Add(time.Hour)
	if !bytes.Equal(first, nodeInterventionStatusFingerprint(later)) {
		t.Fatal("timestamp alone changed the fingerprint; an idle controller would rewrite every cycle")
	}
	changed := base
	changed.StoppedProcesses++
	if bytes.Equal(first, nodeInterventionStatusFingerprint(changed)) {
		t.Fatal("a content change did not change the fingerprint")
	}

	for _, tc := range []struct {
		name  string
		state string
		want  time.Duration
	}{
		{"live reconciliation", "partial", 15 * time.Second},
		{"idle, no managed authority", "not_required", nodeInterventionIdleInterval + 15*time.Second},
		{"idle, control unavailable", "control_unavailable", nodeInterventionIdleInterval + 15*time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := base
			status.State = tc.state
			if got := nodeInterventionStatusMaxAge(status); got != tc.want {
				t.Fatalf("max age = %s, want %s", got, tc.want)
			}
		})
	}
	if nodeInterventionStatusRefresh >= nodeInterventionStatusMaxAge(base) {
		t.Fatal("skipping identical writes can outlive the fast freshness bound")
	}

	for _, tc := range []struct {
		name       string
		authorized bool
		err        error
		want       time.Duration
	}{
		{"managed with authority", true, nil, nodeInterventionInterval},
		{"authority could not be verified", false, errors.New("unavailable"), nodeInterventionInterval},
		{"no managed authority", false, nil, nodeInterventionIdleInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeInterventionCadence(tc.authorized, tc.err); got != tc.want {
				t.Fatalf("cadence = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestNodeInterventionUnclassifiedSurfacesAreScopedPerSurface pins that a
// surface which could not classify an observed invocation is reported by name
// and does not degrade the node's process cutoff. Coverage is per surface; a
// node-wide downgrade would say every other surface is uncovered too.
func TestNodeInterventionUnclassifiedSurfacesAreScopedPerSurface(t *testing.T) {
	base := nodeInterventionStatus{
		State: "partial", ProcessCutoff: "active", ExecutionAdmission: "unavailable",
		RequestAdmission: "unavailable", Reason: "ok",
		UnclassifiedSurfaces: []string{"muse/cli", "opencode/cli"},
	}
	if !validNodeInterventionStatus(base) {
		t.Fatal("bounded unclassified-surface list rejected")
	}
	if base.ProcessCutoff != "active" {
		t.Fatal("an unclassified invocation must not degrade node-wide cutoff")
	}
	for _, tc := range []struct {
		name     string
		surfaces []string
	}{
		{"unsorted", []string{"opencode/cli", "muse/cli"}},
		{"duplicated", []string{"muse/cli", "muse/cli"}},
		{"empty id", []string{""}},
		{"control characters", []string{"muse/cli\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := base
			status.UnclassifiedSurfaces = tc.surfaces
			if validNodeInterventionStatus(status) {
				t.Fatalf("invalid unclassified-surface list accepted: %q", tc.surfaces)
			}
		})
	}
}
