package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// nodeInterventionStatus is a local operational report. Readiness does not
// authorize actions: the daemon resolves durable authority separately before
// every signal. No shell arguments and no credentials land here, and a stale
// file must never be displayed as a live controller.
//
// It is not path-free: a capture row's Detail may quote a LOCAL source path
// the strict pass could not read, because that path is the only actionable
// thing an operator has when a tool's accounting breaks. The file sits beside
// the node database and is written 0600, so the path discloses nothing the
// reader could not already stat. Do not strip it.
type nodeInterventionStatus struct {
	At                  time.Time             `json:"at"`
	Controller          intervention.Identity `json:"controller"`
	Authority           string                `json:"authority,omitempty"`
	State               string                `json:"state"`
	Reason              string                `json:"reason"`
	ProcessCutoff       string                `json:"process_cutoff"`
	ExecutionAdmission  string                `json:"execution_admission"`
	RequestAdmission    string                `json:"request_admission"`
	ManifestFingerprint string                `json:"manifest_fingerprint,omitempty"`
	ControlledSurfaces  []string              `json:"controlled_surfaces,omitempty"`
	BoundProcesses      int                   `json:"bound_processes"`
	StoppedProcesses    int                   `json:"stopped_processes"`
	UnavailableSurfaces []string              `json:"unavailable_surfaces,omitempty"`
	// UnclassifiedSurfaces names the dedicated surfaces that abstained on at
	// least one observed process because its leading argument was neither a
	// declared CLI nor a declared non-billable form. It is per SURFACE, and it
	// does NOT degrade node-wide process cutoff: one surface's unclassified
	// invocation says nothing about another surface's coverage. Sorted,
	// deduplicated, and free of paths, arguments and identities.
	UnclassifiedSurfaces []string `json:"unclassified_surfaces,omitempty"`
	// Capture reports, per ACTIVE tool, whether that tool's own accounting
	// source was established for the cycle. It is honesty context for an
	// operator reading a stop decision, never an authorization input: the
	// decision itself is taken from the live capture result, not from this file.
	Capture map[string]nodeInterventionCaptureStatus `json:"capture,omitempty"`
}

// nodeInterventionCaptureStatus is one tool's bounded capture report: a reason
// constant, a truncated detail, and two counters. It holds no argument and no
// credential. Detail MAY quote a local source path (the file the strict pass
// could not read), bounded to nodeInterventionCaptureDetailMax bytes and
// stripped of control characters.
type nodeInterventionCaptureStatus struct {
	Ready bool `json:"ready"`
	// Delayed records that the strict tail catch-up did not complete this
	// cycle while the source itself stayed intact: the decision was taken on
	// the measured total already in the store, and the newest tail lands on a
	// later pass. A delayed tool stays Ready (ruling 2026-09-15).
	Delayed        bool   `json:"delayed,omitempty"`
	Reason         string `json:"reason,omitempty"`
	Detail         string `json:"detail,omitempty"`
	FilesSeen      int    `json:"files_seen,omitempty"`
	FilesProcessed int    `json:"files_processed,omitempty"`
}

const (
	// nodeInterventionCaptureDetailMax bounds the operator-facing detail copied
	// into the status file; the capture layer's own detail budget is larger.
	nodeInterventionCaptureDetailMax = 200
	// nodeInterventionCaptureToolsMax bounds the report to a plausible number of
	// concurrently active adapters.
	nodeInterventionCaptureToolsMax = 64
)

// nodeInterventionCaptureReport projects the cycle's capture result onto the
// bounded status shape, for the active tools only.
//
// Ready, Delayed and Reason come from the RESOLVED source - the same
// (class, reason) the budget decision was taken from - so the report can never
// call a tool ready that the cycle refused to decide on, or name a reason the
// decision never applied. The raw watcher status supplies only the operator
// context the resolve step does not carry: the detail, and the two counters.
func nodeInterventionCaptureReport(activeTools []string, resolved map[string]nodeInterventionSource, capture watcher.NodeBudgetCaptureStatus) map[string]nodeInterventionCaptureStatus {
	if len(activeTools) == 0 {
		return nil
	}
	out := make(map[string]nodeInterventionCaptureStatus, len(activeTools))
	for _, tool := range activeTools {
		if tool == "" || len(out) >= nodeInterventionCaptureToolsMax {
			continue
		}
		source := capture.Sources[tool]
		decided, ok := resolved[tool]
		if !ok {
			// No workload resolved this tool in this cycle. Report the raw
			// source's own reason and stay fail-closed, exactly as a decision
			// on an unresolved tool would be.
			decided = nodeInterventionSource{Tool: tool, Reason: source.AccountingReason()}
		}
		out[tool] = nodeInterventionCaptureStatus{
			Ready:          decided.Ready,
			Delayed:        decided.Delayed,
			Reason:         decided.Reason,
			Detail:         truncateNodeInterventionDetail(source.Detail),
			FilesSeen:      source.FilesSeen,
			FilesProcessed: source.FilesProcessed,
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// truncateNodeInterventionDetail bounds one operator detail to
// nodeInterventionCaptureDetailMax BYTES without splitting a rune.
//
// It used to byte-slice. A multi-byte path cut mid-rune marshalled as U+FFFD,
// which is three bytes where the fragment was one or two - so the field came
// back OVER the validator's bound and every reader rejected the whole report
// as invalid, including the launch gate that has to fail open on one.
func truncateNodeInterventionDetail(detail string) string {
	detail = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, detail)
	if len(detail) <= nodeInterventionCaptureDetailMax {
		return detail
	}
	const ellipsis = "..."
	limit := nodeInterventionCaptureDetailMax - len(ellipsis)
	for limit > 0 && !utf8.ValidString(detail[:limit]) {
		limit--
	}
	return detail[:limit] + ellipsis
}

// nodeInterventionStatusFingerprint is the report's content WITHOUT its
// timestamp, so an idle controller can skip rewriting an identical file. A
// marshal failure returns nil, which the caller treats as "always write".
func nodeInterventionStatusFingerprint(status nodeInterventionStatus) []byte {
	status.At = time.Time{}
	raw, err := json.Marshal(status)
	if err != nil {
		return nil
	}
	return raw
}

// nodeInterventionStatusWriter rewrites the controller report only when its
// content changed, or when the last copy is old enough that a reader could
// call it stale. The report is otherwise identical on every idle cycle, and
// the loop runs for the life of the daemon on every node.
type nodeInterventionStatusWriter struct {
	body []byte
	at   time.Time
}

// write persists the report when it is due and records what was written. A
// failed write is reported and leaves the previous record in place, so the
// next cycle retries.
func (w *nodeInterventionStatusWriter) write(ctx context.Context, dbPath string, status nodeInterventionStatus) error {
	body := nodeInterventionStatusFingerprint(status)
	if body != nil && bytes.Equal(body, w.body) && time.Since(w.at) < nodeInterventionStatusRefresh {
		return nil
	}
	if err := writeNodeInterventionStatus(ctx, dbPath, status); err != nil {
		return err
	}
	w.body, w.at = body, time.Now()
	return nil
}

// nodeInterventionStatusMaxAge is the freshness bound a report must meet. A
// report that claims live reconciliation is held to the fast control cadence;
// an idle report (no managed authority, or control unavailable) is written on
// the slower cadence and is allowed to be correspondingly older.
func nodeInterventionStatusMaxAge(status nodeInterventionStatus) time.Duration {
	if status.State == "partial" {
		return 15 * time.Second
	}
	return nodeInterventionIdleInterval + 15*time.Second
}

func nodeInterventionStatusPath(dbPath string) string {
	// Multiple daemon databases may share a directory. A report belongs to
	// exactly one database, just like the daemon's in-process guard registry.
	key := sha256.Sum256([]byte(filepath.Clean(dbPath)))
	return filepath.Join(filepath.Dir(dbPath), fmt.Sprintf("node-intervention-%x.json", key[:12]))
}

func writeNodeInterventionStatus(ctx context.Context, dbPath string, status nodeInterventionStatus) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(nodeInterventionStatusPath(dbPath), raw, fsatomic.Options{TempPattern: ".node-intervention-*.tmp"})
}

func nodeInterventionStatusLine(ctx context.Context, st *store.Store, dbPath string) string {
	status, err := readNodeInterventionStatus(ctx, st, dbPath)
	if err != nil {
		return "unavailable - " + err.Error()
	}
	line := fmt.Sprintf("%s - process_cutoff=%s execution_admission=%s request_admission=%s; bound=%d stopped=%d; %s",
		status.State, status.ProcessCutoff, status.ExecutionAdmission, status.RequestAdmission, status.BoundProcesses, status.StoppedProcesses, status.Reason)
	if unready := nodeInterventionUnreadyCapture(status.Capture); unready != "" {
		line += "; accounting source unavailable: " + unready
	}
	if delayed := nodeInterventionDelayedCapture(status.Capture); delayed != "" {
		// A separate list, never folded into the one above: a delayed tail did
		// not deny anything, and reading it as "unavailable" is exactly the
		// confusion the 2026-09-15 ruling removed from the decision.
		line += "; accounting delayed (measured total used): " + delayed
	}
	if len(status.UnclassifiedSurfaces) > 0 {
		// Per-surface coverage gap, not a node-wide one: these surfaces saw a
		// process whose invocation their declaration could not classify.
		line += "; unclassified invocation on: " + strings.Join(status.UnclassifiedSurfaces, ", ")
	}
	return line
}

// nodeInterventionUnreadyCapture lists the active tools whose own accounting
// source is STRUCTURALLY unavailable, with the reason. A ready tool is
// omitted - including a merely delayed one, which belongs to the sibling list
// below: the line is an exception report, and a stopped process should be
// explainable from it without opening the status file.
func nodeInterventionUnreadyCapture(capture map[string]nodeInterventionCaptureStatus) string {
	return nodeInterventionCaptureList(capture, func(source nodeInterventionCaptureStatus) bool {
		return !source.Ready
	})
}

// nodeInterventionDelayedCapture lists the active tools whose newest tail did
// not land this cycle while their source stayed intact. Those tools were
// decided on their measured total; nothing was denied for this reason.
func nodeInterventionDelayedCapture(capture map[string]nodeInterventionCaptureStatus) string {
	return nodeInterventionCaptureList(capture, func(source nodeInterventionCaptureStatus) bool {
		return source.Ready && source.Delayed
	})
}

// nodeInterventionCaptureList renders the sorted "tool=reason" summary of the
// capture rows a selector accepts.
func nodeInterventionCaptureList(capture map[string]nodeInterventionCaptureStatus, include func(nodeInterventionCaptureStatus) bool) string {
	tools := make([]string, 0, len(capture))
	for tool, source := range capture {
		if include(source) {
			tools = append(tools, tool)
		}
	}
	sort.Strings(tools)
	parts := make([]string, 0, len(tools))
	for _, tool := range tools {
		parts = append(parts, tool+"="+capture[tool].Reason)
	}
	return strings.Join(parts, ", ")
}

func readNodeInterventionStatus(ctx context.Context, st *store.Store, dbPath string) (nodeInterventionStatus, error) {
	var status nodeInterventionStatus
	f, err := os.Open(nodeInterventionStatusPath(dbPath))
	if err != nil {
		return status, errors.New("no live controller report")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil || len(raw) > 64*1024 || json.Unmarshal(raw, &status) != nil {
		return status, errors.New("invalid controller report")
	}
	if !validNodeInterventionStatus(status) {
		return status, errors.New("invalid controller report")
	}
	age := time.Since(status.At)
	if status.At.IsZero() || age < 0 || age > nodeInterventionStatusMaxAge(status) {
		return status, errors.New("controller report is stale")
	}
	live, err := intervention.Inspect(ctx, status.Controller.PID)
	if err != nil || live != status.Controller {
		return status, errors.New("controller identity could not be verified")
	}
	auth, err := nodeInterventionAuthority(ctx, st, live.UID, time.Now().UTC())
	if err != nil || auth.Authority != status.Authority {
		return status, errors.New("controller enrollment changed or could not be verified")
	}
	return status, nil
}

func validNodeInterventionStatus(status nodeInterventionStatus) bool {
	switch status.State {
	case "pending_control", "partial", "control_unavailable", "not_required":
	default:
		return false
	}
	switch status.ProcessCutoff {
	case "active", "degraded", "unavailable":
	default:
		return false
	}
	return status.ExecutionAdmission == "unavailable" && status.RequestAdmission == "unavailable" &&
		status.BoundProcesses >= 0 && status.StoppedProcesses >= 0 && len(status.Reason) <= 2048 &&
		strings.IndexFunc(status.Reason, unicode.IsControl) < 0 && validNodeInterventionSurfaceWitness(status) &&
		validNodeInterventionCapture(status.Capture)
}

// validNodeInterventionCapture keeps the additive capture map inside the same
// bounds the rest of the report obeys: no control characters, no unbounded
// strings, and no unbounded number of entries.
func validNodeInterventionCapture(capture map[string]nodeInterventionCaptureStatus) bool {
	if len(capture) > nodeInterventionCaptureToolsMax {
		return false
	}
	for tool, source := range capture {
		if tool == "" || len(tool) > 128 || strings.IndexFunc(tool, unicode.IsControl) >= 0 {
			return false
		}
		if len(source.Reason) > 128 || strings.IndexFunc(source.Reason, unicode.IsControl) >= 0 {
			return false
		}
		if len(source.Detail) > nodeInterventionCaptureDetailMax ||
			strings.IndexFunc(source.Detail, unicode.IsControl) >= 0 {
			return false
		}
		if source.FilesSeen < 0 || source.FilesProcessed < 0 {
			return false
		}
	}
	return true
}

func validNodeInterventionSurfaceWitness(status nodeInterventionStatus) bool {
	if status.ManifestFingerprint != "" &&
		(len(status.ManifestFingerprint) != len("v1 ")+sha256.Size*2 || !strings.HasPrefix(status.ManifestFingerprint, "v1 ")) {
		return false
	}
	if len(status.ControlledSurfaces) > 128 ||
		(len(status.ControlledSurfaces) > 0 && status.ManifestFingerprint == "") {
		return false
	}
	if len(status.UnclassifiedSurfaces) > 128 {
		return false
	}
	previous := ""
	for _, id := range status.UnclassifiedSurfaces {
		if id == "" || id <= previous || strings.IndexFunc(id, unicode.IsControl) >= 0 {
			return false
		}
		previous = id
	}
	previous = ""
	for _, id := range status.ControlledSurfaces {
		if id == "" || id <= previous || strings.IndexFunc(id, unicode.IsControl) >= 0 {
			return false
		}
		previous = id
	}
	return true
}
