package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newTestDialectRunner builds a runner over a temp home + temp DB —
// constructing the struct directly so tests control home instead of
// os.UserHomeDir (the newTestMCPRunner pattern).
func newTestDialectRunner(t *testing.T) (*dialectRunner, *store.Store, string) {
	t.Helper()
	ctx := context.Background()
	home := t.TempDir()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	g, err := guard.New(guard.Options{Config: config.Default().Guard, Home: home})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	r := &dialectRunner{
		st: st, g: g, home: home,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return r, st, home
}

// dropDenyEntry rewrites a settings.json removing one deny entry —
// the user-edited-away-from-policy drift shape.
func dropDenyEntry(t *testing.T, path, entry string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	var perms struct {
		Deny []string        `json:"deny"`
		Ask  json.RawMessage `json:"ask"`
	}
	if err := json.Unmarshal(settings["permissions"], &perms); err != nil {
		t.Fatalf("parse permissions: %v", err)
	}
	kept := perms.Deny[:0]
	found := false
	for _, v := range perms.Deny {
		if v == entry {
			found = true
			continue
		}
		kept = append(kept, v)
	}
	if !found {
		t.Fatalf("entry %q not present to drop", entry)
	}
	perms.Deny = kept
	pb, _ := json.Marshal(perms)
	settings["permissions"] = pb
	out, _ := json.MarshalIndent(settings, "", "  ")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}
}

// TestDialectCompileDriftLifecycle is the §13.2 end-to-end over a
// real temp home + real DB: compile writes + pins; a clean drift
// check stays quiet; a hand-edit that removes a managed entry fires
// exactly one R-204 and drifts the pin; a repeat check stays silent
// (already-known gate); recompile restores the entry and re-pins; the
// final check is quiet again.
func TestDialectCompileDriftLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r, st, home := newTestDialectRunner(t)
	settings := filepath.Join(home, ".claude", "settings.json")

	// Compile + write + pin.
	reports := r.CompileTargets(ctx, []string{"claude-code"}, true, false)
	if len(reports) != 1 || !reports[0].Wrote || !reports[0].Pinned || len(reports[0].Issues) != 0 {
		t.Fatalf("compile reports = %+v", reports)
	}
	if len(reports[0].Added) == 0 || len(reports[0].Removed) != 0 {
		t.Fatalf("first compile added %d / removed %d", len(reports[0].Added), len(reports[0].Removed))
	}
	if _, err := os.Stat(settings); err != nil {
		t.Fatalf("settings.json not written: %v", err)
	}
	pins, err := st.LoadGuardPins(ctx, "native_dialect")
	if err != nil || len(pins) != 1 || pins[0].Name != "claude-code" || pins[0].Status != "pinned" {
		t.Fatalf("pins = %+v, %v", pins, err)
	}

	// Compliant drift check: quiet.
	sum := r.CheckDrift(ctx)
	if sum.Checked != 1 || len(sum.Drifted) != 0 || sum.EventsRecorded != 0 {
		t.Fatalf("clean drift check = %+v", sum)
	}

	// The operator (or an agent) edits a managed deny entry away.
	dropDenyEntry(t, settings, "Bash(mkfs:*)")
	sum = r.CheckDrift(ctx)
	if len(sum.Drifted) != 1 || sum.EventsRecorded != 1 {
		t.Fatalf("drifted check = %+v", sum)
	}
	pins, _ = st.LoadGuardPins(ctx, "native_dialect")
	if pins[0].Status != "drifted" {
		t.Fatalf("pin after drift = %+v", pins[0])
	}
	events, err := st.LoadRecentGuardEvents(ctx, time.Time{}, 100)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	r204 := 0
	for _, e := range events {
		if e.RuleID == "R-204" {
			r204++
			if e.Category != "posture" || e.Decision != "flag" {
				t.Errorf("R-204 row = category %s decision %s", e.Category, e.Decision)
			}
			if !strings.Contains(e.Reason, "missing") {
				t.Errorf("R-204 reason %q lacks the drift detail", e.Reason)
			}
		}
	}
	if r204 != 1 {
		t.Fatalf("R-204 events = %d, want 1", r204)
	}

	// Re-check while still drifted: no event spam.
	sum = r.CheckDrift(ctx)
	if len(sum.Drifted) != 1 || sum.EventsRecorded != 0 {
		t.Fatalf("repeat drift check = %+v", sum)
	}

	// Recompile: entry restored, pin back to pinned, checks quiet.
	reports = r.CompileTargets(ctx, []string{"claude-code"}, true, false)
	if len(reports) != 1 || !reports[0].Wrote || len(reports[0].Added) != 1 {
		t.Fatalf("recompile reports = %+v", reports)
	}
	pins, _ = st.LoadGuardPins(ctx, "native_dialect")
	if pins[0].Status != "pinned" {
		t.Fatalf("pin after recompile = %+v", pins[0])
	}
	sum = r.CheckDrift(ctx)
	if len(sum.Drifted) != 0 || sum.EventsRecorded != 0 {
		t.Fatalf("post-recompile drift check = %+v", sum)
	}
}

// TestDialectCompile_DiffAndRequireExisting pins the read-only diff
// pass (nothing written, nothing pinned) and the requireExisting gate
// (absent config → skipped, never created).
func TestDialectCompile_DiffAndRequireExisting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r, st, home := newTestDialectRunner(t)

	reports := r.CompileTargets(ctx, []string{"claude-code"}, false, false)
	if len(reports) != 1 || reports[0].Wrote || reports[0].Pinned || len(reports[0].Added) == 0 {
		t.Fatalf("diff reports = %+v", reports)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatal("diff pass created the settings file")
	}
	if pins, _ := st.LoadGuardPins(ctx, "native_dialect"); len(pins) != 0 {
		t.Fatalf("diff pass pinned: %+v", pins)
	}

	// No explicit selection + missing file: skipped, not created.
	reports = r.CompileTargets(ctx, nil, true, true)
	skipped := 0
	for _, rep := range reports {
		if rep.Skipped != "" {
			skipped++
		} else if rep.Wrote {
			t.Fatalf("requireExisting wrote %s", rep.Path)
		}
	}
	if skipped == 0 {
		t.Fatal("no target reported the requireExisting skip")
	}

	// CheckDrift with zero pins: silent (never-compiled installs are
	// baseline-quiet).
	if sum := r.CheckDrift(ctx); sum.Checked != 0 || sum.EventsRecorded != 0 {
		t.Fatalf("unpinned drift check = %+v", sum)
	}
}

// TestDialectCompile_OpenCodeTarget covers the second implemented
// dialect end-to-end at the runner level: explicit selection creates
// the XDG-style config with managed bash entries and pins it.
func TestDialectCompile_OpenCodeTarget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	r, st, home := newTestDialectRunner(t)

	reports := r.CompileTargets(ctx, []string{"opencode"}, true, false)
	if len(reports) != 1 || !reports[0].Wrote || !reports[0].Pinned {
		t.Fatalf("opencode compile = %+v", reports)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".config", "opencode", "opencode.json"))
	if err != nil {
		t.Fatalf("opencode.json: %v", err)
	}
	if !strings.Contains(string(raw), `"mkfs*": "deny"`) {
		t.Errorf("opencode.json missing managed entry:\n%s", raw)
	}
	pins, _ := st.LoadGuardPins(ctx, "native_dialect")
	if len(pins) != 1 || pins[0].Name != "opencode" || pins[0].Client != "opencode" {
		t.Fatalf("pins = %+v", pins)
	}

	// Unknown / deferred dialect names surface as issues, not writes.
	reports = r.CompileTargets(ctx, []string{"windsurf", "nope"}, true, false)
	issues := 0
	for _, rep := range reports {
		issues += len(rep.Issues)
		if rep.Wrote {
			t.Fatalf("deferred/unknown dialect wrote: %+v", rep)
		}
	}
	if issues != 2 {
		t.Fatalf("issues = %d, want 2 (deferred windsurf + unknown nope)", issues)
	}
}
