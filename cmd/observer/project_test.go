package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestResolveProjectArgNumericID pins the id branch of resolveProjectArg:
// a positive integer argument is used AS-IS and never touches the store
// (resolveProjectArg returns before dereferencing st), so a nil *store.
// Store is safe here — no database needed.
func TestResolveProjectArgNumericID(t *testing.T) {
	cases := []struct {
		arg     string
		wantID  int64
		wantErr bool
	}{
		{arg: "42", wantID: 42},
		{arg: "1", wantID: 1},
		{arg: "9999999999", wantID: 9999999999},
	}
	for _, tc := range cases {
		t.Run(tc.arg, func(t *testing.T) {
			id, err := resolveProjectArg(context.Background(), nil, tc.arg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("resolveProjectArg(%q) = %d, nil; want an error", tc.arg, id)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveProjectArg(%q) unexpected error: %v", tc.arg, err)
			}
			if id != tc.wantID {
				t.Errorf("resolveProjectArg(%q) = %d, want %d", tc.arg, id, tc.wantID)
			}
		})
	}
}

// TestResolveProjectArgRoot covers the root-path branch: a non-numeric
// argument (or a non-positive integer, which fails resolveProjectArg's
// id>0 check and falls through to the root path) is resolved via
// store.ProjectIDForRoot — the same root-to-id resolver the dashboard and
// the loc-tracking editor-save path use. This needs a real store, so it
// seeds a tiny temp database (the predict_test.go / tasks_test.go
// pattern in this package).
func TestResolveProjectArgRoot(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "o.db")
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	root := filepath.Join(dir, "myproject")
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-09-21T00:00:00Z') RETURNING id`,
		root).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	st := store.New(database)

	t.Run("known root resolves", func(t *testing.T) {
		id, err := resolveProjectArg(ctx, st, root)
		if err != nil {
			t.Fatalf("resolveProjectArg(%q): %v", root, err)
		}
		if id != projectID {
			t.Errorf("resolveProjectArg(%q) = %d, want %d", root, id, projectID)
		}
	})

	t.Run("relative-form root resolves via Abs+Clean", func(t *testing.T) {
		rel, err := filepath.Rel(".", root)
		if err != nil {
			t.Skipf("no relative form from cwd: %v", err)
		}
		id, err := resolveProjectArg(ctx, st, rel)
		if err != nil {
			t.Fatalf("resolveProjectArg(%q): %v", rel, err)
		}
		if id != projectID {
			t.Errorf("resolveProjectArg(%q) = %d, want %d", rel, id, projectID)
		}
	})

	t.Run("unknown root errors with a clear message", func(t *testing.T) {
		unknown := filepath.Join(dir, "no-such-project")
		_, err := resolveProjectArg(ctx, st, unknown)
		if err == nil {
			t.Fatalf("resolveProjectArg(%q): want an error, got nil", unknown)
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("resolveProjectArg(%q) error = %q, want it to mention \"not found\"", unknown, err.Error())
		}
	})

	t.Run("zero/negative numeric argument falls through to root lookup", func(t *testing.T) {
		_, err := resolveProjectArg(ctx, st, "0")
		if err == nil {
			t.Fatal("resolveProjectArg(\"0\"): want an error (falls through to an unknown root path), got nil")
		}
	})
}

// TestFormatROIValue pins the CLI's per-unit rendering — every unit value
// internal/projectroi.Proxies (via toRoiTiles' ratio→pct mapping) can
// hand back.
func TestFormatROIValue(t *testing.T) {
	cases := []struct {
		unit string
		v    float64
		want string
	}{
		{"usd", 3.5, "$3.50"},
		{"pct", 0.256, "25.6%"},
		{"count", 7, "7"},
		{"usd_per_line", 0.01234, "$0.0123/line"},
		{"usd_per_commit", 12.5, "$12.50/commit"},
		{"widgets", 3, "3 widgets"},
	}
	for _, tc := range cases {
		t.Run(tc.unit, func(t *testing.T) {
			got := formatROIValue(tc.v, tc.unit)
			if got != tc.want {
				t.Errorf("formatROIValue(%v, %q) = %q, want %q", tc.v, tc.unit, got, tc.want)
			}
		})
	}
}

// TestPrintProjectDetail_TasksAvailability pins 2026-09-22 rework
// finding #11: the CLI must never print the raw task_items fallback
// Total/Done/CostUSD numbers when the task-lifecycle rollup failed
// (Tasks.Available == false) — those figures are a different, degraded
// count than the Tasks tab renders, and printing them next to a formula
// implies a real, exact measurement. Available == true still renders the
// real numbers.
func TestPrintProjectDetail_TasksAvailability(t *testing.T) {
	t.Run("unavailable", func(t *testing.T) {
		var d dashboard.ProjectDetail
		d.Tasks.Total = 99
		d.Tasks.Done = 50
		d.Tasks.CostUSD = 123.45
		d.Tasks.Available = false
		var buf strings.Builder
		printProjectDetail(&buf, d)
		out := buf.String()
		if !strings.Contains(out, "tasks: unavailable (rollup failed)") {
			t.Errorf("output missing the unavailable line:\n%s", out)
		}
		if strings.Contains(out, "99") || strings.Contains(out, "50") || strings.Contains(out, "123.45") {
			t.Errorf("output must not print the degraded fallback numbers when unavailable:\n%s", out)
		}
	})

	t.Run("available", func(t *testing.T) {
		var d dashboard.ProjectDetail
		d.Tasks.Total = 10
		d.Tasks.Done = 4
		d.Tasks.CostUSD = 2.5
		d.Tasks.Available = true
		var buf strings.Builder
		printProjectDetail(&buf, d)
		out := buf.String()
		if !strings.Contains(out, "total: 10, done: 4, cost: $2.50") {
			t.Errorf("output missing the real task numbers when available:\n%s", out)
		}
		if strings.Contains(out, "unavailable") {
			t.Errorf("output must not claim unavailable when Tasks.Available is true:\n%s", out)
		}
	})
}

// TestPrintProjectSkills pins the `observer project --skills` table: the
// three facts stay separate columns, an unmeasurable invocation count reads
// "not measurable" (never 0), versions render as "#<ordinal> <id>", a
// changed-during-session run names both versions, and the empty state
// says so instead of printing an empty table.
func TestPrintProjectSkills(t *testing.T) {
	var empty strings.Builder
	printProjectSkills(&empty, dashboard.ProjectSkills{RootPath: "/r", WindowDays: 30})
	if !strings.Contains(empty.String(), "No skills found") || !strings.Contains(empty.String(), "not scanned yet") {
		t.Errorf("empty output = %q", empty.String())
	}

	var p dashboard.ProjectSkills
	raw := `{"root_path":"/r","window_days":30,"capture":{"observed_since":"2026-09-20T00:00:00Z","git":{"state":"ok","reflog_since":"2026-09-01T00:00:00Z"}},
	 "skills":[
	  {"key":"project:.claude/skills/deploy","scope":"project","name":"deploy",
	   "current":{"in_git":"committed","worktree":"modified","head_version":"aaaaaaaa"},
	   "versions":[{"id":"aaaaaaaa","ordinal":1},{"id":"bbbbbbbb","ordinal":2}],
	   "commits":[{"sha":"1111111111","status":"A","skill_md_changed":true,"reachable":true,"version":"aaaaaaaa","subject":"add"}],
	   "invocations":{"measurable":true,"count":0}},
	  {"key":"user:~/.claude/skills/tidy","scope":"user","name":"tidy",
	   "current":{"in_git":"not_in_project_git"},"versions":[],"commits":[],"invocations":{"measurable":false}}],
	 "spans":[{"skill_key":"project:.claude/skills/deploy","from":"a","to":"b","sessions":2,
	   "observed":{"state":"changed_during_session","changed":["aaaaaaaa","bbbbbbbb"]},"head":{"state":"committed","version":"aaaaaaaa"}},
	  {"skill_key":"user:~/.claude/skills/tidy","sessions":1,"observed":{"state":"not_captured"},"head":{"state":"not_in_project_git"}}],
	 "unmatched_invocations":[{"tool":"claude-code","name":"superpowers:plan","count":2}]}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	printProjectSkills(&out, p)
	got := out.String()
	for _, want := range []string{
		"committed, uncommitted changes", "#1 aaaaaaaa", "none captured", "not measurable",
		"changed: #1 aaaaaaaa -> #2 bbbbbbbb", "not captured", "not in project git",
		"superpowers:plan x2", "home directory",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}
