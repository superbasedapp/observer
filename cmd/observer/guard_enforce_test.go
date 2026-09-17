package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestGuardRulesDocInSync is the docs/guard-rules.md drift gate: the
// committed catalog must equal what the generator emits for the
// current built-in tables. A rule change without a regenerate fails
// here, never ships stale.
func TestGuardRulesDocInSync(t *testing.T) {
	t.Parallel()
	want := renderRuleCatalogMarkdown(policy.Catalog())
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "guard-rules.md"))
	if err != nil {
		t.Fatalf("read docs/guard-rules.md: %v", err)
	}
	// Normalize line endings — the generator emits LF; a Windows
	// checkout may materialize CRLF depending on git config.
	got := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if got != want {
		t.Error("docs/guard-rules.md is out of sync with the rule catalog — regenerate with `observer guard rules --markdown > docs/guard-rules.md` (raw-byte redirect; PowerShell `>` writes UTF-16)")
	}
}

// TestSetGuardConfigMode pins the surgical config edit: keys rewrite
// in place, comments and unrelated sections survive byte-for-byte,
// and a missing section appends.
func TestSetGuardConfigMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	t.Run("existing section edits in place", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(dir, "a.toml")
		body := "# my config\n[observer]\ndb_path = \"/x\" # keep me\n\n[guard]\n# posture comment\nmode = \"observe\"\nenabled = true\nretention_days = 365\n\n[proxy]\nport = 8820\n"
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := setGuardConfigMode(p, true, "enforce"); err != nil {
			t.Fatalf("setGuardConfigMode: %v", err)
		}
		got, _ := os.ReadFile(p)
		text := string(got)
		for _, want := range []string{
			`mode = "enforce"`, "enabled = true", "# posture comment",
			"retention_days = 365", `db_path = "/x" # keep me`, "[proxy]\nport = 8820",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("post-edit config missing %q:\n%s", want, text)
			}
		}
		if strings.Contains(text, `mode = "observe"`) {
			t.Error("old mode value survived the edit")
		}
	})

	t.Run("missing section appends", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(dir, "b.toml")
		if err := os.WriteFile(p, []byte("[observer]\ndb_path = \"/x\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := setGuardConfigMode(p, false, "off"); err != nil {
			t.Fatalf("setGuardConfigMode: %v", err)
		}
		got, _ := os.ReadFile(p)
		if !strings.Contains(string(got), "[guard]\nenabled = false\nmode = \"off\"") {
			t.Errorf("appended section wrong:\n%s", got)
		}
	})

	t.Run("missing file creates", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(dir, "c.toml")
		if err := setGuardConfigMode(p, true, "observe"); err != nil {
			t.Fatalf("setGuardConfigMode: %v", err)
		}
		got, _ := os.ReadFile(p)
		if !strings.Contains(string(got), "[guard]") {
			t.Errorf("created config wrong:\n%s", got)
		}
	})
}

// TestGuardApproveRevokeCmds drives the approvals register CLI
// end-to-end against a temp DB: grant, list, revoke.
func TestGuardApproveRevokeCmds(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)

	out, err := runGuardCmd(t, "approve", "R-110", "--global", "--ttl", "1h", "--config", cfgPath)
	if err != nil {
		t.Fatalf("approve: %v (%s)", err, out)
	}
	if !strings.Contains(out, "approval 1 granted: R-110 scope=global") {
		t.Errorf("approve output: %s", out)
	}

	out, err = runGuardCmd(t, "approvals", "--config", cfgPath)
	if err != nil {
		t.Fatalf("approvals: %v", err)
	}
	if !strings.Contains(out, "R-110") || !strings.Contains(out, "global") {
		t.Errorf("approvals list: %s", out)
	}

	// The grant is live in the store lookup the guard consults.
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	if !st.ApprovalActiveFor(context.Background(), "R-110", "any-session", "", time.Now().UTC()) {
		t.Error("global grant not visible to ApprovalActiveFor")
	}
	if st.ApprovalActiveFor(context.Background(), "R-101", "any-session", "", time.Now().UTC()) {
		t.Error("grant leaked to a different rule")
	}
	_ = database.Close()

	out, err = runGuardCmd(t, "revoke", "1", "--config", cfgPath)
	if err != nil {
		t.Fatalf("revoke: %v (%s)", err, out)
	}
	if _, err := runGuardCmd(t, "revoke", "1", "--config", cfgPath); err == nil {
		t.Error("double-revoke succeeded")
	}

	// Scope validation: zero or two scopes rejected.
	if _, err := runGuardCmd(t, "approve", "R-110", "--config", cfgPath); err == nil {
		t.Error("approve without a scope accepted")
	}
	if _, err := runGuardCmd(t, "approve", "R-110", "--global", "--session", "s1", "--config", cfgPath); err == nil {
		t.Error("approve with two scopes accepted")
	}
}

// TestGuardSimulateAndRescan covers the replay surfaces end to end —
// and doubles as the §18 simulation golden: the seeded history must
// produce the pinned verdict set (exactly one R-101) on every run.
func TestGuardSimulateAndRescan(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)

	// Seed history through the normal ingest path (no guard wired —
	// the live seam stays silent so rescan has something to find).
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	base := time.Now().UTC().Add(-time.Hour)
	if _, err := st.Ingest(context.Background(), []models.ToolEvent{
		// "rm -rf ~" fires R-101's home-targeting arm on every host
		// flavor — the outside-project arm would need the project root
		// and the host home to share a path flavor, which a synthetic
		// "/p" root on a Windows test host doesn't (mixed-flavor =
		// unknown = no-hit, the documented G1 convention).
		{
			SourceFile: "f", SourceEventID: "e1", SessionID: "sR", ProjectRoot: "/p",
			Timestamp: base, Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "rm -rf ~", Success: true,
		},
		{
			SourceFile: "f", SourceEventID: "e2", SessionID: "sR", ProjectRoot: "/p",
			Timestamp: base.Add(time.Second), Tool: models.ToolClaudeCode,
			ActionType: models.ActionRunCommand, Target: "go build ./...", Success: true,
		},
	}, nil, store.IngestOptions{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	countEvents := func() int {
		var n int
		if err := database.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM guard_events`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Simulate: pinned verdict set, nothing persists.
	out, err := runGuardCmd(t, "simulate", "--since", "24h", "--config", cfgPath)
	if err != nil {
		t.Fatalf("simulate: %v (%s)", err, out)
	}
	if !strings.Contains(out, "2 actions scanned, 1 verdicts") || !strings.Contains(out, "R-101") {
		t.Errorf("[§18 GOLDEN] simulate output diverged from the pinned verdict set:\n%s", out)
	}
	if countEvents() != 0 {
		t.Fatal("simulate persisted guard events — it must be a dry run")
	}

	// Rescan persists exactly the golden set; a second rescan adds zero.
	out, err = runGuardCmd(t, "rescan", "--since", "24h", "--config", cfgPath)
	if err != nil {
		t.Fatalf("rescan: %v (%s)", err, out)
	}
	if !strings.Contains(out, "persisted 1 new guard event(s)") {
		t.Errorf("rescan output: %s", out)
	}
	if countEvents() != 1 {
		t.Fatalf("guard_events = %d after rescan, want 1", countEvents())
	}
	out, err = runGuardCmd(t, "rescan", "--since", "24h", "--config", cfgPath)
	if err != nil {
		t.Fatalf("second rescan: %v", err)
	}
	if !strings.Contains(out, "persisted 0 new guard event(s)") || countEvents() != 1 {
		t.Errorf("rescan not idempotent: %s (rows=%d)", out, countEvents())
	}
	_ = database.Close()
}
