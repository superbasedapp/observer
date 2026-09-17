package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// withTempConfig writes a minimal observer config pointing at the given
// SQLite path and returns the file path. cobra's loadConfigAndDB picks
// it up via --config.
func withTempConfig(t *testing.T, dbPath string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.toml")
	body := `
[observer]
db_path = "` + filepath.ToSlash(dbPath) + `"
log_level = "info"
`
	if err := writeFileForTest(cfg, body); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfg
}

func writeFileForTest(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// seedAuditRows mirrors the reader_test seeder pattern from
// internal/mcp/audit, but kept here so the CLI tests don't reach
// across packages.
func seedAuditRows(t *testing.T, dbPath string) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	now := time.Now()
	insert := func(ts time.Time, session, tool, path string, ok bool, sizeBytes int) {
		var okInt int
		if ok {
			okInt = 1
		}
		var reason any
		if !ok {
			reason = "deny_test"
		}
		if _, err := database.ExecContext(
			context.Background(),
			`INSERT INTO mcp_audit (ts, session_id, tool_name, request_hash,
			    path_requested, response_size_bytes, response_truncated,
			    response_ok, reason, duration_us)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ts.UTC().Format(time.RFC3339Nano),
			session, tool, "h-"+tool, path, sizeBytes, 0, okInt, reason, int64(1500),
		); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	insert(now.Add(-1*time.Minute), "s1", "get_file", "/a.go", true, 1024)
	insert(now.Add(-2*time.Minute), "s1", "get_file", "/a.go", true, 1024)
	insert(now.Add(-3*time.Minute), "s2", "get_symbols", "/b.go", true, 512)
	insert(now.Add(-4*time.Minute), "s1", "get_file", "/secret.env", false, 0)
}

// TestMCPAuditCmd_StatsHappyPath: stats subcommand prints all the
// load-bearing fields. JSON shape matches the audit.Stats struct.
func TestMCPAuditCmd_StatsHappyPath(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	if database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath}); err != nil {
		t.Fatalf("init db: %v", err)
	} else {
		database.Close()
	}
	seedAuditRows(t, dbPath)
	cfg := withTempConfig(t, dbPath)

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"mcp-audit", "stats", "--config", cfg, "--since", "1h"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, out.String())
	}
	got := out.String()
	for _, want := range []string{"total:", "ok:", "denied:", "by tool:", "get_file"} {
		if !strings.Contains(got, want) {
			t.Errorf("stats output missing %q\nfull:\n%s", want, got)
		}
	}
}

// TestMCPAuditCmd_ListJSON: --json flag emits machine-readable
// JSON, parseable into []audit.ListRow-shaped objects.
func TestMCPAuditCmd_ListJSON(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	if database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath}); err == nil {
		database.Close()
	}
	seedAuditRows(t, dbPath)
	cfg := withTempConfig(t, dbPath)

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"mcp-audit", "list", "--config", cfg, "--since", "1h", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, out.String())
	}
	var parsed []map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out.String())
	}
	if len(parsed) != 4 {
		t.Errorf("got %d rows, want 4", len(parsed))
	}
}

// TestMCPAuditCmd_DeniedFiltersOK: denied subcommand surfaces only
// response_ok=0 rows.
func TestMCPAuditCmd_DeniedFiltersOK(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	if database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath}); err == nil {
		database.Close()
	}
	seedAuditRows(t, dbPath)
	cfg := withTempConfig(t, dbPath)

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"mcp-audit", "denied", "--config", cfg, "--since", "1h", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, out.String())
	}
	var parsed []map[string]any
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out.String())
	}
	if len(parsed) != 1 {
		t.Errorf("got %d denied rows, want 1", len(parsed))
	}
	// Confirm the row IS denied (audit.ListRow marshals ResponseOK).
	if ok, _ := parsed[0]["ResponseOK"].(bool); ok {
		t.Errorf("denied row has ResponseOK=true: %+v", parsed[0])
	}
}

// TestMCPAuditCmd_TopPathsAggregates: same path 2× collapses to one
// row with calls=2.
func TestMCPAuditCmd_TopPathsAggregates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	if database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath}); err == nil {
		database.Close()
	}
	seedAuditRows(t, dbPath)
	cfg := withTempConfig(t, dbPath)

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"mcp-audit", "top-paths", "--config", cfg, "--since", "1h", "--json"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, out.String())
	}
	var paths []map[string]any
	if err := json.Unmarshal(out.Bytes(), &paths); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out.String())
	}
	// /a.go should be top with 2 calls.
	if len(paths) == 0 || paths[0]["Path"] != "/a.go" {
		t.Errorf("expected /a.go at top, got %v", paths)
	}
	if calls, _ := paths[0]["Calls"].(float64); calls != 2 {
		t.Errorf("/a.go calls: got %v, want 2", paths[0]["Calls"])
	}
}

// TestMCPAuditCmd_PurgeRequiresYes pins the destructive-operation
// guard: --older-than alone is not enough; --yes is mandatory.
func TestMCPAuditCmd_PurgeRequiresYes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	if database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath}); err == nil {
		database.Close()
	}
	seedAuditRows(t, dbPath)
	cfg := withTempConfig(t, dbPath)

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"mcp-audit", "purge", "--config", cfg, "--older-than", "1h"})
	err := root.Execute()
	if err == nil {
		t.Errorf("expected error (missing --yes), got nil")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("error doesn't mention --yes: %v", err)
	}
}

// TestMCPAuditCmd_PurgeWithYes: --yes proceeds with the deletion.
func TestMCPAuditCmd_PurgeWithYes(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	if database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath}); err == nil {
		database.Close()
	}
	seedAuditRows(t, dbPath)
	cfg := withTempConfig(t, dbPath)

	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	// Use a 30-second window so the seeded 1-2-3-4 minute rows all qualify.
	root.SetArgs([]string{"mcp-audit", "purge", "--config", cfg, "--older-than", "30s", "--yes"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "deleted 4 row") {
		t.Errorf("expected 'deleted 4 row(s)' in output:\n%s", out.String())
	}
}

// TestMCPAuditCmd_ParseSinceFlag pins the duration-parsing semantics
// at the flag layer: empty/0 = all time (zero), bad input errors,
// negatives reject.
func TestMCPAuditCmd_ParseSinceFlag(t *testing.T) {
	cases := []struct {
		in      string
		wantDur time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"1h", time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"not-a-duration", 0, true},
		{"-1h", 0, true},
	}
	for _, c := range cases {
		got, err := parseSinceFlag(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseSinceFlag(%q): expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSinceFlag(%q): %v", c.in, err)
		}
		if got != c.wantDur {
			t.Errorf("parseSinceFlag(%q): got %v, want %v", c.in, got, c.wantDur)
		}
	}
}

// TestMCPAuditCmd_TruncOrDash: the tiny truncation helper covers
// the printed-cell-width invariant.
func TestMCPAuditCmd_TruncOrDash(t *testing.T) {
	cases := []struct {
		in, want string
		n        int
	}{
		{"", "-", 10},
		{"short", "short", 10},
		{"exactlyten", "exactlyten", 10},
		{"this is too long for the cell", "this is...", 10},
		{"x", "x", 1}, // n <= 3 path
	}
	for _, c := range cases {
		got := truncOrDash(c.in, c.n)
		if got != c.want {
			t.Errorf("truncOrDash(%q, %d): got %q, want %q", c.in, c.n, got, c.want)
		}
	}
}
