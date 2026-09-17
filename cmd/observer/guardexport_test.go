package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedExportFixture populates the temp DB with three guard events of
// ascending severity (timestamps now-3h/-2h/-1h), one policy-state
// load and one active approval — enough to exercise every report
// section and the export filters.
func seedExportFixture(t *testing.T, dbPath string) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	st := store.New(database)
	now := time.Now().UTC()

	mk := func(rule, severity, decision string, age time.Duration) store.GuardEventRow {
		return store.GuardEventRow{
			TS: now.Add(-age), SessionID: "sess-1", Tool: "claude-code",
			EventKind: "shell_exec", RuleID: rule, Category: "destructive",
			Severity: severity, Decision: decision, Source: "builtin",
			Reason: "fixture verdict", TargetExcerpt: "rm -rf | x=1", TargetHash: "th",
		}
	}
	if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{
		mk("R-001", "info", "flag", 3*time.Hour),
		mk("R-002", "high", "flag", 2*time.Hour),
		mk("R-003", "critical", "deny", time.Hour),
	}); err != nil {
		t.Fatalf("seed events: %v", err)
	}
	if _, err := st.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
		Layer: "user", Path: "/u/guard-policy.toml", ContentHash: "abc123",
		LoadedAt: now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("seed policy state: %v", err)
	}
	if _, err := st.InsertGuardApproval(ctx, store.GuardApprovalRow{
		TS: now.Add(-time.Hour), RuleID: "R-003", Scope: "session",
		SessionID: "sess-1", GrantedBy: "operator",
	}); err != nil {
		t.Fatalf("seed approval: %v", err)
	}
}

// jsonLines extracts the JSON-object lines from mixed command output
// (the export stream shares the buffer with the stderr summary line).
func jsonLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "{") {
			lines = append(lines, l)
		}
	}
	return lines
}

// TestGuardExportCmd_JSONL pins the default export: every event, one
// JSON object per line, chain order.
func TestGuardExportCmd_JSONL(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)
	seedExportFixture(t, dbPath)

	out, err := runGuardCmd(t, "export", "--config", cfgPath)
	if err != nil {
		t.Fatalf("guard export: %v\n%s", err, out)
	}
	lines := jsonLines(out)
	if len(lines) != 3 {
		t.Fatalf("got %d JSONL lines, want 3:\n%s", len(lines), out)
	}
	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 0 not JSON: %v", err)
	}
	if first["rule_id"] != "R-001" || first["severity"] != "info" {
		t.Errorf("chain order violated, first = %v", first)
	}
	if !strings.Contains(out, "exported 3 event(s) as jsonl") {
		t.Errorf("missing summary line:\n%s", out)
	}
}

// TestGuardExportCmd_CEFWithSeverityFilter pins the CEF form plus the
// --min-severity gate.
func TestGuardExportCmd_CEFWithSeverityFilter(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)
	seedExportFixture(t, dbPath)

	out, err := runGuardCmd(t, "export", "--config", cfgPath, "--format", "cef", "--min-severity", "high")
	if err != nil {
		t.Fatalf("guard export cef: %v\n%s", err, out)
	}
	if strings.Contains(out, "|R-001|") {
		t.Errorf("info event must be filtered at min-severity high:\n%s", out)
	}
	if !strings.Contains(out, "CEF:0|SuperBased|ObserverGuard|") {
		t.Errorf("missing CEF header:\n%s", out)
	}
	if !strings.Contains(out, "|R-002|destructive flag|8|") || !strings.Contains(out, "|R-003|destructive deny|10|") {
		t.Errorf("severity scores wrong:\n%s", out)
	}
	// The fixture target contains '=' and '|': extension-escaped value
	// keeps the pipe, escapes the equals.
	if !strings.Contains(out, `cs6=rm -rf | x\=1`) {
		t.Errorf("extension escaping wrong:\n%s", out)
	}
}

// TestGuardExportCmd_OutFile pins --out: file created 0600-class,
// stdout stays clean of event lines.
func TestGuardExportCmd_OutFile(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)
	seedExportFixture(t, dbPath)
	outPath := filepath.Join(t.TempDir(), "events.jsonl")

	out, err := runGuardCmd(t, "export", "--config", cfgPath, "--out", outPath)
	if err != nil {
		t.Fatalf("guard export --out: %v\n%s", err, out)
	}
	if len(jsonLines(out)) != 0 {
		t.Errorf("event lines leaked to stdout with --out:\n%s", out)
	}
	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	if got := len(jsonLines(string(body))); got != 3 {
		t.Errorf("out file has %d JSONL lines, want 3", got)
	}
}

// TestGuardExportCmd_FlagValidation pins the reject table: bad
// format, bad severity, window-form conflict.
func TestGuardExportCmd_FlagValidation(t *testing.T) {
	t.Parallel()
	cfgPath, _ := writeGuardTestConfig(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bad format", []string{"--format", "xml"}, "--format must be jsonl or cef"},
		{"bad severity", []string{"--min-severity", "extreme"}, "--min-severity must be one of"},
		{"window conflict", []string{"--since", "24h", "--period", "2026-05"}, "exclusive"},
		{"bad period", []string{"--period", "lastweek"}, "not a duration"},
	}
	for _, c := range cases {
		args := append([]string{"export", "--config", cfgPath}, c.args...)
		out, err := runGuardCmd(t, args...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v (output %s), want containing %q", c.name, err, out, c.want)
		}
	}
}

// TestGuardExportCmd_PeriodWindow pins the calendar-window path: a
// past month excludes the (recent) fixture events.
func TestGuardExportCmd_PeriodWindow(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)
	seedExportFixture(t, dbPath)

	out, err := runGuardCmd(t, "export", "--config", cfgPath, "--period", "2020-01")
	if err != nil {
		t.Fatalf("guard export --period: %v\n%s", err, out)
	}
	if got := len(jsonLines(out)); got != 0 {
		t.Errorf("a 2020 window must exclude today's events, got %d lines", got)
	}
}

// TestGuardReportCmd pins the evidence pack in both shapes against
// the seeded fixture.
func TestGuardReportCmd(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)
	seedExportFixture(t, dbPath)

	out, err := runGuardCmd(t, "report", "--config", cfgPath, "--period", "24h")
	if err != nil {
		t.Fatalf("guard report: %v\n%s", err, out)
	}
	for _, want := range []string{
		"Guard evidence pack — period 24h",
		"== Policy changes in period ==",
		"/u/guard-policy.toml",
		"total 3, enforced 0",
		"by severity:",
		"== Audit-chain verification ==",
		"OK — 3 row(s) verified",
		"== Coverage matrix (§6.5) ==",
		"claude-code",
		"== Exception register (active approvals) ==",
		"R-003 scope=session granted_by=operator",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}

	out, err = runGuardCmd(t, "report", "--config", cfgPath, "--period", "24h", "--json")
	if err != nil {
		t.Fatalf("guard report --json: %v", err)
	}
	var r struct {
		Period struct {
			Label string `json:"label"`
		} `json:"period"`
		Stats struct {
			Total int `json:"total"`
		} `json:"verdict_stats"`
		Chain struct {
			OK      bool `json:"ok"`
			Checked int  `json:"checked"`
		} `json:"audit_chain"`
		PolicyChanges []any `json:"policy_changes"`
		Coverage      []any `json:"coverage_matrix"`
		Approvals     []any `json:"active_approvals"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("report JSON: %v\n%s", err, out)
	}
	if r.Period.Label != "24h" || r.Stats.Total != 3 || !r.Chain.OK || r.Chain.Checked != 3 {
		t.Errorf("report JSON fields wrong: %+v", r)
	}
	if len(r.PolicyChanges) != 1 || len(r.Coverage) == 0 || len(r.Approvals) != 1 {
		t.Errorf("report JSON sections wrong: changes=%d coverage=%d approvals=%d",
			len(r.PolicyChanges), len(r.Coverage), len(r.Approvals))
	}
}
