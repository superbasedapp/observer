package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// writeGuardTestConfig writes a minimal config.toml whose DB path
// lives in the same temp dir, returning (configPath, dbPath).
func writeGuardTestConfig(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")
	// Forward slashes keep the TOML free of the Windows \U escaping
	// trap (the documented Windows-host fixture failure class).
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath, dbPath
}

// runGuardCmd executes `observer guard <args...>` capturing stdout.
func runGuardCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newGuardCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestGuardRulesCmd smoke-tests the catalog listing in both shapes.
func TestGuardRulesCmd(t *testing.T) {
	t.Parallel()
	out, err := runGuardCmd(t, "rules")
	if err != nil {
		t.Fatalf("guard rules: %v", err)
	}
	for _, want := range []string{"R-101", "R-152", "T-504", "destructive", "boundary", "taint"} {
		if !strings.Contains(out, want) {
			t.Errorf("catalog output missing %q", want)
		}
	}
	out, err = runGuardCmd(t, "rules", "--json")
	if err != nil {
		t.Fatalf("guard rules --json: %v", err)
	}
	if !strings.Contains(out, `"id": "R-101"`) || !strings.Contains(out, `"observe": "flag"`) {
		t.Errorf("json output shape: %s", out[:min(200, len(out))])
	}
}

// TestGuardTestCmd dry-runs a destructive command and a benign one
// through a real temp config.
func TestGuardTestCmd(t *testing.T) {
	t.Parallel()
	cfgPath, _ := writeGuardTestConfig(t)

	out, err := runGuardCmd(t, "test", "--config", cfgPath, "git push --force origin main")
	if err != nil {
		t.Fatalf("guard test: %v", err)
	}
	if !strings.Contains(out, "R-110") || !strings.Contains(out, "flag") {
		t.Errorf("force-push dry-run output: %s", out)
	}
	// The pre-enforce confidence line: observe flags, enforce denies.
	if !strings.Contains(out, "In enforce:   deny") {
		t.Errorf("missing enforce-mode projection: %s", out)
	}

	out, err = runGuardCmd(t, "test", "--config", cfgPath, "go test ./...")
	if err != nil {
		t.Fatalf("guard test benign: %v", err)
	}
	if !strings.Contains(out, "allow — no rule matched") {
		t.Errorf("benign dry-run output: %s", out)
	}

	// --file form classifies as a write.
	out, err = runGuardCmd(t, "test", "--config", cfgPath, "--file", "~/.ssh/authorized_keys")
	if err != nil {
		t.Fatalf("guard test --file: %v", err)
	}
	if !strings.Contains(out, "R-152") {
		t.Errorf("sensitive write dry-run output: %s", out)
	}

	// Exactly one input form is required.
	if _, err := runGuardCmd(t, "test", "--config", cfgPath); err == nil {
		t.Error("no input form accepted")
	}
}

// TestGuardLintCmd lints a clean and a broken explicit policy file.
func TestGuardLintCmd(t *testing.T) {
	t.Parallel()
	cfgPath, _ := writeGuardTestConfig(t)
	dir := t.TempDir()

	good := filepath.Join(dir, "good.toml")
	if err := os.WriteFile(good, []byte(
		"[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='flag'\nmatch.command_base='make'\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runGuardCmd(t, "lint", "--config", cfgPath, good)
	if err != nil {
		t.Fatalf("lint clean file: %v (%s)", err, out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("lint output: %s", out)
	}

	bad := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(bad, []byte(
		"[[rule]]\nid='R-101'\ncategory='destructive'\ndecision='deny'\nmatch.command_base='rm'\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = runGuardCmd(t, "lint", "--config", cfgPath, bad)
	if err == nil {
		t.Fatalf("lint accepted a builtin-ID collision: %s", out)
	}
	if !strings.Contains(out, "collides with built-in") {
		t.Errorf("lint problem output: %s", out)
	}
}

// TestGuardVerifyAuditCmd runs the chain walk against a real temp DB:
// clean chain passes; a tampered row fails with exit-error.
func TestGuardVerifyAuditCmd(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)

	// Seed two chained rows through the one-owner helper.
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	s := store.New(database)
	if _, err := s.InsertGuardEvents(context.Background(), []store.GuardEventRow{
		{TS: time.Now().UTC(), SessionID: "s1", RuleID: "R-101", Decision: "flag", Severity: "critical"},
		{TS: time.Now().UTC(), SessionID: "s1", RuleID: "R-110", Decision: "deny", Severity: "critical"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	out, err := runGuardCmd(t, "verify-audit", "--config", cfgPath)
	if err != nil {
		t.Fatalf("verify-audit clean: %v (%s)", err, out)
	}
	if !strings.Contains(out, "audit chain OK — 2 row(s)") {
		t.Errorf("clean output: %s", out)
	}

	if _, err := database.ExecContext(context.Background(),
		`UPDATE guard_events SET decision = 'allow' WHERE rule_id = 'R-110'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	_ = database.Close()

	out, err = runGuardCmd(t, "verify-audit", "--config", cfgPath)
	if err == nil {
		t.Fatalf("verify-audit passed a tampered chain: %s", out)
	}
	if !strings.Contains(out, "BROKEN") {
		t.Errorf("tampered output: %s", out)
	}
}

// TestGuardStatusCmd smoke-tests status against a real temp DB with
// one verdict row.
func TestGuardStatusCmd(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	s := store.New(database)
	if _, err := s.PersistGuardVerdicts(context.Background(), []guard.ActionVerdict{}); err != nil {
		t.Fatalf("empty persist: %v", err)
	}
	if _, err := s.InsertGuardEvents(context.Background(), []store.GuardEventRow{
		{
			TS: time.Now().UTC(), SessionID: "s1", RuleID: "R-101", Decision: "flag",
			Severity: "critical", Category: "destructive",
		},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = database.Close()

	out, err := runGuardCmd(t, "status", "--config", cfgPath)
	if err != nil {
		t.Fatalf("guard status: %v (%s)", err, out)
	}
	for _, want := range []string{
		"Guard:        on", "Mode:         observe",
		"Verdicts (24h): 1 total", "by decision: flag=1",
		"Audit chain:  OK (1 rows verified)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q:\n%s", want, out)
		}
	}
}

// TestGuardStatusPrintsTheOrgBudgetPosture is finding H5's pin.
//
// The developer whose proxied requests are being denied is the one reading
// this screen, and before this the ONLY surface carrying `budget_required` was
// the org admin's dashboard. They could see the deny verdicts and nothing that
// said why; the one person who could see the reason was not the one hitting
// it.
//
// The word `budget_required` is asserted literally, because it is the string
// the developer will search the docs and the org dashboard for.
func TestGuardStatusPrintsTheOrgBudgetPosture(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if _, err := store.New(database).PersistGuardVerdicts(context.Background(), []guard.ActionVerdict{}); err != nil {
		t.Fatalf("empty persist: %v", err)
	}
	_ = database.Close()

	out, err := runGuardCmd(t, "status", "--config", cfgPath)
	if err != nil {
		t.Fatalf("guard status: %v (%s)", err, out)
	}
	// The line is present on EVERY node, including this ungoverned fixture:
	// "you are not subject to an org budget" is an answer a developer needs
	// as much as the blocking one, and a line that only appears when
	// something is wrong teaches nobody where to look.
	if !strings.Contains(out, "Org budget:") {
		t.Fatalf("no org budget line:\n%s", out)
	}
	for _, want := range []string{"coverage=", "fetch_state=", "from_org=", "last_fetch_ok=", "budget_required="} {
		if !strings.Contains(out, want) {
			t.Errorf("the org budget line is missing %q:\n%s", want, out)
		}
	}
	// An ungoverned node is not blocking, and must not say it is.
	if strings.Contains(out, "budget_required=true") {
		t.Errorf("an ungoverned node reported budget_required=true:\n%s", out)
	}
}

// TestGuardBudgetPostureLineNamesTheBlock: when the node IS in the fail-closed
// posture the line must say so in WORDS, not only as an enum value — the
// developer reading it has just been denied and needs to know the denial is
// the org's configuration, not their own machine misbehaving.
func TestGuardBudgetPostureLineNamesTheBlock(t *testing.T) {
	t.Parallel()

	blocked := budgetPostureStatusLine(orgcontract.BudgetPostureRow{
		Coverage:   orgcontract.BudgetCoverageBudgetRequired,
		FetchState: orgcontract.BudgetFetchUnverified,
		FromOrg:    true,
	})
	for _, want := range []string{
		"budget_required=true",
		"BLOCKS all proxied requests",
		"fetch_state=" + orgcontract.BudgetFetchUnverified,
	} {
		if !strings.Contains(blocked, want) {
			t.Errorf("the blocking line is missing %q: %s", want, blocked)
		}
	}

	ordinary := budgetPostureStatusLine(orgcontract.BudgetPostureRow{
		Coverage:   orgcontract.BudgetCoverageProxyOnly,
		FetchState: orgcontract.BudgetFetchOK,
		FromOrg:    true, LastFetchOK: true,
	})
	if strings.Contains(ordinary, "budget_required=true") || strings.Contains(ordinary, "BLOCKS") {
		t.Errorf("an enforcing node was rendered as blocking: %s", ordinary)
	}
}

// TestRewriteCachedBudgetFetchState is finding B's unit pin (2026-09-13
// W7/W8 verification): a composed line's fetch_state=unreachable token must
// become an honest "cached" rendering naming the cached version and
// fetched_at. The cold process's last_fetch_ok=false must likewise become
// unknown_to_cli because this command performed no fetch. A line carrying any
// OTHER fetch_state must be left alone — this rewrite must never invent a
// cache that was not there.
func TestRewriteCachedBudgetFetchState(t *testing.T) {
	t.Parallel()
	fetchedAt := time.Date(2026, 9, 13, 6, 29, 22, 0, time.UTC)

	got := rewriteCachedBudgetFetchState(
		"coverage=proxy_only fetch_state=unreachable from_org=true last_fetch_ok=false budget_required=false",
		store.OrgBudgetCache{Have: true, Version: 5, FetchedAt: fetchedAt},
	)
	if strings.Contains(got, "fetch_state=unreachable") {
		t.Errorf("still says unreachable over a primed cache: %s", got)
	}
	for _, want := range []string{
		"fetch_state=cached",
		"CLI read verified body v5 persisted at 2026-09-13T06:29:22Z",
		"daemon fetch state unavailable here",
		"last_fetch_ok=unknown_to_cli",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rewritten line missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "last_fetch_ok=false") || strings.Contains(got, "last_fetch_ok=true") {
		t.Errorf("cached CLI line claimed a fetch result: %s", got)
	}
	// Every other field on the line is the composer's own verdict and must
	// survive untouched.
	for _, want := range []string{"coverage=proxy_only", "from_org=true", "budget_required=false"} {
		if !strings.Contains(got, want) {
			t.Errorf("rewrite dropped %q: %s", want, got)
		}
	}

	// A line with no unreachable token (e.g. a live ok fetch, or a node that
	// never opted in) is returned unchanged — nothing to rewrite.
	unchanged := "coverage=proxy_only fetch_state=ok from_org=true last_fetch_ok=true budget_required=false"
	if got := rewriteCachedBudgetFetchState(unchanged, store.OrgBudgetCache{Have: true, Version: 5, FetchedAt: fetchedAt}); got != unchanged {
		t.Errorf("rewrote a line that was not unreachable: %s", got)
	}

	// No FetchedAt on the cached row still renders honestly rather than a
	// zero-value timestamp.
	noTime := rewriteCachedBudgetFetchState(
		"coverage=proxy_only fetch_state=unreachable from_org=true last_fetch_ok=false budget_required=false",
		store.OrgBudgetCache{Have: true, Version: 3},
	)
	if !strings.Contains(noTime, "an unknown time") {
		t.Errorf("missing honest time fallback: %s", noTime)
	}
}

// TestGuardStatusOrgBudgetLineHonestAboutPrimedCache is finding B's
// end-to-end pin: `observer guard status` on a node that has a verified org
// budget PERSISTED in org_budget_cache — the CLI's only source of truth,
// since it is a different process from the daemon and has made no live
// fetch of its own — must never print the bare word "unreachable" on the
// "Org budget:" line. Before this fix it did, on a demonstrably healthy
// managed devbox, because the composed fetch_state for a primed cache and
// for a genuine outage are the SAME wire value by construction. For the same
// reason it must not print a boolean last_fetch_ok result that only a fetching
// daemon could know.
func TestGuardStatusOrgBudgetLineHonestAboutPrimedCache(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeGuardTestConfig(t)
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	doc := orgcontract.BudgetPolicyDoc{
		BudgetPolicyBody: orgcontract.BudgetPolicyBody{
			Version: 5, ResolvedScope: "member", Period: "monthly",
			IssuedAt: time.Date(2026, 9, 13, 6, 29, 22, 0, time.UTC).Format(time.RFC3339),
		},
	}
	st := store.New(database)
	enrolment := store.Enrolment{
		OrgID: "guard-status-org", OrgServerURL: "https://org.example.test",
		UserID: "guard-status-member",
	}
	if err := st.WriteEnrolment(context.Background(), enrolment); err != nil {
		t.Fatalf("seed enrolment: %v", err)
	}
	orgKey := orgclient.OrgKey(enrolment.OrgServerURL, enrolment.OrgID)
	if _, err := st.BumpEnrolmentGeneration(context.Background(), orgKey, false); err != nil {
		t.Fatalf("seed enrolment generation: %v", err)
	}
	identity, active, err := orgclient.CurrentBudgetIdentity(context.Background(), st)
	if err != nil || !active {
		t.Fatalf("current budget identity: active=%v err=%v", active, err)
	}
	if err := st.SaveOrgBudget(context.Background(), doc, `"etag-1"`, "fp-1", identity); err != nil {
		t.Fatalf("seed org budget cache: %v", err)
	}
	_ = database.Close()

	out, err := runGuardCmd(t, "status", "--config", cfgPath)
	if err != nil {
		t.Fatalf("guard status: %v (%s)", err, out)
	}
	if strings.Contains(out, "fetch_state=unreachable") {
		t.Errorf("a primed cache was rendered as unreachable:\n%s", out)
	}
	for _, want := range []string{"Org budget:", "fetch_state=cached", "CLI read verified body v5", "last_fetch_ok=unknown_to_cli"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "last_fetch_ok=false") || strings.Contains(out, "last_fetch_ok=true") {
		t.Errorf("cached CLI output claimed a fetch result:\n%s", out)
	}
}
