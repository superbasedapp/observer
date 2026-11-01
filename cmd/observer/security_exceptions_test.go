//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSecurityWorkflowKeyParity: the commit scan's workflow finding and
// the baseline driver key the same hit identically, so a hit present at
// the approved baseline commit is recognized as the same finding.
func TestSecurityWorkflowKeyParity(t *testing.T) {
	hash := secposture.ProjectRootHash("/p")
	f := securityCIFinding(hash, strings.Repeat("a", 40), secquickscan.CIFinding{Path: ".github/workflows/ci.yml", RuleID: "S-775", Line: 2})
	if want := secsvc.WorkflowFindingKey(hash, "S-775", ".github/workflows/ci.yml"); f.LocalKey != want {
		t.Fatalf("commit-scan key %s, baseline key %s", f.LocalKey, want)
	}
	if secsvc.FindingKeyName != securityFindingKeyName {
		t.Fatalf("the history scan keys secrets under %q, the daemon under %q", secsvc.FindingKeyName, securityFindingKeyName)
	}
	if len(securityBaselineDriverSet(false)) != 0 || len(securityBaselineDriverSet(true)) != 1 {
		t.Fatal("the baseline driver set follows security.code")
	}
}

func runSecurityCLI(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// TestSecurityExceptionAndBaselineCLI drives `observer security exception
// add | list | revoke` and `observer security baseline` over a real store
// and repository.
func TestSecurityExceptionAndBaselineCLI(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun := func(args ...string) {
		t.Helper()
		c := exec.Command("git", append([]string{"-C", repo}, args...)...)
		c.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	gitRun("init", "-q")
	gitRun("config", "user.email", "t@example.invalid")
	gitRun("config", "user.name", "t")
	if err := os.WriteFile(filepath.Join(repo, "a.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun("add", "-A")
	gitRun("commit", "-q", "-m", "first commit")

	dbPath := filepath.Join(dir, "o.db")
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(dbPath)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	id, _, err := st.UpsertSecFinding(context.Background(), secfinding.Normalize(secfinding.Finding{
		LocalKey: "k1", Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: secposture.ProjectRootHash(repo)}, Location: secfinding.Location{RelPath: "a.py", StartLine: 1},
		Status: policy.FindingStatusOpen,
	}), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = database.Close()

	if _, err := runSecurityCLI(t, newSecurityExceptionCmd(), "add", id, "--reason", "because", "--expires", "7d", "--config", cfgPath); err == nil {
		t.Fatal("a free-text reason was accepted")
	}
	out, err := runSecurityCLI(t, newSecurityExceptionCmd(), "add", id, "--reason", "false_positive", "--expires", "7d", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "Exception 1 for finding "+id) {
		t.Fatalf("add: %v\n%s", err, out)
	}
	out, err = runSecurityCLI(t, newSecurityExceptionCmd(), "list", "--config", cfgPath)
	if err != nil || !strings.Contains(out, "S-721") || !strings.Contains(out, "applies") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if out, err = runSecurityCLI(t, newSecurityExceptionCmd(), "revoke", "1", "--config", cfgPath); err != nil || !strings.Contains(out, "open again") {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	out, err = runSecurityCLI(t, newSecurityBaselineCmd(), "--project", repo, "--config", cfgPath)
	if err != nil || !strings.Contains(out, "No baseline") || !strings.Contains(out, "first commit") {
		t.Fatalf("baseline show: %v\n%s", err, out)
	}
	if out, err = runSecurityCLI(t, newSecurityBaselineCmd(), "--project", repo, "--approve", "HEAD", "--config", cfgPath); err != nil || !strings.Contains(out, "Baseline approved") {
		t.Fatalf("baseline approve: %v\n%s", err, out)
	}
	if out, err = runSecurityCLI(t, newSecurityBaselineCmd(), "--project", repo, "--config", cfgPath); err != nil || !strings.Contains(out, "approved from the cli") {
		t.Fatalf("baseline after approve: %v\n%s", err, out)
	}
	if _, err := runSecurityCLI(t, newSecurityBaselineCmd(), "--project", repo, "--approve", "HEAD", "--reset", "--config", cfgPath); err == nil {
		t.Fatal("--approve with --reset was accepted")
	}
	if _, err := runSecurityCLI(t, newSecurityScanCmd(), "--project", repo, "--config", cfgPath); err == nil {
		t.Fatal("scan without --history was accepted")
	}
	if out, err = runSecurityCLI(t, newSecurityScanCmd(), "--history", "--project", repo, "--config", cfgPath); err != nil || !strings.Contains(out, "History scan: 1 commit(s) read, 0 secret hit(s)") {
		t.Fatalf("scan --history: %v\n%s", err, out)
	}
}

func TestSecurityNotifyText(t *testing.T) {
	one := []store.SecSeenFinding{{RuleID: "S-721", RelPath: "conf/\x1b[31mprod.py"}}
	title, body := securityNotifyText(one)
	if title != "Observer: new critical code security finding" || body != "S-721 in conf/31mprod.py. See Code security > Findings." {
		t.Fatalf("one: %q %q", title, body)
	}
	title, body = securityNotifyText(append(one, store.SecSeenFinding{RuleID: "S-775", RelPath: "x"}))
	if !strings.HasPrefix(title, "Observer: 2 new") || !strings.Contains(body, "and 1 more") {
		t.Fatalf("two: %q %q", title, body)
	}
}
