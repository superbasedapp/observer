//go:build !sbo_omit_security && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// boxTestStep publishes a commit-scan step over a fresh store, as the
// daemon's postwrite loop does, and takes it down at the test's end.
func boxTestStep(t *testing.T, git secquickscan.GitFunc) (*securityCommitStep, *sql.DB) {
	t.Helper()
	st, database := openTestStore(t)
	eng := newSecurityQuickScanEngine(func(typ, _ string) string { return "id-" + typ })
	if git != nil {
		eng.Git = git
	}
	step := &securityCommitStep{scan: &secquickscan.CommitScan{Engine: eng}, st: st, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	securityRT.commitScan.Store(step)
	t.Cleanup(func() { securityRT.commitScan.Store(nil) })
	return step, database
}

// boxStepLog is a git runner that records each return step (the verb
// after the -c settings) beside the real git, and the scan's place.
type boxStepLog struct{ steps []string }

func (l *boxStepLog) run(ctx context.Context, st workspace.Step) ([]byte, error) {
	verb := ""
	for i := 1; i < len(st.Argv); i++ {
		a := st.Argv[i]
		if a == "-c" || a == "-C" {
			i++
			continue
		}
		if !strings.HasPrefix(a, "-") {
			verb = a
			break
		}
	}
	l.steps = append(l.steps, verb)
	return runReturnGit(ctx, st)
}

// boxCommitSecret commits a test secret in the copy and returns its id.
func boxCommitSecret(t *testing.T, req workspace.ReturnRequest, inCopy func(...string) string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(req.CopyDir, "cfg.py"), []byte("k = \""+fakeSecretAWSKeyID+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inCopy("add", "cfg.py")
	inCopy("commit", "-qm", "wip")
	return inCopy("rev-parse", "HEAD")
}

// TestSecurityBoxReturnScanBound: with both modules built, the return
// step's scan is bound to the security module's.
func TestSecurityBoxReturnScanBound(t *testing.T) {
	if sandboxReturnScan == nil {
		t.Fatal("sandboxReturnScan is nil with the security and sandbox modules built")
	}
}

// TestSecurityBoxReturnCarriesTheFinding is the sandbox plan's P3 revision
// 5 acceptance case, in process (no container engine: the copy is a real
// clone-local repository and the runner a recording wrapper of the real
// git): a returned commit that adds a test secret yields the ref AND the
// commit-scope finding, recorded with the run in its lineage before the
// ref was written.
func TestSecurityBoxReturnCarriesTheFinding(t *testing.T) {
	req, inCopy := returnFixture(t)
	sha := boxCommitSecret(t, req, inCopy)
	_, database := boxTestStep(t, nil)
	log := &boxStepLog{}
	var refAtScan bool
	scan := func(ctx context.Context, in sandboxReturnScanInput) error {
		log.steps = append(log.steps, "scan")
		_, err := exec.Command("git", "-C", in.Repo, "rev-parse", "--verify", "--quiet", in.Ref).Output()
		refAtScan = err == nil
		return sandboxReturnScan(ctx, in)
	}
	res, err := sandboxReturn(context.Background(), req, log.run, scan)
	if err != nil {
		t.Fatal(err)
	}
	if res.Commit != sha || res.Ref != workspace.ReturnRefPrefix+req.RunID {
		t.Fatalf("result %+v", res)
	}
	if refAtScan {
		t.Fatal("the ref existed when the scan ran")
	}
	if got, err := exec.Command("git", "-C", req.SourceRepo, "rev-parse", res.Ref).Output(); err != nil || strings.TrimSpace(string(got)) != sha {
		t.Fatalf("ref %s = %q %v", res.Ref, got, err)
	}
	scanAt, refAt := -1, -1
	for i, s := range log.steps {
		switch s {
		case "scan":
			scanAt = i
		case "update-ref":
			refAt = i
		}
	}
	if scanAt < 0 || refAt < scanAt {
		t.Fatalf("steps %v: the scan must run before update-ref", log.steps)
	}
	var rule, scope, runID, commit string
	if err := database.QueryRow(`SELECT rule_id, scope, run_id, commit_sha FROM sec_findings WHERE project_root_hash = ?`,
		secposture.ProjectRootHash(req.SourceRepo)).Scan(&rule, &scope, &runID, &commit); err != nil {
		t.Fatalf("no finding: %v", err)
	}
	if rule != "secret.aws_access_key" || scope != string(policy.FindingScopeCommit) || runID != req.RunID || commit != sha {
		t.Fatalf("finding rule=%s scope=%s run=%s commit=%s", rule, scope, runID, commit)
	}
	var target string
	if err := database.QueryRow(`SELECT target_json FROM sec_scan_runs WHERE project_root_hash = ? AND scope = 'commit' AND outcome = 'findings'`,
		secposture.ProjectRootHash(req.SourceRepo)).Scan(&target); err != nil || !strings.Contains(target, `"commit":"`+sha+`"`) || !strings.Contains(target, `"run_id":"`+req.RunID+`"`) {
		t.Fatalf("run target %q %v", target, err)
	}
}

// TestSecurityBoxReturnUnrunnableScan: a scan that cannot run (git fails
// for every scan read) records an unknown run and the ref is still
// written.
func TestSecurityBoxReturnUnrunnableScan(t *testing.T) {
	req, inCopy := returnFixture(t)
	boxCommitSecret(t, req, inCopy)
	failing := func(context.Context, string, int, time.Duration, ...string) ([]byte, bool, error) {
		return nil, false, errors.New("git unavailable")
	}
	_, database := boxTestStep(t, failing)
	res, err := sandboxReturn(context.Background(), req, runReturnGit, sandboxReturnScan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.Command("git", "-C", req.SourceRepo, "rev-parse", "--verify", res.Ref).Output(); err != nil {
		t.Fatalf("no ref after an unrunnable scan: %v", err)
	}
	var unknown, findings int
	_ = database.QueryRow(`SELECT COUNT(*) FROM sec_scan_runs WHERE scope = 'commit' AND outcome = 'unknown' AND target_json LIKE '{"box":true%'`).Scan(&unknown)
	_ = database.QueryRow(`SELECT COUNT(*) FROM sec_findings`).Scan(&findings)
	if unknown == 0 || findings != 0 {
		t.Fatalf("unknown runs %d, findings %d", unknown, findings)
	}
}

// TestSecurityBoxReturnInertWhenNotSelected: with no published step and a
// config whose components do not run the postwrite loop, the bound scan
// does nothing and the return takes exactly the steps and result of a
// return with no scan at all.
func TestSecurityBoxReturnInertWhenNotSelected(t *testing.T) {
	securityRT.commitScan.Store(nil)
	prev := securityReturnStepFromConfig
	securityReturnStepFromConfig = func(context.Context, string) (*securityCommitStep, func()) { return nil, nil }
	t.Cleanup(func() { securityReturnStepFromConfig = prev })
	results := map[bool]sandboxReturnResult{}
	steps := map[bool][]string{}
	for _, bound := range []bool{false, true} {
		req, inCopy := returnFixture(t)
		_ = os.WriteFile(filepath.Join(req.CopyDir, "b.txt"), []byte("two\n"), 0o600)
		inCopy("add", "b.txt")
		inCopy("commit", "-qm", "two")
		log := &boxStepLog{}
		var scan func(context.Context, sandboxReturnScanInput) error
		if bound {
			scan = sandboxReturnScan
		}
		res, err := sandboxReturn(context.Background(), req, log.run, scan)
		if err != nil {
			t.Fatal(err)
		}
		res.Commit = ""
		results[bound], steps[bound] = res, log.steps
	}
	if !reflect.DeepEqual(results[false], results[true]) || !reflect.DeepEqual(steps[false], steps[true]) {
		t.Fatalf("unbound %+v %v, bound %+v %v", results[false], steps[false], results[true], steps[true])
	}
}

// TestSecurityReturnStepFromConfigGate: outside the daemon the step is
// built only where the postwrite loop would run; a config that removes
// security.secrets (the loop's component) gives none.
func TestSecurityReturnStepFromConfigGate(t *testing.T) {
	securityRT.commitScan.Store(nil)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = " + tomlQuote(filepath.Join(dir, "observer.db")) + "\n[components]\nremove = [\"security.secrets\"]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if step, _ := securityReturnStepFromConfig(context.Background(), cfgPath); step != nil {
		t.Fatal("a step was built with security.secrets removed")
	}
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = "+tomlQuote(filepath.Join(dir, "observer.db"))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	step, done := securityReturnStepFromConfig(context.Background(), cfgPath)
	if securityInertByDefault() {
		// The managed edition: with no block the module is inert, no step.
		if step != nil {
			done()
			t.Fatal("a step was built with no [components] block in an edition that leaves the module inert")
		}
		return
	}
	if step == nil {
		t.Fatal("no step under a legacy config (every compiled module active)")
	}
	done()
}

// tomlQuote quotes s as a TOML basic string.
func tomlQuote(s string) string {
	return "\"" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + "\""
}
