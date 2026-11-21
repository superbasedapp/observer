//go:build !sbo_omit_security && !sbo_omit_security_scan_actionlint

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/remedy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

const (
	g5BadWorkflow  = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ nope.x }}\n"
	g5GoodWorkflow = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
)

func writeWorkflow(t *testing.T, root, name, body string) {
	t.Helper()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestRunActionlintRecordsAndCloses: a run records the workflow findings;
// once the workflow is fixed, the next complete run closes them.
func TestRunActionlintRecordsAndCloses(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	root := t.TempDir()
	writeWorkflow(t, root, "ci.yml", g5BadWorkflow)
	writeWorkflow(t, root, "notes.txt", "not a workflow")
	if err := testSymlink(t, filepath.Join(root, ".github", "workflows", "ci.yml"), filepath.Join(root, ".github", "workflows", "link.yml")); err != nil {
		t.Skip("no symlinks here")
	}
	rep, err := runActionlint(ctx, st, root, root)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Files != 1 || rep.Findings == 0 || rep.Outcome != "findings" || len(rep.Skipped) != 1 {
		t.Fatalf("report %+v", rep)
	}
	open, _ := st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen})
	if len(open) == 0 || open[0].Rule.Pack != "actionlint" {
		t.Fatalf("open %+v", open)
	}
	if err := os.Remove(filepath.Join(root, ".github", "workflows", "link.yml")); err != nil {
		t.Fatal(err)
	}
	writeWorkflow(t, root, "ci.yml", g5GoodWorkflow)
	rep, err = runActionlint(ctx, st, root, root)
	if err != nil || rep.Outcome != "clean" {
		t.Fatalf("fixed: %+v %v", rep, err)
	}
	if open, _ := st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen}); len(open) != 0 {
		t.Fatalf("not closed: %+v", open)
	}
}

// TestRunActionlintLinkedWorktreeClosesNothing (P-041).
func TestRunActionlintLinkedWorktreeClosesNothing(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	root, wt := t.TempDir(), t.TempDir()
	writeWorkflow(t, root, "ci.yml", g5BadWorkflow)
	if _, err := runActionlint(ctx, st, root, root); err != nil {
		t.Fatal(err)
	}
	writeWorkflow(t, wt, "ci.yml", g5GoodWorkflow)
	rep, err := runActionlint(ctx, st, root, wt)
	if err != nil || !rep.LinkedWorktree {
		t.Fatalf("%+v %v", rep, err)
	}
	if open, _ := st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen}); len(open) == 0 {
		t.Fatal("a linked worktree run closed the project's findings")
	}
}

// TestActionlintIsOptIn: not selected with no [components] block.
func TestActionlintIsOptIn(t *testing.T) {
	if actionlintSelected(componentstate.Legacy()) {
		t.Fatal("selected with no [components] block")
	}
	snap := componentstate.Resolve(config.ComponentsConfig{Add: []string{actionlintComponent, "security.code"}}, nil)
	if !actionlintSelected(snap) {
		t.Fatal("not selected although added")
	}
}

// TestActionlintDoctorLinksTheScannersSwitch (lane L5): the not-selected
// doctor row names the Code security > Scanners switch first and carries it
// as a dashboard link; the [components] key stays for the file reader.
func TestActionlintDoctorLinksTheScannersSwitch(t *testing.T) {
	setTestHome(t, t.TempDir())
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if actionlintSelected(componentSnapshotFor(cfg)) {
		t.Skip("actionlint is offered by default here; the not-selected row does not apply")
	}
	c := securityActionlintDoctorCheck(context.Background(), cfg)
	if !strings.Contains(c.Message, "Code security > Scanners") || !strings.Contains(c.Message, "[components]") {
		t.Errorf("message = %q", c.Message)
	}
	if len(c.Remediations) != 1 || c.Remediations[0].Action != remedy.OpenScanners {
		t.Errorf("remediations = %+v, want the Scanners link", c.Remediations)
	}
}
