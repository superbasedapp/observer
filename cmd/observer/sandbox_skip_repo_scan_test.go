//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSandboxOrgBindSkipRepoScan (ruling P-060, ledger SBX-GOV-3): for a
// bind the organization asserts holds no repositories the walk below it is
// skipped, so a bind past the 20000-read budget launches; the bind itself is
// still checked; every other bind is walked and refused exactly as before.
func TestSandboxOrgBindSkipRepoScan(t *testing.T) {
	// A bind past the directory budget (as in TestSandboxOrgBindWalkCapRefuses).
	wide := t.TempDir()
	for i := 0; i < 160; i++ {
		for j := 0; j < 126; j++ {
			if err := os.MkdirAll(filepath.Join(wide, fmt.Sprintf("a%03d", i), fmt.Sprintf("b%03d", j)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A repository below it that the org's assertion says is not there.
	mkGitDir(t, filepath.Join(wide, "a000", "b000"))
	if _, _, err := sandboxOrgBindGitRows([]string{wide}, nil); err == nil {
		t.Fatal("without the assertion the walk must still refuse past the budget")
	}
	rows, pins, err := sandboxOrgBindGitRows([]string{wide}, []string{wide})
	if err != nil {
		t.Fatalf("a skipped bind past the budget refused: %v", err)
	}
	if len(rows) != 0 || len(pins) != 0 {
		t.Fatalf("a skipped bind with no .git of its own yields rows %v pins %v", rows, pins)
	}

	// The bind itself is still checked: a repository AT the bind is protected.
	self := t.TempDir()
	mkGitDir(t, self)
	mkGitDir(t, filepath.Join(self, "nested", "repo"))
	rows, pins, err = sandboxOrgBindGitRows([]string{self}, []string{self})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range rows {
		got[r.path] = true
	}
	if !got[filepath.Join(self, ".git", "config")] || !got[filepath.Join(self, ".git", "hooks")] {
		t.Fatalf("a skipped bind that is itself a repository lost its rows: %v", rows)
	}
	if got[filepath.Join(self, "nested", "repo", ".git", "config")] {
		t.Fatal("a skipped bind was walked below")
	}
	if !slices.Contains(pins, filepath.Join(self, ".git")) {
		t.Fatalf("the bind's own .git not pinned: %v", pins)
	}

	// Another bind in the same launch is walked as before.
	walked := t.TempDir()
	mkGitDir(t, filepath.Join(walked, "x", "repo"))
	rows, _, err = sandboxOrgBindGitRows([]string{self, walked}, []string{self})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		found = found || r.path == filepath.Join(walked, "x", "repo", ".git", "config")
	}
	if !found {
		t.Fatal("a bind not named by the assertion was not walked")
	}
	if _, _, err := sandboxOrgBindGitRows([]string{self, wide}, []string{self}); err == nil || !strings.Contains(err.Error(), wide) {
		t.Fatalf("the budget refusal on an unskipped bind is gone: %v", err)
	}
}

// TestSandboxManagedOrgBindsFor: skip entries apply only for applied org
// write binds; a refused extra_rw_binds key takes them with it; a body from
// an older server (no field) walks every bind.
func TestSandboxManagedOrgBindsFor(t *testing.T) {
	rw := []string{"/srv/cache", "/srv/work"}
	skip := []string{"/srv/cache"}
	p := &orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, Node: &orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &rw, SkipRepoScan: &skip}}
	got := sandboxManagedOrgBindsFor(p, nil)
	if len(got.rw) != 2 || len(got.skipScan) != 1 || got.skipScan[0] != filepath.Clean(filepath.FromSlash("/srv/cache")) {
		t.Fatalf("binds %+v", got)
	}
	refused := []SandboxManagedRefusedKey{{Key: "terminal.sandbox.extra_rw_binds", Reason: sandboxRefusedSensitive}}
	if got := sandboxManagedOrgBindsFor(p, refused); got.rw != nil || got.skipScan != nil {
		t.Fatalf("a refused bind key kept %+v", got)
	}
	older := &orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, Node: &orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &rw}}
	if got := sandboxManagedOrgBindsFor(older, nil); len(got.rw) != 2 || got.skipScan != nil {
		t.Fatalf("a body without the field skips %v", got.skipScan)
	}
	if got := sandboxManagedOrgBindsFor(nil, nil); got.rw != nil || got.skipScan != nil {
		t.Fatalf("no body: %+v", got)
	}
}

// TestSandboxManagedStatusLineSaysSkipRepoScan: `observer sandbox status`
// names the binds the walk skips (ruling P-060: the posture says when it is
// set), and says nothing when none.
func TestSandboxManagedStatusLineSaysSkipRepoScan(t *testing.T) {
	s := sandboxManagedRailStatus{State: sandboxRailInForce, SkipRepoScan: []string{"/srv/cache"}}
	if line := sandboxManagedStatusLine(s); !strings.Contains(line, "repository check skipped") || !strings.Contains(line, "/srv/cache") {
		t.Fatalf("status line %q", line)
	}
	s.SkipRepoScan = nil
	if line := sandboxManagedStatusLine(s); strings.Contains(line, "repository check skipped") {
		t.Fatalf("status line without the field %q", line)
	}
}

// TestSandboxSkipRepoScanDoctorFollowsTheLaunchPins (audit finding 5 of
// lane SHR-FOLLOWUPS): doctor's skip_repo_scan line is composed with the
// governance pins the launch uses, so a pinned extra_rw_binds key that
// refuses the org's binds also drops their skip; without those pins the
// line says it shows the body as served.
func TestSandboxSkipRepoScanDoctorFollowsTheLaunchPins(t *testing.T) {
	bind := nonSensitiveTestDir(t)
	rw := []string{bind}
	skip := []string{bind}
	p := orgcontract.SandboxManagedPolicyV1{Schema: orgcontract.SandboxManagedSchema, Node: &orgcontract.SandboxManagedNodeV1{ExtraRWBinds: &rw, SkipRepoScan: &skip}}
	cfg := config.Default()
	_, refused := composeSandboxManaged(cfg.Terminal.Sandbox, p, sandboxManagedEnvFor(cfg, nil))
	open := sandboxManagedOrgBindsFor(&p, refused).skipScan
	if len(open) != 1 {
		t.Fatalf("with no pins the skip is %v (refused %+v)", open, refused)
	}
	pins := map[string]any{"terminal.sandbox.extra_rw_binds": []any{}}
	_, refused = composeSandboxManaged(cfg.Terminal.Sandbox, p, sandboxManagedEnvFor(cfg, pins))
	if got := sandboxManagedOrgBindsFor(&p, refused).skipScan; got != nil {
		t.Fatalf("a pinned extra_rw_binds key kept the skip %v (refused %+v)", got, refused)
	}
	if got := sandboxSkipRepoScanDoctorLine(nil, false); got != nil {
		t.Fatalf("no skip still printed %+v", got)
	}
	known := sandboxSkipRepoScanDoctorLine(open, true)
	if len(known) != 1 || !strings.Contains(known[0].Message, bind) || strings.Contains(known[0].Message, "as served") {
		t.Fatalf("doctor line with the pins read %+v", known)
	}
	unknown := sandboxSkipRepoScanDoctorLine(open, false)
	if len(unknown) != 1 || !strings.Contains(unknown[0].Message, "as served by the organization, before this node's own pins") {
		t.Fatalf("doctor line without the pins %+v", unknown)
	}
}
