//go:build !sbo_omit_security && !sbo_omit_adapter_claude_code && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestLeftSecFlooredBoxCommitIsHeld (audit F8): a commit an agent makes in
// a sandbox copy of a floored project is held like a host commit there. The
// copy run's record maps the copy's tree to its source project, whose
// security.scanning section sets the quick-scan commit gate floor; the
// posture writer signs that floor at the copy, and the real `observer hook`
// receiver denies an unscannable commit from the copy. With no copy run the
// same tree has no floor and the commit asks.
func TestLeftSecFlooredBoxCommitIsHeld(t *testing.T) {
	const claude = "claude-code-pretooluse-bash.json"
	for _, c := range []struct {
		name     string
		copyRun  bool
		decision string
	}{
		{"copy run of a floored project", true, "deny"},
		{"no copy run", false, "ask"},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := pt39Node(t, "observe", true)
			obs := boxRunsFixture(t)
			src := filepath.Join(t.TempDir(), "src")
			if c.copyRun {
				rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{
					RunID: "RUNHELD", Tool: "claude-code", ProjectRoot: src, WorkspaceDir: n.root, Roots: []string{n.root},
					Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: n.root,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
					t.Fatal(err)
				}
			}
			sc := config.DefaultSecurityConfig()
			withProjectSections(t, true, true, sc, map[string]guard.ProjectFamilyLoad{
				filepath.Clean(src): matched(guard.ProjectFamilySet{OrgProjectID: "P", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, `{"require":{"commit_gate":"quick_scan"}}`, "P")}}),
			})
			gate, _ := securityPostureFloors(sc)(n.root)
			if (gate == policy.CommitGateFloorQuickScan) != c.copyRun {
				t.Fatalf("the floor the posture writer signs at the copy = %q", gate)
			}
			n.writePostureFor(t, n.root, func(f *secposture.File) { f.CommitGateFloor = gate })
			out := drivePT39(t, n, "claude-code", "pre-tool", pt39Payload(t, claude, n.root, "cd "+n.other+" && git commit -m wip"))
			if !strings.Contains(out, `"permissionDecision":"`+c.decision+`"`) {
				t.Fatalf("stdout %q, want %s", out, c.decision)
			}
		})
	}
}
