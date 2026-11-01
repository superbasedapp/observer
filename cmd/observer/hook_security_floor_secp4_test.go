//go:build !sbo_omit_security && !sbo_omit_adapter_claude_code

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestProjectCommitGateFloorEndToEnd (lane SEC-P4 milestone 8): the commit
// gate floor from an org project section to the hook's answer, through the
// node's own seams: the managed node's project read
// (securityProjectFamiliesAt), the per-project floor the posture writer
// signs (securityPostureFloors, what secsvc.Options.Floors calls), and the
// real `observer hook` receiver reading that posture. In the floored
// project `cd /other-repo && git commit` from Claude Code is denied; the
// same payload in an unfloored project asks; an individual node never
// takes the managed-only floor.
func TestProjectCommitGateFloorEndToEnd(t *testing.T) {
	const claude = "claude-code-pretooluse-bash.json"
	for _, c := range []struct {
		name     string
		managed  bool
		floored  bool
		decision string
	}{
		{"managed, floored project", true, true, "deny"},
		{"managed, unfloored project", true, false, "ask"},
		{"individual, the same section", false, true, "ask"},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := pt39Node(t, "observe", c.managed)
			loads := map[string]guard.ProjectFamilyLoad{}
			if c.floored {
				loads[n.root] = matched(guard.ProjectFamilySet{OrgProjectID: "X", Members: []orgcontract.ProjectFamilyMember{sectionMember(t, 3, `{"require":{"commit_gate":"quick_scan"}}`, "X")}})
			}
			sc := config.DefaultSecurityConfig()
			withProjectSections(t, c.managed, true, sc, loads)
			gate, _ := securityPostureFloors(sc)(n.root)
			if want := c.floored && c.managed; (gate == "quick_scan") != want {
				t.Fatalf("the posture writer's floor at the project = %q", gate)
			}
			n.writePostureFor(t, n.root, func(f *secposture.File) { f.CommitGateFloor = gate })
			out := drivePT39(t, n, "claude-code", "pre-tool", pt39Payload(t, claude, n.root, "cd "+n.other+" && git commit -m wip"))
			if !strings.Contains(out, `"permissionDecision":"`+c.decision+`"`) {
				t.Fatalf("stdout %q, want %s", out, c.decision)
			}
		})
	}
}
