package integration

import (
	"strings"
	"testing"
)

// TestHeadlessPermissionLanesDeclared: every grounded headless row declares
// at least one permission lane, and no permission-skipping token rides on
// a row's always-on argv (Lead, OutputArgs), where the Arena could not keep
// it off (OSH-R-005).
func TestHeadlessPermissionLanesDeclared(t *testing.T) {
	skipTokens := []string{
		"--dangerously-skip-permissions", "--always-approve", "--yes",
		"--dangerously-bypass-approvals-and-sandbox", "--yolo", "workspace-write",
	}
	for _, c := range Capabilities() {
		h := c.Headless
		if h == nil {
			continue
		}
		if len(h.Permissions) == 0 {
			t.Errorf("tool %q: headless row declares no permission lane", c.Tool)
		}
		for lane := range h.Permissions {
			switch lane {
			case HeadlessPermBypass, HeadlessPermEdit, HeadlessPermReadOnly:
			default:
				t.Errorf("tool %q: unknown permission lane %q", c.Tool, lane)
			}
		}
		always := strings.Join(append(append([]string{}, h.Lead...), h.OutputArgs...), " ")
		for _, tok := range skipTokens {
			for _, a := range append(append([]string{}, h.Lead...), h.OutputArgs...) {
				if a == tok {
					t.Errorf("tool %q: %q is on the always-on argv %q; it belongs in a permission lane", c.Tool, tok, always)
				}
			}
		}
	}
}
