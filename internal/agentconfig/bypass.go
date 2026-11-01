package agentconfig

import (
	"fmt"
	"strings"
)

// bypass.go: does an organization's AI tool settings policy forbid running a
// tool with its own permission checks skipped (OSH-R-005)? The Agent Arena
// asks before it drives a harness unattended on a managed node; the answer
// is read from settings the org already distributes, so no new policy field
// exists for it.

// bypassForbiddingSetting is one native setting whose ENFORCED value says
// "this tool must not run with its permission prompts bypassed". Keyed by the
// full catalogue id (TestBypassForbiddingSettingsAreCatalogued pins each
// one), because the same path means different things in different tools.
type bypassForbiddingSetting struct {
	id      string
	forbids func(v any) bool
	what    string
}

func valueIs(want any) func(any) bool { return func(v any) bool { return v == want } }

func valueIn(want ...string) func(any) bool {
	return func(v any) bool {
		s, ok := v.(string)
		if !ok {
			return false
		}
		for _, w := range want {
			if s == w {
				return true
			}
		}
		return false
	}
}

// bypassForbiddingSettings is the closed table:
//   - claude-code and copilot-cli permissions.disableBypassPermissionsMode
//     "disable" removes the bypass mode (catalogue rows, schema-grounded for
//     claude-code);
//   - grok's requirements.toml ui.disable_bypass_permissions_mode = true
//     forbids the approval-bypassing modes, and an enforced ui.permission_mode
//     of "default" or "ask" keeps approvals on (the reference documents only
//     "always-approve" and "auto" as skipping approvals). Grok has no
//     approval_mode map row (audit F5): the reference does not say how its
//     "default" and "auto" modes line up with ask_edits / auto_edits, so the
//     common key is not mapped and only these doc-grounded switches are read.
var bypassForbiddingSettings = []bypassForbiddingSetting{
	{id: "claude-code/permissions.disableBypassPermissionsMode", forbids: valueIs("disable"), what: `= "disable"`},
	{id: "copilot-cli/permissions.disableBypassPermissionsMode", forbids: valueIs("disable"), what: `= "disable"`},
	{id: "grok/ui.disable_bypass_permissions_mode", forbids: valueIs(true), what: "= true"},
	{id: "grok/ui.permission_mode", forbids: valueIn("default", "ask"), what: "to a mode that keeps approvals on"},
}

// fullAutoApproval is the one approval_mode value under which nothing
// prompts: an enforced value stricter than it forbids a bypass.
const fullAutoApproval = "full_auto"

// BypassForbidden reports whether a set of ENFORCED org settings for one
// tool forbids running it with its permission checks skipped. enforced maps
// a catalogue setting id ("claude-code/permissions.defaultMode") to its
// decoded native value; the caller passes only enforced directives (an org
// default is the developer's to change, so it forbids nothing). It forbids
// when the tool's approval_mode reads back as anything stricter than
// full_auto, or when a bypass-forbidding switch is set. A value that cannot
// be read back forbids too: the org said something about this tool's
// approvals and it is not understood, so the strict reading wins.
func BypassForbidden(tool string, enforced map[string]any) (forbidden bool, why string) {
	for _, row := range bypassForbiddingSettings {
		if !strings.HasPrefix(row.id, tool+"/") {
			continue
		}
		if v, ok := enforced[row.id]; ok && row.forbids(v) {
			return true, fmt.Sprintf("your organization enforces %s %s", row.id, row.what)
		}
	}
	m, ok := MapRowFor(tool, KeyApprovalMode)
	if !ok {
		return false, ""
	}
	natives := make([]any, len(m.Settings))
	present := false
	for i, id := range m.Settings {
		if v, ok := enforced[id]; ok {
			natives[i] = v
			present = true
		}
	}
	if !present {
		return false, ""
	}
	v, _, err := m.Reverse(natives)
	if err != nil {
		return true, fmt.Sprintf("your organization enforces an approval mode for %s that this build cannot read", tool)
	}
	if mode, _ := v.(string); mode != fullAutoApproval {
		return true, fmt.Sprintf("your organization enforces approval mode %q for %s", mode, tool)
	}
	return false, ""
}
