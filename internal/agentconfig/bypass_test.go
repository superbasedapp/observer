package agentconfig

import "testing"

// TestBypassForbidden pins when an organization's enforced AI tool settings
// forbid running a tool with its permission checks skipped (OSH-R-005).
func TestBypassForbidden(t *testing.T) {
	cases := []struct {
		name     string
		tool     string
		enforced map[string]any
		want     bool
	}{
		{"nothing enforced", "claude-code", nil, false},
		{"approval full_auto", "claude-code", map[string]any{"claude-code/permissions.defaultMode": "bypassPermissions"}, false},
		{"approval auto_edits", "claude-code", map[string]any{"claude-code/permissions.defaultMode": "acceptEdits"}, true},
		{"approval plan", "claude-code", map[string]any{"claude-code/permissions.defaultMode": "plan"}, true},
		{"approval unreadable", "claude-code", map[string]any{"claude-code/permissions.defaultMode": "something-new"}, true},
		{"bypass switch off", "claude-code", map[string]any{"claude-code/permissions.disableBypassPermissionsMode": "disable"}, true},
		{"other tool's setting", "codex", map[string]any{"claude-code/permissions.defaultMode": "plan"}, false},
		{"tool without approval row", "no-such-tool", map[string]any{"no-such-tool/x": "y"}, false},
		// audit F5: grok's doc-grounded bypass switches (no approval_mode row).
		{"grok bypass forbidden", "grok", map[string]any{"grok/ui.disable_bypass_permissions_mode": true}, true},
		{"grok bypass allowed", "grok", map[string]any{"grok/ui.disable_bypass_permissions_mode": false}, false},
		{"grok permission mode ask", "grok", map[string]any{"grok/ui.permission_mode": "ask"}, true},
		{"grok permission mode always-approve", "grok", map[string]any{"grok/ui.permission_mode": "always-approve"}, false},
		{"another tool's grok setting", "claude-code", map[string]any{"grok/ui.disable_bypass_permissions_mode": true}, false},
	}
	for _, c := range cases {
		got, why := BypassForbidden(c.tool, c.enforced)
		if got != c.want {
			t.Errorf("%s: forbidden=%v (%q), want %v", c.name, got, why, c.want)
		}
		if got && why == "" {
			t.Errorf("%s: forbidden with no reason", c.name)
		}
	}
}

// TestBypassForbiddingSettingsAreCatalogued: every switch the table reads is
// a real catalogue row, so a renamed setting cannot leave a dead row.
func TestBypassForbiddingSettingsAreCatalogued(t *testing.T) {
	for _, row := range bypassForbiddingSettings {
		if _, ok := Setting(row.id); !ok {
			t.Errorf("bypass-forbidding setting %q is not in the catalogue", row.id)
		}
	}
}
