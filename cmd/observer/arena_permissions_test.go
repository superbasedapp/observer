package main

import (
	"strings"
	"testing"
)

// TestDecideArenaBypass pins the Arena permission-skip decision table
// (OSH-R-005): the operator's own setting must allow it, and on a managed
// node the organization's AI tool settings must be readable and must not
// forbid it. Every unreadable state refuses.
func TestDecideArenaBypass(t *testing.T) {
	cases := []struct {
		name  string
		f     arenaBypassFacts
		allow bool
		why   string
	}{
		{"unreadable", arenaBypassFacts{readErr: true, localAllows: true}, false, "could not be read"},
		{"default off", arenaBypassFacts{}, false, "arena_allow_skip_permissions is off"},
		{"individual, allowed", arenaBypassFacts{localAllows: true}, true, ""},
		{"individual ignores org", arenaBypassFacts{localAllows: true, orgForbids: true, orgWhy: "x"}, true, ""},
		{"managed, no policy", arenaBypassFacts{localAllows: true, managed: true}, true, ""},
		{"managed, policy unreadable", arenaBypassFacts{localAllows: true, managed: true, policyUnreadable: true}, false, "could not be read"},
		{"managed, org forbids", arenaBypassFacts{localAllows: true, managed: true, orgForbids: true, orgWhy: "your organization enforces approval mode \"auto_edits\""}, false, "your organization enforces"},
		{"managed, local off", arenaBypassFacts{managed: true}, false, "is off"},
	}
	for _, c := range cases {
		allow, why := decideArenaBypass(c.f)
		if allow != c.allow || !strings.Contains(why, c.why) {
			t.Errorf("%s: (%v, %q), want (%v, ~%q)", c.name, allow, why, c.allow, c.why)
		}
	}
}

// TestEnforcedAgentConfigValues: only the tool's ENFORCED directives are
// read; a default and another tool's setting are not.
func TestEnforcedAgentConfigValues(t *testing.T) {
	body := `{"schema":1,"directives":[` +
		`{"setting":"claude-code/permissions.defaultMode","value":"acceptEdits","mode":"enforced"},` +
		`{"setting":"claude-code/model","value":"opus","mode":"default"},` +
		`{"setting":"codex/approval_policy","value":"never","mode":"enforced"}]}`
	got, err := enforcedAgentConfigValues(body, "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["claude-code/permissions.defaultMode"] != "acceptEdits" {
		t.Fatalf("enforced = %v", got)
	}
	if _, err := enforcedAgentConfigValues("{not json", "claude-code"); err == nil {
		t.Fatal("an unreadable body read as no directives")
	}
}
