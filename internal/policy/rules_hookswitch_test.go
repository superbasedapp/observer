package policy

import (
	"strings"
	"testing"
	"time"
)

// testHookSwitches mirrors the shape the guard layer injects from
// internal/hookdisable (this package may not import it). The guard's own
// test pins that the real table reaches the rule.
var testHookSwitches = []HookSwitch{
	{Glob: "~/.claude/settings.json", Key: "disableAllHooks", Off: true, Desc: "hook switch claude.disableAllHooks"},
	{Glob: "**/.claude/settings.json", Key: "disableAllHooks", Off: true, Desc: "hook switch claude.project.disableAllHooks"},
	{Glob: "**/.claude/settings.local.json", Key: "disableAllHooks", Off: true, Desc: "hook switch claude.local.disableAllHooks"},
	{Glob: "**/.codebuddy/settings.local.json", Key: "disableAllHooks", Off: true, Desc: "hook switch codebuddy.local.disableAllHooks"},
	{Glob: "**/.gemini/settings.json", Key: "hooksConfig.enabled", Off: false, Desc: "hook switch gemini.project.hooksConfig.enabled"},
	{Glob: "**/.factory/settings.local.json", Key: "hooksDisabled", Off: true, Desc: "hook switch factory.local.hooksDisabled"},
}

// hookSwitchCase is one R-162 / R-163 row case.
type hookSwitchCase struct {
	name       string
	kind       EventKind
	actionType string
	target     string
	dialect    Dialect
	edits      []ProposedEdit
	// current is the file's content before the write; "-" means the
	// engine has no ReadFile at all (text-only judgement).
	current     string
	home, root  string
	wantRule    string
	wantEnforce Decision
}

func whole(s string) []ProposedEdit { return []ProposedEdit{{Kind: EditWhole, New: s}} }

func replace(old, new string) ProposedEdit {
	return ProposedEdit{Kind: EditReplace, Old: old, New: new}
}

func TestHookSwitchRules(t *testing.T) {
	t.Parallel()
	const local = ".claude/settings.local.json"
	grants := `{"permissions":{"allow":["Bash(ls)"]}}`
	cases := []hookSwitchCase{
		// --- R-162 file-access row: Write ---
		{
			name: "write adds disableAllHooks true", kind: KindFileAccess, actionType: "write_file", target: local,
			edits: whole(`{"permissions":{"allow":[]},"disableAllHooks":true}`), wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "write of permission grants only", kind: KindFileAccess, actionType: "write_file", target: local,
			edits: whole(`{"permissions":{"allow":["Bash(npm test)"]}}`),
		},
		{
			name: "write with disableAllHooks false", kind: KindFileAccess, actionType: "write_file", target: local,
			edits: whole(`{"disableAllHooks":false}`),
		},
		{
			name: "write with the value as a string is not a switch", kind: KindFileAccess, actionType: "write_file", target: local,
			edits: whole(`{"disableAllHooks":"true"}`),
		},
		{
			name: "write with comments and a trailing comma", kind: KindFileAccess, actionType: "write_file", target: local,
			edits: whole("{\n  // keep\n  \"disableAllHooks\": true,\n}"), wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "write of a non-settings file naming the key", kind: KindFileAccess, actionType: "write_file", target: "docs/notes.json",
			edits: whole(`{"disableAllHooks":true}`),
		},
		{name: "write with no proposed content (post-hoc)", kind: KindFileAccess, actionType: "write_file", target: local},
		{
			name: "read of the file", kind: KindFileAccess, actionType: "read_file", target: local,
			edits: whole(`{"disableAllHooks":true}`),
		},
		{
			name: "rewrite that keeps an existing switch", kind: KindFileAccess, actionType: "write_file", target: local,
			current: `{"disableAllHooks":true}`, edits: whole(`{"disableAllHooks":true,"permissions":{"allow":["Bash(ls)"]}}`),
		},
		{
			name: "gemini nested switch off", kind: KindFileAccess, actionType: "write_file", target: ".gemini/settings.json",
			edits: whole(`{"hooksConfig":{"enabled":false}}`), wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "gemini nested switch on", kind: KindFileAccess, actionType: "write_file", target: ".gemini/settings.json",
			edits: whole(`{"hooksConfig":{"enabled":true}}`),
		},
		{
			name: "codebuddy local file", kind: KindFileAccess, actionType: "write_file", target: ".codebuddy/settings.local.json",
			edits: whole(`{"disableAllHooks":true}`), wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "windows path", kind: KindFileAccess, actionType: "write_file", target: `C:\Users\u\proj\.claude\settings.local.json`,
			home: `C:\Users\u`, root: `C:\Users\u\proj`,
			edits: whole(`{"disableAllHooks":true}`), wantRule: "R-162", wantEnforce: DecisionDeny,
		},

		// --- R-162 file-access row: Edit / MultiEdit ---
		{
			name: "edit that only grants a permission", kind: KindFileAccess, actionType: "edit_file", target: local,
			current: grants, edits: []ProposedEdit{replace(`"Bash(ls)"`, `"Bash(ls)","Bash(npm test)"`)},
		},
		{
			name: "edit adding disableAllHooks true", kind: KindFileAccess, actionType: "edit_file", target: local,
			current: grants, edits: []ProposedEdit{replace(`{"permissions"`, `{"disableAllHooks":true,"permissions"`)},
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "edit adding disableAllHooks false", kind: KindFileAccess, actionType: "edit_file", target: local,
			current: grants, edits: []ProposedEdit{replace(`{"permissions"`, `{"disableAllHooks":false,"permissions"`)},
		},
		{
			name: "edit flipping only the value next to the key", kind: KindFileAccess, actionType: "edit_file", target: local,
			current: `{"disableAllHooks":false}`, edits: []ProposedEdit{replace(`false`, `true`)},
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "edit near an existing switch that stays on", kind: KindFileAccess, actionType: "edit_file", target: local,
			current: `{"disableAllHooks":true,"permissions":{"allow":[]}}`,
			edits:   []ProposedEdit{replace(`"disableAllHooks":true,"permissions":{"allow":[]}`, `"disableAllHooks":true,"permissions":{"allow":["Bash(ls)"]}`)},
		},
		{
			name: "edit with no file reader judges the text", kind: KindFileAccess, actionType: "edit_file", target: local,
			current: "-", edits: []ProposedEdit{replace(`"permissions"`, `"disableAllHooks": true, "permissions"`)},
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "edit with no file reader and no key in its text (limit: unseen)", kind: KindFileAccess, actionType: "edit_file", target: local,
			current: "-", edits: []ProposedEdit{replace(`false`, `true`)},
		},
		{
			name: "multiedit whose second edit adds the switch", kind: KindFileAccess, actionType: "edit_file", target: local,
			current: grants, edits: []ProposedEdit{
				replace(`"Bash(ls)"`, `"Bash(ls)","Bash(go test)"`),
				replace(`{"permissions"`, `{"disableAllHooks":true,"permissions"`),
			},
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "replace_all turning every false to true", kind: KindFileAccess, actionType: "edit_file", target: ".factory/settings.local.json",
			current: `{"hooksDisabled":false,"x":false}`, edits: []ProposedEdit{{Kind: EditReplace, Old: "false", New: "true", All: true}},
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "patch fragment adding the switch", kind: KindFileAccess, actionType: "edit_file", target: ".factory/settings.local.json",
			current: `{}`, edits: []ProposedEdit{{Kind: EditFragment, Old: `  "x": 1,`, New: `  "hooksDisabled": true,`}},
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "patch fragment that already held the switch", kind: KindFileAccess, actionType: "edit_file", target: ".factory/settings.local.json",
			edits: []ProposedEdit{{Kind: EditFragment, Old: `"hooksDisabled": true, "x": 1`, New: `"hooksDisabled": true, "x": 2`}},
		},

		// --- R-162 shell row ---
		{
			name: "jq then mv into the file", kind: KindShellExec,
			target:   `jq '.disableAllHooks = true' .claude/settings.local.json > /tmp/s && mv /tmp/s .claude/settings.local.json`,
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "echo redirect into the file", kind: KindShellExec,
			target:   `echo '{"disableAllHooks": true}' > .claude/settings.local.json`,
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "sed -i flipping the value", kind: KindShellExec,
			target:   `sed -i 's/"disableAllHooks": false/"disableAllHooks": true/' .claude/settings.local.json`,
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "python inline script", kind: KindShellExec,
			target:   `python3 -c "import json;p='.claude/settings.local.json';d=json.load(open(p));d['disableAllHooks']=True;json.dump(d,open(p,'w'))"`,
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "gemini nested via echo", kind: KindShellExec,
			target:   `echo '{"hooksConfig":{"enabled":false}}' > .gemini/settings.json`,
			wantRule: "R-162", wantEnforce: DecisionDeny,
		},
		{
			name: "jq setting the switch false", kind: KindShellExec,
			target: `jq '.disableAllHooks = false' .claude/settings.local.json > /tmp/s && mv /tmp/s .claude/settings.local.json`,
		},
		{
			name: "python reading and comparing the switch", kind: KindShellExec,
			target: `python3 -c "import json;print(json.load(open('.claude/settings.local.json')).get('disableAllHooks') == True)"`,
		},
		{name: "cat the file", kind: KindShellExec, target: `cat .claude/settings.local.json`},

		// --- R-163 record-only row ---
		{
			name: "copy over the file (content unseen)", kind: KindShellExec,
			target:   `cp /tmp/evil.json .claude/settings.local.json`,
			wantRule: "R-163", wantEnforce: DecisionFlag,
		},
		{
			name: "jq editing permissions then mv (content unseen)", kind: KindShellExec,
			target:   `jq '.permissions.allow += ["Bash(ls)"]' .claude/settings.local.json > /tmp/s && mv /tmp/s .claude/settings.local.json`,
			wantRule: "R-163", wantEnforce: DecisionFlag,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home, root := tc.home, tc.root
			if home == "" {
				home = "/home/u"
			}
			if root == "" {
				root = "/home/u/proj"
			}
			ev := Event{
				Kind: tc.kind, ActionType: tc.actionType, Target: tc.target, Dialect: tc.dialect,
				Cwd: root, ProjectRoot: root, SessionID: "s1", Edits: tc.edits,
				Now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
			}
			var read func(string) ([]byte, bool)
			if tc.current != "-" {
				read = func(p string) ([]byte, bool) {
					if tc.current == "" || !strings.HasSuffix(strings.ReplaceAll(p, `\`, "/"), strings.ReplaceAll(tc.target, `\`, "/")) {
						return nil, false
					}
					return []byte(tc.current), true
				}
			}
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				e, err := New(Config{Mode: mode, Home: home, HookSwitches: testHookSwitches, ReadFile: read})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				v := e.Evaluate(ev)
				want := tc.wantEnforce
				if mode == ModeObserve {
					want = DecisionFlag
				}
				if tc.wantRule == "" {
					if v.RuleID == "R-162" || v.RuleID == "R-163" {
						t.Fatalf("%s: want no R-162/R-163 hit, got %s/%s (%q)", mode, v.RuleID, v.Decision, v.Reason)
					}
					continue
				}
				if v.RuleID != tc.wantRule || v.Decision != want {
					t.Fatalf("%s: got %s/%s, want %s/%s (%q)", mode, v.RuleID, v.Decision, tc.wantRule, want, v.Reason)
				}
			}
		})
	}
}

// TestHookSwitchRulesInertWithoutTable pins that the rows match nothing
// when the guard layer injected no switch table.
func TestHookSwitchRulesInertWithoutTable(t *testing.T) {
	t.Parallel()
	e, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []Event{
		{Kind: KindFileAccess, ActionType: "write_file", Target: ".claude/settings.local.json", Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", Edits: whole(`{"disableAllHooks":true}`)},
		{Kind: KindShellExec, Target: `cp /tmp/x .claude/settings.local.json`, Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj"},
	} {
		if v := e.Evaluate(ev); v.RuleID == "R-162" || v.RuleID == "R-163" {
			t.Fatalf("no table: got %s for %q", v.RuleID, ev.Target)
		}
	}
}

// TestHookSwitchRuleIsIntegrity pins R-162 in the integrity set: a
// below-org disable or relaxation leaves the deny standing, because a layer
// that relaxed it would let an agent switch every guard hook off.
func TestHookSwitchRuleIsIntegrity(t *testing.T) {
	t.Parallel()
	if !IsIntegrityRuleID("R-162") || IsIntegrityRuleID("R-163") {
		t.Fatal("integrity set: want R-162 in, R-163 (record-only) out")
	}
	allow := DecisionAllow
	ev := Event{
		Kind: KindFileAccess, ActionType: "write_file", Target: ".claude/settings.local.json",
		Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", Edits: whole(`{"disableAllHooks":true}`),
	}
	for name, cfg := range map[string]Config{
		"disabled": {Mode: ModeEnforce, Home: "/home/u", HookSwitches: testHookSwitches, Disabled: []string{"R-162"}},
		"relaxed":  {Mode: ModeEnforce, Home: "/home/u", HookSwitches: testHookSwitches, Overrides: []Override{{RuleID: "R-162", Decision: &allow, Source: "user"}}},
	} {
		e, err := New(cfg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v := e.Evaluate(ev); v.RuleID != "R-162" || v.Decision != DecisionDeny {
			t.Errorf("%s: verdict %s/%s, want R-162/deny", name, v.RuleID, v.Decision)
		}
	}
}

// TestTextSetsSwitch pins the text judgement shapes one row each.
func TestTextSetsSwitch(t *testing.T) {
	t.Parallel()
	dah := HookSwitch{Key: "disableAllHooks", Off: true}
	gem := HookSwitch{Key: "hooksConfig.enabled", Off: false}
	cases := []struct {
		text string
		sw   HookSwitch
		want bool
	}{
		{`"disableAllHooks": true`, dah, true},
		{`"disableAllHooks":false`, dah, false},
		{`\"disableAllHooks\":true`, dah, true},
		{`.disableAllHooks |= true`, dah, true},
		{`$j.disableAllHooks = $true`, dah, true},
		{`d['disableAllHooks']=True`, dah, true},
		{`"mydisableAllHooks": true`, dah, false},
		{`"disableAllHooksX": true`, dah, false},
		{`"disableAllHooks": "true"`, dah, false},
		{`get('disableAllHooks') == True`, dah, false},
		{`"hooksConfig": {"notifications": true, "enabled": false}`, gem, true},
		{`.hooksConfig.enabled = false`, gem, true},
		{`c['hooksConfig']['enabled'] = False`, gem, true},
		{`"enabled": false`, gem, false},
		{`"hooksConfig": {"enabled": true}`, gem, false},
		{`"sandbox": {"enabled": false}`, gem, false},
	}
	for _, tc := range cases {
		if got := textSetsSwitch(tc.text, tc.sw); got != tc.want {
			t.Errorf("textSetsSwitch(%q, %s) = %v, want %v", tc.text, tc.sw.Key, got, tc.want)
		}
	}
}
