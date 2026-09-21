package guard

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestParsePolicyFile_MatcherVocabulary compiles each v1 matcher and
// proves it fires (and stays quiet) through a real engine — the §4.4
// vocabulary is behavior, not just parse-able syntax.
func TestParsePolicyFile_MatcherVocabulary(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		rule    string // [[rule]] body lines below id/category/decision
		hit     policy.Event
		miss    policy.Event
		decided policy.Decision // expected observe-mode decision on hit
	}{
		{
			name: "command_base + arg_contains AND-combine",
			rule: "decision = 'flag'\napplies_to = ['shell_exec']\nmatch.command_base = 'kubectl'\nmatch.arg_contains = '--all-namespaces'",
			hit: policy.Event{
				Kind: policy.KindShellExec, ActionType: "run_command",
				Target: "kubectl get pods --all-namespaces",
			},
			miss: policy.Event{
				Kind: policy.KindShellExec, ActionType: "run_command",
				Target: "kubectl get pods -n dev",
			},
			decided: policy.DecisionFlag,
		},
		{
			name: "path_glob with path_not exemption",
			rule: "decision = 'flag'\nmatch.path_glob = ['~/notes/**']\nmatch.path_not = ['~/notes/public/**']",
			hit: policy.Event{
				Kind: policy.KindFileAccess, ActionType: "read_file",
				Target: "/home/u/notes/secret.md", ProjectRoot: "/home/u/proj",
			},
			miss: policy.Event{
				Kind: policy.KindFileAccess, ActionType: "read_file",
				Target: "/home/u/notes/public/readme.md", ProjectRoot: "/home/u/proj",
			},
			decided: policy.DecisionFlag,
		},
		{
			name: "path_sensitive reuses the R-152 table",
			rule: "decision = 'flag'\nmatch.path_sensitive = true",
			hit: policy.Event{
				Kind: policy.KindFileAccess, ActionType: "read_file",
				Target: "/home/u/.ssh/id_rsa", ProjectRoot: "/home/u/proj",
			},
			miss: policy.Event{
				Kind: policy.KindFileAccess, ActionType: "read_file",
				Target: "/home/u/proj/main.go", ProjectRoot: "/home/u/proj",
			},
			decided: policy.DecisionFlag,
		},
		{
			name: "url_domain matches subdomains",
			rule: "decision = 'flag'\nmatch.url_domain = 'pastebin.com'",
			hit: policy.Event{
				Kind: policy.KindToolCall, ActionType: "web_fetch",
				Target: "https://api.pastebin.com/raw/xyz",
			},
			miss: policy.Event{
				Kind: policy.KindToolCall, ActionType: "web_fetch",
				Target: "https://notpastebin.com/x",
			},
			decided: policy.DecisionFlag,
		},
		{
			name: "mcp_server",
			rule: "decision = 'flag'\nmatch.mcp_server = 'github'",
			hit: policy.Event{
				Kind: policy.KindMCPCall, ActionType: "mcp_call",
				Target: "mcp__github__create_issue",
			},
			miss: policy.Event{
				Kind: policy.KindMCPCall, ActionType: "mcp_call",
				Target: "mcp__slack__post_message",
			},
			decided: policy.DecisionFlag,
		},
		{
			name: "taint_source + sink shell_exec",
			rule: "decision = 'ask'\nmatch.taint_source = 'web_fetch'\nmatch.sink = 'shell_exec'",
			hit: policy.Event{
				Kind: policy.KindShellExec, ActionType: "run_command",
				Target: "ls", Taint: policy.TaintState{Marks: []policy.TaintMark{
					{Source: policy.TaintSourceWebFetch, Origin: "x"},
				}},
			},
			miss: policy.Event{
				Kind: policy.KindShellExec, ActionType: "run_command",
				Target: "ls",
			},
			decided: policy.DecisionFlag, // ask degrades to flag in observe
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := "[[rule]]\nid = 'U-T'\ncategory = 'boundary'\n" + tc.rule + "\n"
			pf, err := parsePolicyFile([]byte(body), layerUser)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			eng, err := policy.New(policy.Config{
				Mode: policy.ModeObserve, Home: "/home/u",
				// Isolate the user rule: disable ALL built-ins so the
				// assertion can't be masked by a catalog hit.
				Disabled:   builtinIDs(),
				ExtraRules: pf.rules,
			})
			if err != nil {
				t.Fatalf("engine: %v", err)
			}
			if v := eng.Evaluate(tc.hit); v.RuleID != "U-T" || v.Decision != tc.decided {
				t.Errorf("hit verdict = %+v, want U-T/%v", v, tc.decided)
			}
			if v := eng.Evaluate(tc.miss); v.RuleID == "U-T" {
				t.Errorf("miss fired: %+v", v)
			}
		})
	}
}

// builtinIDs returns every built-in rule ID (for isolating user rules
// in vocabulary tests).
func builtinIDs() []string {
	var ids []string
	seen := map[string]bool{}
	for _, info := range policy.Catalog() {
		if !seen[info.ID] {
			ids = append(ids, info.ID)
			seen[info.ID] = true
		}
	}
	return ids
}

// TestParsePolicyFile_LintErrors pins every loud-rejection class the
// strict parser owns (`observer guard lint` calls this same path).
func TestParsePolicyFile_LintErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want string // error substring
	}{
		{"unknown top-level key", "[[rules]]\nid='x'\n", "unknown keys"},
		{"unknown matcher key", "[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='flag'\nmatch.bogus = 1\n", "unknown keys"},
		{"missing id", "[[rule]]\ncategory='boundary'\ndecision='flag'\nmatch.command_base='x'\n", "missing id"},
		{"missing category", "[[rule]]\nid='U-1'\ndecision='flag'\nmatch.command_base='x'\n", "missing category"},
		{"missing decision", "[[rule]]\nid='U-1'\ncategory='boundary'\nmatch.command_base='x'\n", "missing decision"},
		{"bad decision", "[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='maybe'\nmatch.command_base='x'\n", "unknown decision"},
		{"bad severity", "[[rule]]\nid='U-1'\ncategory='boundary'\nseverity='extreme'\ndecision='flag'\nmatch.command_base='x'\n", "unknown severity"},
		{"builtin id collision", "[[rule]]\nid='R-101'\ncategory='destructive'\ndecision='deny'\nmatch.command_base='rm'\n", "collides with built-in"},
		{"duplicate id", "[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='flag'\nmatch.command_base='a'\n[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='flag'\nmatch.command_base='b'\n", "duplicate id"},
		{"no matchers", "[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='flag'\n", "no matchers"},
		{"mixed matcher classes", "[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='flag'\nmatch.command_base='x'\nmatch.path_glob=['/a/**']\n", "cannot mix"},
		{"bad regex", "[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='flag'\nmatch.command_regex='('\n", "command_regex"},
		{"unknown event_kind", "[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='flag'\nmatch.event_kind=['weird']\n", "unknown event_kind"},
		{"unknown applies_to", "[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='flag'\napplies_to=['weird']\nmatch.command_base='x'\n", "unknown applies_to"},
		{"unknown sink", "[[rule]]\nid='U-1'\ncategory='boundary'\ndecision='flag'\nmatch.sink='volcano'\n", "unknown sink"},
		{"taint_source alone cannot infer kinds", "[[rule]]\nid='U-1'\ncategory='taint'\ndecision='flag'\nmatch.taint_source='web_fetch'\n", "cannot infer applies_to"},
		{"cost matcher alone cannot infer kinds", "[[rule]]\nid='U-1'\ncategory='budget'\ndecision='flag'\nmatch.session_cost_usd_gt=5.0\n", "cannot infer applies_to"},
		{"repeat matcher alone cannot infer kinds", "[[rule]]\nid='U-1'\ncategory='anomaly'\ndecision='flag'\nmatch.repeat_count_gt=5\n", "cannot infer applies_to"},
		{"override missing rule", "[[override]]\ndecision='deny'\n", "missing rule id"},
		{"override bad decision", "[[override]]\nrule='R-110'\ndecision='maybe'\n", "unknown decision"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parsePolicyFile([]byte(tc.body), layerUser)
			if err == nil {
				t.Fatal("expected a parse error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestPolicyRuleRefs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		body          string
		wantOverrides []string
		wantDeclared  []string
		wantDisabled  []string
		wantErr       bool
	}{
		{
			name: "overrides and declared rules",
			body: "[[override]]\nrule='R-110'\ndecision='deny'\n" +
				"[[override]]\nrule='R-172'\nenforce=true\n" +
				"[[rule]]\nid='ORG-1'\ncategory='boundary'\ndecision='flag'\nmatch.command_base='scp'\n",
			wantOverrides: []string{"R-110", "R-172"},
			wantDeclared:  []string{"ORG-1"},
		},
		{
			name:         "top-level disable list is reported",
			body:         "disable = ['R-101', 'R-152']\n",
			wantDisabled: []string{"R-101", "R-152"},
		},
		{
			name:          "empty file",
			body:          "",
			wantOverrides: nil,
			wantDeclared:  nil,
		},
		{
			name:          "loose parse tolerates what Lint rejects",
			body:          "[[rule]]\nid='ORG-2'\n", // no category/decision/matchers: Lint fails, refs still readable
			wantDeclared:  []string{"ORG-2"},
			wantOverrides: nil,
		},
		{
			name:    "structurally unparseable",
			body:    "[[override\n",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ov, decl, dis, err := PolicyRuleRefs([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected a parse error")
				}
				return
			}
			if err != nil {
				t.Fatalf("PolicyRuleRefs: %v", err)
			}
			if !slices.Equal(ov, tc.wantOverrides) {
				t.Errorf("overrides = %v, want %v", ov, tc.wantOverrides)
			}
			if !slices.Equal(decl, tc.wantDeclared) {
				t.Errorf("declared = %v, want %v", decl, tc.wantDeclared)
			}
			if !slices.Equal(dis, tc.wantDisabled) {
				t.Errorf("disabled = %v, want %v", dis, tc.wantDisabled)
			}
		})
	}
}
