package policy

import (
	"strings"
	"testing"
	"time"
)

// TestMCPRules_Findings is the §5.5 conformance table for the
// finding-driven rows (R-301/302/303/305): one case per row, plus the
// no-findings baseline. The findings are stamped by the guard layer
// (mcpsec diff results); the rows only match on Kind.
func TestMCPRules_Findings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		finding  string
		wantRule string
		wantSev  Severity
	}{
		{name: "R-301 hit: new unpinned server", finding: MCPFindingNewServer, wantRule: "R-301", wantSev: SeverityWarn},
		{name: "R-302 hit: description drift", finding: MCPFindingDescriptionDrift, wantRule: "R-302", wantSev: SeverityCritical},
		{name: "R-303 hit: poisoning heuristic", finding: MCPFindingPoisoning, wantRule: "R-303", wantSev: SeverityHigh},
		{name: "R-305 hit: binary changed", finding: MCPFindingBinaryChanged, wantRule: "R-305", wantSev: SeverityCritical},
		{name: "near-miss: unknown finding kind", finding: "not_a_kind"},
		{name: "near-miss: no findings", finding: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := Event{
				Kind:      KindConfigChange,
				Tool:      "claude-code",
				Target:    "github",
				SessionID: "",
				Now:       time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC),
			}
			if tc.finding != "" {
				ev.MCPFindings = []MCPFinding{{
					Kind: tc.finding, Server: "github", Client: "claude-code", Detail: "test detail",
				}}
			}
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				eng, err := New(Config{Mode: mode, Home: "/home/u"})
				if err != nil {
					t.Fatalf("New %s: %v", mode, err)
				}
				v := eng.Evaluate(ev)
				if tc.wantRule == "" {
					if v.RuleID != "" {
						t.Fatalf("%s: want no hit, got %+v", mode, v)
					}
					continue
				}
				// All four finding rows are flag in BOTH modes — the
				// scan is post-hoc; taint + approve are the levers.
				if v.RuleID != tc.wantRule || v.Decision != DecisionFlag {
					t.Errorf("%s = %s/%s, want %s/flag (reason %q)", mode, v.RuleID, v.Decision, tc.wantRule, v.Reason)
				}
				if v.RuleID == tc.wantRule && v.Severity != tc.wantSev {
					t.Errorf("%s severity = %s, want %s", mode, v.Severity, tc.wantSev)
				}
			}
		})
	}
}

// TestMCPRules_FindingDetailInReason pins the reason shape: the
// verdict must name the server, client and detail so the audit row is
// self-explanatory without config access.
func TestMCPRules_FindingDetailInReason(t *testing.T) {
	t.Parallel()
	eng, err := New(Config{Mode: ModeObserve, Home: "/home/u"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v := eng.Evaluate(Event{
		Kind: KindConfigChange,
		MCPFindings: []MCPFinding{{
			Kind: MCPFindingBinaryChanged, Server: "github", Client: "cursor", Detail: "command npx → curl",
		}},
		Now: time.Now(),
	})
	for _, want := range []string{"github", "cursor", "command npx → curl"} {
		if !contains(v.Reason, want) {
			t.Errorf("reason %q missing %q", v.Reason, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}

// TestMCPRules_R304FileAccess is the R-304 path-row conformance table
// (file-access + config-change kinds): agent writes to MCP registry
// files flag in observe and deny in enforce; reads and unrelated
// writes stay quiet.
func TestMCPRules_R304FileAccess(t *testing.T) {
	t.Parallel()
	cases := []boundaryCase{
		{name: "R-304 hit: claude user registry", kind: KindFileAccess, actionType: "write_file", target: "~/.claude.json", wantRule: "R-304", wantEnforce: DecisionDeny},
		{name: "R-304 hit: cursor user registry", kind: KindFileAccess, actionType: "write_file", target: "~/.cursor/mcp.json", wantRule: "R-304", wantEnforce: DecisionDeny},
		{name: "R-304 hit: project mcp.json", kind: KindFileAccess, actionType: "write_file", target: ".mcp.json", wantRule: "R-304", wantEnforce: DecisionDeny},
		{name: "R-304 hit: project cursor registry", kind: KindFileAccess, actionType: "edit_file", target: ".cursor/mcp.json", wantRule: "R-304", wantEnforce: DecisionDeny},
		{name: "R-304 hit: config-change kind", kind: KindConfigChange, actionType: "", target: "~/.claude.json", wantRule: "R-304", wantEnforce: DecisionDeny},
		{
			name: "R-304 hit: windows claude registry", kind: KindFileAccess, actionType: "write_file",
			target: `C:\Users\u\.claude.json`,
			home:   `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-304", wantEnforce: DecisionDeny,
		},
		// ~/.codex/config.toml is in BOTH R-160's and R-304's tables
		// (it carries hook config AND MCP servers). R-160 wins the tie
		// by table position; both deny in enforce — pinned so the
		// overlap stays a deliberate fact, not an accident.
		{name: "R-304/R-160 overlap: codex config routes to R-160", kind: KindFileAccess, actionType: "write_file", target: "~/.codex/config.toml", wantRule: "R-160", wantEnforce: DecisionDeny},
		{name: "R-304 near-miss: read registry", kind: KindFileAccess, actionType: "read_file", target: "~/.claude.json", wantRule: "R-150", wantEnforce: DecisionFlag},
		{name: "R-304 near-miss: unrelated project json", kind: KindFileAccess, actionType: "write_file", target: "config/mcp-fixtures.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home := tc.home
			if home == "" {
				home = "/home/u"
			}
			root, cwd := tc.root, tc.cwd
			if root == "" {
				root = "/home/u/proj"
			}
			if cwd == "" {
				cwd = root
			}
			ev := Event{
				Kind: tc.kind, ActionType: tc.actionType, Target: tc.target,
				Cwd: cwd, ProjectRoot: root, SessionID: "s1",
				Now: time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC),
			}
			observe, err := New(Config{Mode: ModeObserve, Home: home})
			if err != nil {
				t.Fatalf("New observe: %v", err)
			}
			enforce, err := New(Config{Mode: ModeEnforce, Home: home})
			if err != nil {
				t.Fatalf("New enforce: %v", err)
			}
			ov, efv := observe.Evaluate(ev), enforce.Evaluate(ev)
			if tc.wantRule == "" {
				if ov.RuleID != "" || efv.RuleID != "" {
					t.Fatalf("want no hit, got observe=%+v enforce=%+v", ov, efv)
				}
				return
			}
			if ov.RuleID != tc.wantRule || ov.Decision != DecisionFlag {
				t.Errorf("observe = %s/%s, want %s/flag (reason %q)", ov.RuleID, ov.Decision, tc.wantRule, ov.Reason)
			}
			if efv.RuleID != tc.wantRule || efv.Decision != tc.wantEnforce {
				t.Errorf("enforce = %s/%s, want %s/%s (reason %q)", efv.RuleID, efv.Decision, tc.wantRule, tc.wantEnforce, efv.Reason)
			}
		})
	}
}

// TestMCPRules_R304Shell covers the R-304 shell row.
func TestMCPRules_R304Shell(t *testing.T) {
	t.Parallel()
	cases := []destructiveCase{
		{name: "R-304 sh hit: redirect into cursor registry", cmd: "echo '{}' > ~/.cursor/mcp.json", wantRule: "R-304", wantEnforce: DecisionDeny},
		// Bare ".mcp.json" is not a pathish token (looksPathish), so the
		// realistic redirect shape is the covered one — the same
		// documented tokenizer approximation every path rule shares.
		{name: "R-304 sh hit: redirect into project registry", cmd: "cat cfg.json > .mcp.json", wantRule: "R-304", wantEnforce: DecisionDeny},
		{name: "R-304 sh hit: cp over claude registry", cmd: "cp ./evil.json ~/.claude.json", wantRule: "R-304", wantEnforce: DecisionDeny},
		{
			name: "R-304 sh hit: PS set-content", cmd: `Set-Content C:\Users\u\.cursor\mcp.json '{}'`, dialect: DialectPowerShell,
			home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`,
			wantRule: "R-304", wantEnforce: DecisionDeny,
		},
		{name: "R-304 sh near-miss: cat registry", cmd: "cat ~/.claude.json"},
	}
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// TestMCPToolFromTarget pins the tool-name extraction alongside
// MCPServerFromTarget — both sides of the poisoning name-collision
// heuristic must agree on the parse.
func TestMCPToolFromTarget(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"mcp__github__create_issue", "create_issue"},
		{"mcp__github__search__deep", "search__deep"},
		{"mcp__github", ""},
		{"github/create_issue", "create_issue"},
		{"github:create_issue", "create_issue"},
		{"plain_tool", ""},
		{"", ""},
		{"  mcp__srv__t  ", "t"},
	}
	for _, tc := range cases {
		if got := MCPToolFromTarget(tc.in); got != tc.want {
			t.Errorf("MCPToolFromTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHiddenUnicode pins the exported shared helper (R-180's
// obfuscation table, reused by the §9.3 mcpsec hidden-text row)
// including the Unicode-tags extension added with G10.
func TestHiddenUnicode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{name: "clean text", in: "use this tool to search issues", want: false},
		{name: "single zero-width below density", in: "a\u200bb", want: false},
		{name: "three zero-width", in: "a\u200bb\u200cc\u200dd", want: true},
		{name: "bidi override", in: "abc\u202exyz", want: true},
		{name: "unicode tag block", in: "abc\U000E0041xyz", want: true},
		{name: "tag block end", in: "x\U000E007Fy", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HiddenUnicode(tc.in); got != tc.want {
				t.Errorf("HiddenUnicode = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMCPRules_AccessFindings is the doc3 §12.6 conformance table for the
// Agent Access rows R-306/R-307: they apply to the MCP CALL (KindMCPCall),
// flag in observe, DENY in enforce, and never fire on a config-scan event
// or without the finding the guard's MCP-access seam stamps.
func TestMCPRules_AccessFindings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		kind     EventKind
		finding  string
		wantRule string
		wantSev  Severity
	}{
		{name: "R-306 hit: unapproved server on an mcp_call", kind: KindMCPCall, finding: MCPFindingUnapprovedServer, wantRule: "R-306", wantSev: SeverityHigh},
		{name: "R-307 hit: org grant denied on an mcp_call", kind: KindMCPCall, finding: MCPFindingOrgGrantDenied, wantRule: "R-307", wantSev: SeverityCritical},
		{name: "near-miss: access finding on a config_change event", kind: KindConfigChange, finding: MCPFindingUnapprovedServer},
		{name: "near-miss: mcp_call without a finding", kind: KindMCPCall, finding: ""},
		{name: "near-miss: config finding kind on an mcp_call", kind: KindMCPCall, finding: MCPFindingNewServer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ev := Event{
				Kind:       tc.kind,
				ActionType: "mcp_call",
				Tool:       "claude-code",
				Target:     "mcp__github__create_issue",
				SessionID:  "s1",
				Caps:       Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
				Now:        time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC),
			}
			if tc.finding != "" {
				ev.MCPFindings = []MCPFinding{{Kind: tc.finding, Server: "github", Client: "claude-code", Detail: "node table: no row matched"}}
			}
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				eng, err := New(Config{Mode: mode, Home: "/home/u"})
				if err != nil {
					t.Fatalf("New %s: %v", mode, err)
				}
				v := eng.Evaluate(ev)
				if tc.wantRule == "" {
					if v.RuleID == "R-306" || v.RuleID == "R-307" {
						t.Fatalf("%s: want no access-rule hit, got %+v", mode, v)
					}
					continue
				}
				want := DecisionFlag
				if mode == ModeEnforce {
					want = DecisionDeny
				}
				if v.RuleID != tc.wantRule || v.Decision != want {
					t.Errorf("%s = %s/%s, want %s/%s (reason %q)", mode, v.RuleID, v.Decision, tc.wantRule, want, v.Reason)
				}
				if v.RuleID == tc.wantRule && v.Severity != tc.wantSev {
					t.Errorf("%s severity = %s, want %s", mode, v.Severity, tc.wantSev)
				}
				if v.RuleID == tc.wantRule && !strings.Contains(v.Reason, "node table: no row matched") {
					t.Errorf("%s reason %q does not carry the finding detail", mode, v.Reason)
				}
			}
		})
	}
}
