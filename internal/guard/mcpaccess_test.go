package guard

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestMCPAccessSeam_HookDeny is the doc3 §12.6 hook-deny table: the injected
// node MCP-access lookup stamps R-306/R-307 on a KindMCPCall event and the
// REAL engine denies it in enforce (flags in observe); a nil lookup, an
// unknown (no-table) answer, an allow, a non-MCP event and an approved rule
// each leave the call alone.
func TestMCPAccessSeam_HookDeny(t *testing.T) {
	t.Parallel()
	mcpCaps := policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}
	newGuard := func(t *testing.T, mode string) *Guard {
		t.Helper()
		cfg := guardCfg()
		cfg.Mode = mode
		g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
		if err != nil {
			t.Fatalf("guard.New: %v", err)
		}
		return g
	}
	cases := []struct {
		name     string
		mode     string
		lookup   MCPAccessLookup
		ev       policy.Event
		wantRule string
		wantDec  policy.Decision
	}{
		{
			name: "nil lookup: inert", mode: "enforce", lookup: nil,
			ev: policy.Event{Kind: policy.KindMCPCall, ActionType: "mcp_call", Target: "mcp__github__create_issue", SessionID: "s", Caps: mcpCaps},
		},
		{
			name: "no table loaded (Known=false): inert", mode: "enforce",
			lookup: func(string, string) MCPAccessVerdict { return MCPAccessVerdict{} },
			ev:     policy.Event{Kind: policy.KindMCPCall, ActionType: "mcp_call", Target: "mcp__github__create_issue", SessionID: "s", Caps: mcpCaps},
		},
		{
			name: "allowed by the table: no finding", mode: "enforce",
			lookup: func(string, string) MCPAccessVerdict {
				return MCPAccessVerdict{Known: true, Allowed: true, Reason: "g1"}
			},
			ev: policy.Event{Kind: policy.KindMCPCall, ActionType: "mcp_call", Target: "mcp__github__create_issue", SessionID: "s", Caps: mcpCaps},
		},
		{
			name: "unapproved server: R-306 deny in enforce", mode: "enforce",
			lookup: func(server, tool string) MCPAccessVerdict {
				if server != "github" || tool != "create_issue" {
					t.Errorf("lookup got (%q,%q)", server, tool)
				}
				return MCPAccessVerdict{Known: true, Reason: "node table: no row matched (default-deny)"}
			},
			ev:       policy.Event{Kind: policy.KindMCPCall, ActionType: "mcp_call", Target: "mcp__github__create_issue", SessionID: "s", Tool: "claude-code", Caps: mcpCaps},
			wantRule: "R-306", wantDec: policy.DecisionDeny,
		},
		{
			name: "org grant denied: R-307 deny in enforce", mode: "enforce",
			lookup: func(string, string) MCPAccessVerdict {
				return MCPAccessVerdict{Known: true, OrgDenied: true, Reason: "grant g-deny"}
			},
			ev:       policy.Event{Kind: policy.KindMCPCall, ActionType: "mcp_call", Target: "mcp__slack__post_message", SessionID: "s", Tool: "claude-code", Caps: mcpCaps},
			wantRule: "R-307", wantDec: policy.DecisionDeny,
		},
		{
			name: "observe mode: R-306 flags, never denies", mode: "observe",
			lookup:   func(string, string) MCPAccessVerdict { return MCPAccessVerdict{Known: true, Reason: "no row"} },
			ev:       policy.Event{Kind: policy.KindMCPCall, ActionType: "mcp_call", Target: "mcp__github__x", SessionID: "s", Caps: mcpCaps},
			wantRule: "R-306", wantDec: policy.DecisionFlag,
		},
		{
			name: "non-MCP event never consults the lookup", mode: "enforce",
			lookup: func(string, string) MCPAccessVerdict {
				t.Error("lookup consulted for a shell event")
				return MCPAccessVerdict{Known: true}
			},
			ev: policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "go test ./...", SessionID: "s", Caps: mcpCaps},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := newGuard(t, tc.mode)
			g.SetMCPAccessLookup(tc.lookup)
			v, worthy := g.EvaluateHook(tc.ev)
			if tc.wantRule == "" {
				if v.Verdict.RuleID == "R-306" || v.Verdict.RuleID == "R-307" {
					t.Fatalf("unexpected access verdict %+v", v.Verdict)
				}
				return
			}
			if !worthy || v.Verdict.RuleID != tc.wantRule || v.Verdict.Decision != tc.wantDec {
				t.Fatalf("verdict = %+v (worthy=%v), want %s/%s", v.Verdict, worthy, tc.wantRule, tc.wantDec)
			}
			if v.Category != "mcp" {
				t.Errorf("category = %q, want mcp", v.Category)
			}
			em := ResolveEmission(v.Verdict, tc.ev.Caps)
			wantPerm := "deny"
			if tc.wantDec == policy.DecisionFlag {
				wantPerm = "allow"
			}
			if em.Permission != wantPerm {
				t.Errorf("emission = %+v, want permission %s", em, wantPerm)
			}
		})
	}
}

// TestMCPAccessSeam_WatcherPathFlags pins that the same seam reaches the
// post-hoc watcher ingest path (EvaluateActions): a denied call lands an
// R-306 verdict row there too — flag-shaped, since the watcher cannot block.
func TestMCPAccessSeam_WatcherPathFlags(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	g.SetMCPAccessLookup(func(string, string) MCPAccessVerdict { return MCPAccessVerdict{Known: true, Reason: "no row"} })
	out := g.EvaluateActions([]ActionInput{{
		SessionID: "s", Tool: "claude-code", ActionType: "mcp_call", Target: "mcp__github__create_issue",
	}})
	if len(out) != 1 || out[0].Verdict.RuleID != "R-306" {
		t.Fatalf("watcher verdicts = %+v, want one R-306", out)
	}
	if em := ResolveEmission(out[0].Verdict, watcherCaps); em.Permission != "allow" || em.DegradedFrom == "" {
		t.Errorf("watcher emission = %+v, want allow degraded from deny", em)
	}
}
