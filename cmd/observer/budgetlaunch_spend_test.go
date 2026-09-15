package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestBudgetLaunchSpendAdmission is the table for the boundary's second
// question: given coverage, would this invocation's own tool be denied right
// now? Each case differs only in what the node has RECORDED, never in the
// launch itself.
func TestBudgetLaunchSpendAdmission(t *testing.T) {
	cases := []struct {
		name string
		// spentTool records over-cap usage under that tool ("" records none).
		spentTool string
		tool      string
		evidence  budgetLaunchEvidence
		wantErr   error
		wantRule  string
	}{
		{
			name: "under cap on a proven proxy route runs",
			tool: "claude-code",
			evidence: budgetLaunchEvidence{
				Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820",
			},
		},
		{
			name: "under cap on a shared host runs", tool: "cursor-ide",
			evidence: budgetLaunchEvidence{
				Route: budgetLaunchRouteUnknown, SurfaceClass: integration.SurfaceSharedHost,
			},
		},
		{
			name: "exhausted cap refuses before the process starts",
			// The node's own usage is what exhausts the cap; the launched tool
			// is irrelevant to a node-wide window, which is the point.
			spentTool: "opencode", tool: "claude-code",
			evidence: budgetLaunchEvidence{
				Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820",
			},
			wantErr: errBudgetLaunchDenied, wantRule: "B-623",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
			if tc.spentTool != "" {
				exhaustManagedBudgetLaunchBudget(t, dbPath, tc.spentTool)
			}
			err := enforceBudgetControlledLaunch(context.Background(), cfgPath, tc.tool, tc.evidence)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("under-cap launch refused: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("admission error = %v, want %v", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantRule) {
				t.Fatalf("rendered error %q does not name the rule %q", err.Error(), tc.wantRule)
			}
		})
	}
}

// TestBudgetLaunchSpendRefusalIsSafeToShow pins the rendered half: the
// developer sees the rule id, the engine's own reason and who to ask — through
// the same explicit safe-message path every other launcher refusal uses, never
// an arbitrary internal error string.
func TestBudgetLaunchSpendRefusalIsSafeToShow(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	exhaustManagedBudgetLaunchBudget(t, dbPath, "claude-code")
	err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "claude-code",
		budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820"})
	var visible launcherMessageError
	if !errors.As(err, &visible) {
		t.Fatalf("spend refusal carries no safe launcher message: %v", err)
	}
	message := visible.launcherMessage()
	for _, want := range []string{"observer claude-code", "organization budget", "B-623", "contact your org admin"} {
		if !strings.Contains(message, want) {
			t.Fatalf("launcher message %q is missing %q", message, want)
		}
	}
}

// TestBudgetLaunchRouteProofIsRegistryDriven pins L4: the launch boundary asks
// the registry whether a route proves the backend, so adding or promoting an
// adapter never means editing a tool-name branch here.
func TestBudgetLaunchRouteProofIsRegistryDriven(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		tool string
		want bool
	}{
		{tool: "claude-code", want: true},
		{tool: "codex", want: true},
		{tool: "opencode", want: true},
		{tool: "copilot-cli", want: true},
		{tool: "aider", want: false},
		{tool: "goose", want: false},
		{tool: "gemini-cli", want: false},
		{tool: "muse", want: false},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			t.Parallel()
			capability, ok := integration.For(tc.tool)
			if !ok {
				t.Fatalf("%s capability missing", tc.tool)
			}
			if got := capability.RouteProven(); got != tc.want {
				t.Fatalf("%s RouteProven = %v, want %v", tc.tool, got, tc.want)
			}
		})
	}
}

// TestBudgetLaunchSurfaceUnbindableReadsTheRegistry pins the other capability
// lookup: which surfaces the refusal can stand for. An unknown tool is never
// exempt.
func TestBudgetLaunchSurfaceUnbindableReadsTheRegistry(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		tool     string
		evidence budgetLaunchEvidence
		want     bool
	}{
		{name: "dedicated CLI stays bindable", tool: "opencode"},
		{
			name: "declared shared host is exempt", tool: "opencode", want: true,
			evidence: budgetLaunchEvidence{SurfaceClass: integration.SurfaceSharedHost},
		},
		{name: "declared remote execution is exempt", tool: "chatgpt-web", want: true},
		{name: "IDE-only adapter is exempt", tool: "cline", want: true},
		{name: "unknown tool is never exempt", tool: "not-an-adapter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := budgetLaunchSurfaceUnbindable(tc.tool, tc.evidence); got != tc.want {
				t.Fatalf("budgetLaunchSurfaceUnbindable(%q) = %v, want %v", tc.tool, got, tc.want)
			}
		})
	}
}
