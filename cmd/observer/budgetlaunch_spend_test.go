package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
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

// TestSubjectCapReachesTheTwoDirectVendorChokepoints is the BUD-GUARD-1 table
// (docs/audits/codebase-audit-2026-09-16.md): where can the organization's
// per-MODEL cap stop a DIRECT-VENDOR (non-proxied) developer?
//
// The process-control pass never names a model itself. The ONE resolver is the
// accounting snapshot's SessionModel, the sibling of SessionTool, so an org
// model cap reaches a RUNNING session through the session's own captured rows
// — which is why the first two rows differ from the third. It reaches a LAUNCH
// never (the sibling test below), because a process that has not started names
// no model.
//
// Row 2 is the honest surprise the audit did not name: a session whose rows do
// NOT agree on one model is not admitted either. A hard model cap that cannot
// attribute the session fails closed rather than guessing which of two models
// the next request will use — the same direction every other unverifiable
// managed-budget input takes.
func TestSubjectCapReachesTheTwoDirectVendorChokepoints(t *testing.T) {
	cases := []struct {
		name string
		// session is the session id handed to the process-control pass, and
		// sessionModels the models its captured rows name.
		session       string
		sessionModels []string
		wantStop      bool
		// wantRule is the rule the decision must carry when it stops.
		wantRule string
		why      string
	}{
		{
			name:    "a session whose rows name one model is stopped",
			session: "s-one", sessionModels: []string{"gpt-5.4"},
			wantStop: true, wantRule: "B-629",
			why: "SessionModel resolves, so the org's per-model cap scopes the decision",
		},
		{
			name:    "a session whose rows name two models is stopped too",
			session: "s-two", sessionModels: []string{"gpt-5.4", "claude-sonnet-5"},
			wantStop: true, wantRule: "B-629",
			why: "a hard model cap it cannot attribute fails closed; it never admits on a guess",
		},
		{
			name:    "a workload with no session id is not",
			session: "", sessionModels: nil,
			wantStop: false,
			why:      "nothing names a model for an unbound process, and the node-wide windows are under cap",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gd, st, cfg := publishedModelCapFixture(t, tc.session, tc.sessionModels)
			w := intervention.Workload{
				SurfaceID: "fixture/cli", SessionID: tc.session,
				Identity: intervention.Identity{UID: os.Getuid()},
			}
			d, err := nodeInterventionBudget(context.Background(), st, cfg, gd, w,
				nodeInterventionSource{Tool: "codex", Ready: true, Reason: "ready"}, time.Now().UTC())
			if err != nil {
				t.Fatalf("nodeInterventionBudget: %v", err)
			}
			if d.Stop != tc.wantStop {
				t.Fatalf("stop = %v (rule %q, %q), want %v — %s", d.Stop, d.RuleID, d.Reason, tc.wantStop, tc.why)
			}
			if tc.wantStop && d.RuleID != tc.wantRule {
				t.Fatalf("rule = %q, want %q — %s", d.RuleID, tc.wantRule, tc.why)
			}
		})
	}
}

// TestModelCapCannotRefuseALaunch is the launch half of the same table: the
// identical published model cap, exceeded by the identical recorded usage,
// must NOT refuse a launch — and a node-wide cap must, so the test proves the
// chokepoint is live rather than inert.
func TestModelCapCannotRefuseALaunch(t *testing.T) {
	cases := []struct {
		name     string
		modelCap bool
		wantErr  bool
		why      string
	}{
		{
			name: "an exceeded per-model cap admits the launch", modelCap: true, wantErr: false,
			why: "a process that has not started names no model, so B-628/B-629 cannot scope it",
		},
		{
			name: "an exceeded node-wide cap still refuses it", modelCap: false, wantErr: true,
			why: "the node-wide window needs neither a session nor a model",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
			if !tc.modelCap {
				exhaustManagedBudgetLaunchBudget(t, dbPath, "codex")
			}
			err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "codex",
				budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820"})
			if tc.wantErr {
				if !errors.Is(err, errBudgetLaunchDenied) {
					t.Fatalf("launch admitted: %v — %s", err, tc.why)
				}
				return
			}
			if err != nil {
				t.Fatalf("launch refused: %v — %s", err, tc.why)
			}
		})
	}
}

// publishedModelCapFixture builds a managed node whose organization published
// an exceeded per-model TOKEN cap, with `models` recorded against `session`.
//
// A token cap rather than a dollar one on purpose: tokens are captured, not
// priced, so the fixture proves the subject scoping without also having to
// stand up a verified org price table.
func publishedModelCapFixture(t *testing.T, session string, models []string) (*guard.Guard, *store.Store, config.Config) {
	t.Helper()
	_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ts := time.Now().UTC().Format(time.RFC3339)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("fixture exec: %v\n%s", err, q)
		}
	}
	if session != "" {
		exec(`INSERT INTO projects (root_path, name, created_at) VALUES ('/repo/p','p',?)`, ts)
		exec(`INSERT INTO sessions (id, project_id, tool, started_at)
		      VALUES (?, (SELECT id FROM projects WHERE root_path='/repo/p'), 'codex', ?)`, session, ts)
		for i, m := range models {
			exec(`INSERT INTO token_usage (source_file, source_event_id, session_id, timestamp, tool, model,
			          input_tokens, output_tokens, estimated_cost_usd, source, reliability)
			      VALUES ('r.jsonl', ?, ?, ?, 'codex', ?, 1000, 500, 0, 'jsonl', 'reliable')`,
				fmt.Sprintf("tk:%d", i), session, ts, m)
		}
	}
	st := store.New(database)
	cfg := config.Default()
	cfg.Observer.DBPath = dbPath
	cfg.Guard.Enabled, cfg.Guard.Mode, cfg.Guard.Budget.FromOrg = true, "enforce", true
	gd := buildGuardForStore(ctx, cfg, st, slog.Default())
	if gd == nil {
		t.Fatal("buildGuardForStore returned no guard")
	}
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("budget identity: active=%v err=%v", active, err)
	}
	durable, err := st.LoadOrgBudget(ctx)
	if err != nil {
		t.Fatalf("LoadOrgBudget: %v", err)
	}
	// ONE publication, the way the org composition boundary does it: an
	// exceeded per-model token cap under ModelTokens protection, with no
	// node-wide numbers at all, so only the subject row can deny.
	if err := gd.ApplyOrgComposedBudget(
		config.GuardBudgetConfig{}, nil, false,
		policy.BudgetProtection{ModelTokens: true}, identity.Binding,
		guardBudgetDocumentWitness(durable.Witness),
		policy.BudgetWindowAmounts{}, false,
		[]policy.BudgetSubjectCap{{
			Kind: policy.BudgetSubjectKindModel, ID: "gpt-5.4",
			Window: policy.BudgetWindowDaily, CapTokens: 10, Hard: true,
		}},
	); err != nil {
		t.Fatalf("ApplyOrgComposedBudget: %v", err)
	}
	return gd, st, cfg
}
