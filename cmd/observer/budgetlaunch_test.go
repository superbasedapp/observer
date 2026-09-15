package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// managedBudgetLaunchFixtureCapTokens is the managed fixture's hard cap. It is
// TOKEN-denominated for the same reason the original fixture was: a managed $
// cap is only measurable against a verified org PRICE table, so a dollar cap
// here would make every launch refuse for unavailable pricing and the fixture
// could exercise only the fail-closed half of the boundary. The cap is
// generous, so a launch with no recorded usage is comfortably under it and a
// test that wants the exhausted half says so by recording usage.
const managedBudgetLaunchFixtureCapTokens = 100_000

func cachedBudget(enforcement, period string, tokens int64) store.OrgBudgetCache {
	return store.OrgBudgetCache{
		Have: true,
		Body: orgcontract.BudgetPolicyBody{
			Version: 1,
			Caps: []orgcontract.BudgetPolicyCap{{
				Period: period, CapTokens: tokens, Enforcement: enforcement,
			}},
		},
	}
}

func TestComposeManagedBudgetLaunchState(t *testing.T) {
	t.Parallel()

	hard := cachedBudget(orgcontract.BudgetPolicyEnforcementHard,
		orgcontract.BudgetPolicyPeriodCalendarMonth, 1000)
	soft := cachedBudget(orgcontract.BudgetPolicyEnforcementSoft,
		orgcontract.BudgetPolicyPeriodCalendarMonth, 1000)
	report := cachedBudget("report", orgcontract.BudgetPolicyPeriodCalendarMonth, 1000)
	rolling := cachedBudget(orgcontract.BudgetPolicyEnforcementHard,
		orgcontract.BudgetPolicyPeriodRolling30d, 1000)
	explicitNone := store.OrgBudgetCache{Have: true, Body: orgcontract.BudgetPolicyBody{ResolvedScope: "none"}}

	base := config.Config{Guard: config.GuardConfig{
		Enabled: true, Mode: "enforce", Budget: config.GuardBudgetConfig{FromOrg: true},
	}}
	cases := []struct {
		name      string
		cfg       config.Config
		cached    store.OrgBudgetCache
		cacheErr  error
		granted   bool
		wantReq   bool
		wantReady bool
	}{
		{name: "individual hard cap unaffected", cfg: base, cached: hard, wantReady: true},
		{name: "managed hard cap requires control", cfg: base, cached: hard, granted: true, wantReq: true, wantReady: true},
		{name: "managed soft cap unaffected", cfg: base, cached: soft, granted: true, wantReady: true},
		{name: "managed report cap unaffected", cfg: base, cached: report, granted: true, wantReady: true},
		{name: "managed explicit signed none unaffected", cfg: base, cached: explicitNone, granted: true, wantReady: true},
		{name: "managed no cap unaffected", cfg: base, cached: store.OrgBudgetCache{Have: true}, granted: true, wantReady: true},
		{name: "unmapped hard rolling cap unaffected", cfg: base, cached: rolling, granted: true, wantReady: true},
		{name: "missing verified budget activates blocking ceiling", cfg: base, granted: true, wantReq: true, wantReady: true},
		{name: "unreadable verified budget activates blocking ceiling", cfg: base, cacheErr: errors.New("corrupt"), granted: true, wantReq: true, wantReady: true},
		{
			name: "disabled guard does not erase hard requirement",
			cfg: config.Config{Guard: config.GuardConfig{
				Enabled: false, Mode: "off", Budget: config.GuardBudgetConfig{FromOrg: true},
			}},
			cached: hard, granted: true, wantReq: true,
		},
		{
			name: "observe guard does not erase hard requirement",
			cfg: config.Config{Guard: config.GuardConfig{
				Enabled: true, Mode: "observe", Budget: config.GuardBudgetConfig{FromOrg: true},
			}},
			cached: hard, granted: true, wantReq: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := composeManagedBudgetLaunchState(tc.cfg, tc.cached, tc.cacheErr, tc.granted)
			if got.Required != tc.wantReq || got.GuardReady != tc.wantReady {
				t.Fatalf("state = %+v, want Required=%v GuardReady=%v", got, tc.wantReq, tc.wantReady)
			}
		})
	}
}

func TestEnvBudgetLaunchEvidenceRejectsOverridesAndAmbiguity(t *testing.T) {
	t.Parallel()
	proxyURL := "http://127.0.0.1:8820"
	home := t.TempDir()
	geminiWant := map[string]string{"GOOGLE_GEMINI_BASE_URL": proxyURL}
	cases := []struct {
		name     string
		tool     string
		env      []string
		expected map[string]string
		args     []string
		settings string
		want     budgetLaunchRoute
	}{
		{name: "Gemini API-key route remains unresolved", tool: "gemini-cli", env: []string{"GOOGLE_GEMINI_BASE_URL=" + proxyURL, "GEMINI_API_KEY=dummy"}, expected: geminiWant, want: budgetLaunchRouteUnknown},
		{name: "direct env override", tool: "gemini-cli", env: []string{"GOOGLE_GEMINI_BASE_URL=https://example.test", "GEMINI_API_KEY=dummy"}, expected: geminiWant, want: budgetLaunchRouteUnknown},
		{name: "Gemini Vertex provider override", tool: "gemini-cli", env: []string{"GOOGLE_GEMINI_BASE_URL=" + proxyURL, "GEMINI_API_KEY=dummy"}, expected: geminiWant, args: []string{"--provider", "vertex"}, want: budgetLaunchRouteUnknown},
		{name: "config override", tool: "gemini-cli", env: []string{"GOOGLE_GEMINI_BASE_URL=" + proxyURL, "GEMINI_API_KEY=dummy"}, expected: geminiWant, args: []string{"--config=other.toml"}, want: budgetLaunchRouteUnknown},
		{name: "Gemini OAuth selection", tool: "gemini-cli", env: []string{"GOOGLE_GEMINI_BASE_URL=" + proxyURL, "GEMINI_API_KEY=dummy"}, expected: geminiWant, settings: `{"selectedAuthType":"oauth-personal"}`, want: budgetLaunchRouteUnknown},
		{name: "Gemini Vertex credentials", tool: "gemini-cli", env: []string{"GOOGLE_GEMINI_BASE_URL=" + proxyURL, "GEMINI_API_KEY=dummy", "GOOGLE_CLOUD_PROJECT=proj"}, expected: geminiWant, want: budgetLaunchRouteUnknown},
		{name: "Gemini explicit Vertex disabled remains unresolved", tool: "gemini-cli", env: []string{"GOOGLE_GEMINI_BASE_URL=" + proxyURL, "GEMINI_API_KEY=dummy", "GOOGLE_GENAI_USE_VERTEXAI=false"}, expected: geminiWant, want: budgetLaunchRouteUnknown},
		{name: "Aider base URL route remains unresolved", tool: "aider", env: []string{"OPENAI_API_BASE=" + proxyURL + "/v1"}, expected: map[string]string{"OPENAI_API_BASE": proxyURL + "/v1"}, want: budgetLaunchRouteUnknown},
		{name: "Aider Anthropic model", tool: "aider", env: []string{"OPENAI_API_BASE=" + proxyURL + "/v1"}, expected: map[string]string{"OPENAI_API_BASE": proxyURL + "/v1"}, args: []string{"--model", "claude-3-5-sonnet"}, want: budgetLaunchRouteUnknown},
		{name: "Aider short model", tool: "aider", env: []string{"OPENAI_API_BASE=" + proxyURL + "/v1"}, expected: map[string]string{"OPENAI_API_BASE": proxyURL + "/v1"}, args: []string{"-m", "claude-3-5-sonnet"}, want: budgetLaunchRouteUnknown},
		{name: "Aider config file", tool: "aider", env: []string{"OPENAI_API_BASE=" + proxyURL + "/v1"}, expected: map[string]string{"OPENAI_API_BASE": proxyURL + "/v1"}, args: []string{"--config", "aider.conf.yml"}, want: budgetLaunchRouteUnknown},
		{name: "Goose configured non-OpenAI provider", tool: "goose", env: []string{"OPENAI_HOST=" + proxyURL}, expected: map[string]string{"OPENAI_HOST": proxyURL}, want: budgetLaunchRouteUnknown},
		{name: "Goose explicit OpenAI provider remains unresolved", tool: "goose", env: []string{"OPENAI_HOST=" + proxyURL}, expected: map[string]string{"OPENAI_HOST": proxyURL}, args: []string{"--provider", "openai"}, want: budgetLaunchRouteUnknown},
		{name: "Goose ambient non-OpenAI provider", tool: "goose", env: []string{"OPENAI_HOST=" + proxyURL, "GOOSE_PROVIDER=anthropic"}, expected: map[string]string{"OPENAI_HOST": proxyURL}, want: budgetLaunchRouteUnknown},
		{name: "Copilot ambient non-OpenAI provider", tool: "copilot-cli", env: []string{"COPILOT_PROVIDER_BASE_URL=" + proxyURL + "/v1", "COPILOT_PROVIDER_TYPE=azure"}, expected: map[string]string{"COPILOT_PROVIDER_BASE_URL": proxyURL + "/v1", "COPILOT_PROVIDER_TYPE": "openai"}, want: budgetLaunchRouteUnknown},
		{name: "Copilot explicit OpenAI provider", tool: "copilot-cli", env: []string{"COPILOT_PROVIDER_BASE_URL=" + proxyURL + "/v1", "COPILOT_PROVIDER_TYPE=openai"}, expected: map[string]string{"COPILOT_PROVIDER_BASE_URL": proxyURL + "/v1", "COPILOT_PROVIDER_TYPE": "openai"}, want: budgetLaunchRouteObserverProxy},
		{name: "Copilot provider-type override", tool: "copilot-cli", env: []string{"COPILOT_PROVIDER_BASE_URL=" + proxyURL + "/v1", "COPILOT_PROVIDER_TYPE=openai"}, expected: map[string]string{"COPILOT_PROVIDER_BASE_URL": proxyURL + "/v1", "COPILOT_PROVIDER_TYPE": "openai"}, args: []string{"--provider-type", "azure"}, want: budgetLaunchRouteUnknown},
		// OpenCode's registry row declares RouteProofLauncherRoute: the
		// injected OPENAI_BASE_URL is both the route and the provider
		// selection, so a surviving injection IS the proxy route. The generic
		// selector scan still takes the proof away per invocation.
		{name: "OpenCode injected base URL is the proven route", tool: "opencode", env: []string{"OPENAI_BASE_URL=" + proxyURL + "/v1"}, expected: map[string]string{"OPENAI_BASE_URL": proxyURL + "/v1"}, want: budgetLaunchRouteObserverProxy},
		{name: "OpenCode overridden base URL", tool: "opencode", env: []string{"OPENAI_BASE_URL=https://example.test/v1"}, expected: map[string]string{"OPENAI_BASE_URL": proxyURL + "/v1"}, want: budgetLaunchRouteUnknown},
		{name: "OpenCode generic provider selector", tool: "opencode", env: []string{"OPENAI_BASE_URL=" + proxyURL + "/v1"}, expected: map[string]string{"OPENAI_BASE_URL": proxyURL + "/v1"}, args: []string{"--provider", "anthropic"}, want: budgetLaunchRouteUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			caseHome := home
			if tc.settings != "" {
				caseHome = t.TempDir()
				if err := os.MkdirAll(filepath.Join(caseHome, ".gemini"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(caseHome, ".gemini", "settings.json"), []byte(tc.settings), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			env := append(append([]string(nil), tc.env...), "HOME="+caseHome)
			got := envBudgetLaunchEvidence(tc.tool, proxyURL, tc.expected, env, tc.args)
			if got.Route != tc.want {
				t.Fatalf("route = %v, want %v", got.Route, tc.want)
			}
		})
	}
}

func TestMuseBudgetLaunchEvidenceAllowsOnlyGroundedMaintenance(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args []string
		want budgetLaunchRoute
	}{
		{name: "exact help", args: []string{"--help"}, want: budgetLaunchRouteMaintenance},
		{name: "exact version", args: []string{"-V"}, want: budgetLaunchRouteMaintenance},
		{name: "auth", args: []string{"auth"}, want: budgetLaunchRouteMaintenance},
		{name: "known top-level flag then export", args: []string{"--workspace", "/repo", "export", "session"}, want: budgetLaunchRouteMaintenance},
		{name: "known joined flag then skills", args: []string{"--provider=meta", "skills", "list"}, want: budgetLaunchRouteMaintenance},
		{name: "model-bearing exec", args: []string{"exec", "hello"}, want: budgetLaunchRouteDirect},
		{name: "model-bearing resume", args: []string{"resume", "session-id"}, want: budgetLaunchRouteDirect},
		{name: "session message", args: []string{"session-message", "hello"}, want: budgetLaunchRouteDirect},
		{name: "sandbox child command stays controlled", args: []string{"sandbox", "run", "muse"}, want: budgetLaunchRouteDirect},
		{name: "unknown flag is ambiguous", args: []string{"--future-flag", "auth"}, want: budgetLaunchRouteDirect},
		{name: "optional value flag is ambiguous", args: []string{"--worktree", "auth"}, want: budgetLaunchRouteDirect},
		{name: "help mixed with prompt", args: []string{"--help", "write code"}, want: budgetLaunchRouteDirect},
		{name: "bare prompt", args: []string{"write code"}, want: budgetLaunchRouteDirect},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := museBudgetLaunchEvidence(tc.args).Route; got != tc.want {
				t.Fatalf("museBudgetLaunchEvidence(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestEnforceBudgetControlledLaunchColdState(t *testing.T) {
	t.Parallel()
	cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")

	err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "muse",
		budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
	if !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("direct Muse admission error = %v, want managed hard-budget refusal", err)
	}
}

func TestEnforceBudgetControlledLaunchAllowsVerifiedProxyRoute(t *testing.T) {
	t.Parallel()
	cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")

	err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "claude-code",
		budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://localhost:8820/v1"})
	if err != nil {
		t.Fatalf("verified configured proxy route refused: %v", err)
	}
}

func TestEnforceBudgetControlledLaunchRejectsAmbiguousProxyOverride(t *testing.T) {
	t.Parallel()
	cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")

	err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "claude-code",
		budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:9999"})
	if !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("custom proxy admission error = %v, want unknown-route refusal", err)
	}
}

func TestEnforceBudgetControlledLaunchMissingVerifiedBudget(t *testing.T) {
	t.Parallel()
	cfgPath, _ := writeManagedBudgetLaunchFixture(t, false, "enforce")

	err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "claude-code",
		budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
	if !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("missing-budget admission error = %v, want B-625-style refusal", err)
	}
}

func TestEnforceBudgetControlledLaunchRefusesUnreadyGuard(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"off", "observe"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, mode)
			err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "claude-code",
				budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820"})
			if !errors.Is(err, errBudgetLaunchUncontrolled) {
				t.Fatalf("mode %s admission error = %v, want unready-Guard refusal", mode, err)
			}
		})
	}
}

func TestEnforceBudgetControlledLaunchUsesGovernancePinnedGuardPosture(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "off")
	sidecar := `{"schema":1,"state":"applied","pinned":{"guard.enabled":true,"guard.mode":"enforce"}}`
	if err := os.WriteFile(filepath.Join(filepath.Dir(dbPath), config.GovernanceSidecarFilename), []byte(sidecar), 0o600); err != nil {
		t.Fatalf("write governance sidecar: %v", err)
	}
	err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "claude-code",
		budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: "http://127.0.0.1:8820"})
	if err != nil {
		t.Fatalf("governance-pinned enforcing Guard was not used by cold launch: %v", err)
	}
}

func TestEnforceBudgetControlledLaunchReturnsStateReadErrors(t *testing.T) {
	t.Parallel()

	err := enforceBudgetControlledLaunch(context.Background(), filepath.Join(t.TempDir(), "missing.toml"),
		"muse", budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
	if err == nil || !strings.Contains(err.Error(), "cannot determine safe launch state") {
		t.Fatalf("missing config error = %v, want safe-state read error", err)
	}

	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	database, openErr := db.Open(context.Background(), db.Options{Path: dbPath})
	if openErr != nil {
		t.Fatalf("reopen DB: %v", openErr)
	}
	if delErr := store.New(database).DeleteAllEnrolmentGrants(context.Background()); delErr != nil {
		t.Fatalf("DeleteAllEnrolmentGrants: %v", delErr)
	}
	if closeErr := database.Close(); closeErr != nil {
		t.Fatalf("close DB: %v", closeErr)
	}
	err = enforceBudgetControlledLaunch(context.Background(), cfgPath, "muse",
		budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
	if err == nil || errors.Is(err, errBudgetLaunchUncontrolled) ||
		!strings.Contains(err.Error(), "managed enrolment has no readable grant") {
		t.Fatalf("missing managed grant error = %v, want ordinary safe-state error", err)
	}
}

func TestEnforceBudgetControlledLaunchRejectsExpiredManagedGrant(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchGrant(t, dbPath, func(grant *store.EnrolmentGrant) {
		grant.ExpiresAt = time.Now().UTC().Add(-time.Hour)
		grant.SignedExpiresAt = grant.ExpiresAt
	})

	err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "muse",
		budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
	if err == nil || errors.Is(err, errBudgetLaunchUncontrolled) ||
		!strings.Contains(err.Error(), "managed enrolment grant is expired") {
		t.Fatalf("expired managed grant error = %v, want ordinary safe-state error", err)
	}
}

func TestEnforceBudgetControlledLaunchHonorsValidExplicitRevocation(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchGrant(t, dbPath, func(grant *store.EnrolmentGrant) {
		grant.Authority = []string{}
	})

	err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "muse",
		budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
	if err != nil {
		t.Fatalf("valid grant without enforce.budget should leave direct launch available: %v", err)
	}
}

func TestEnforceBudgetControlledLaunchLeavesExpiredIndividualGrantUnmanaged(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchEnrolment(t, dbPath, func(enrolment *store.Enrolment) {
		enrolment.Tenancy = orgcontract.TenancyIndividual
	})
	rewriteBudgetLaunchGrant(t, dbPath, func(grant *store.EnrolmentGrant) {
		grant.ConsentMode = govern.ConsentInteractive
		grant.ExpiresAt = time.Now().UTC().Add(-time.Hour)
		grant.SignedExpiresAt = grant.ExpiresAt
	})

	err := enforceBudgetControlledLaunch(context.Background(), cfgPath, "muse",
		budgetLaunchEvidence{Route: budgetLaunchRouteDirect})
	if err != nil {
		t.Fatalf("expired individual grant must not activate managed launch control: %v", err)
	}
}

func TestRunSeedOnlyLaunchSeededNeverStartsMuseUnderManagedHardBudget(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	marker := filepath.Join(t.TempDir(), "started")
	bin := filepath.Join(t.TempDir(), "fake-muse")
	body := "#!/bin/sh\n: > " + marker + "\n"
	if err := os.WriteFile(bin, []byte(body), 0o700); err != nil {
		t.Fatalf("write fake Muse: %v", err)
	}
	err := runSeedOnlyLaunchSeeded(cfgPath, dbPath, "muse", "muse", bin, nil, "")
	if !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("runSeedOnlyLaunchSeeded error = %v, want managed hard-budget refusal", err)
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("fake Muse process started; marker stat error = %v", statErr)
	}
}

func TestRunSeedOnlyLaunchSeededAllowsMuseMaintenanceUnderManagedHardBudget(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	marker := filepath.Join(t.TempDir(), "started")
	bin := filepath.Join(t.TempDir(), "fake-muse")
	body := "#!/bin/sh\n: > " + marker + "\n"
	if err := os.WriteFile(bin, []byte(body), 0o700); err != nil {
		t.Fatalf("write fake Muse: %v", err)
	}
	args := []string{"auth"}
	err := runSeedOnlyLaunchSeededWithEvidence(cfgPath, dbPath, "muse", "muse", bin, args, "",
		museBudgetLaunchEvidence(args))
	if err != nil {
		t.Fatalf("grounded Muse maintenance command refused: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatalf("fake Muse maintenance process did not start: %v", statErr)
	}
}

func TestWireGuardProxyKeepsBudgetScannerWhenOtherScansOff(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "observer.db")
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	processGuards.mu.Lock()
	delete(processGuards.m, dbPath)
	processGuards.mu.Unlock()
	t.Cleanup(func() {
		processGuards.mu.Lock()
		delete(processGuards.m, dbPath)
		processGuards.mu.Unlock()
	})

	cfg := config.Config{
		Observer: config.ObserverConfig{DBPath: dbPath},
		Guard:    config.GuardConfig{Enabled: true, Mode: "enforce"},
	}
	var opts proxy.Options
	wireGuardProxy(ctx, cfg, store.New(database), &opts,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if opts.Guard == nil {
		t.Fatal("proxy Guard is nil with all proxy/MCP scan toggles off; budget scanning would be absent")
	}
	if lookupProcessGuard(dbPath) == nil {
		t.Fatal("wireGuardProxy did not publish the shared process Guard")
	}
	if err := lookupProcessGuard(dbPath).ApplyOrgBudget(config.GuardBudgetConfig{}, nil, true, policy.BudgetProtection{}, ""); err != nil {
		t.Fatalf("ApplyOrgBudget(required): %v", err)
	}
	got := opts.Guard.ScanRequest(ctx, "openai", []byte(`{"model":"test"}`), "")
	if got.Action != "deny" || got.RuleID != "B-625" {
		t.Fatalf("required-budget scan = %+v, want deny B-625", got)
	}
}

func writeManagedBudgetLaunchFixture(t *testing.T, withBudget bool, guardMode string) (string, string) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	st := store.New(database)
	const orgID = "org-budget-launch-test"
	const orgURL = "https://org.example.test"
	orgKey := orgclient.OrgKey(orgURL, orgID)
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: orgID, OrgName: "Budget Test", OrgServerURL: orgURL,
		UserID: "budget-test-member", Tenancy: orgcontract.TenancyManaged,
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	generation, err := st.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatalf("BumpEnrolmentGeneration: %v", err)
	}
	now := time.Now().UTC()
	if err := st.WriteEnrolmentGrant(ctx, store.EnrolmentGrant{
		OrgKey: orgKey, Generation: generation, OrgID: orgID, OrgName: "Budget Test",
		OrgServerURL: orgURL, Authority: []string{govern.AuthorityEnforceBudget},
		ConsentMode: govern.ConsentManaged, GrantedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("WriteEnrolmentGrant: %v", err)
	}
	if withBudget {
		// The document is SIGNED and its key PINNED on a rail, so the cold
		// cache restore this fixture feeds (orgclient.LoadPersistedBudget)
		// verifies it the way a real enrolled node's does. Saving an unsigned
		// body would leave every launch in the "managed, no verified budget"
		// state — B-625 — and the fixture could then only ever exercise the
		// fail-closed half of the boundary.
		body := orgcontract.BudgetPolicyBody{
			Version: 1, IssuedAt: now.Format(time.RFC3339),
			Caps: []orgcontract.BudgetPolicyCap{{
				Period:      orgcontract.BudgetPolicyPeriodCalendarMonth,
				Timezone:    "UTC",
				CapTokens:   managedBudgetLaunchFixtureCapTokens,
				Enforcement: orgcontract.BudgetPolicyEnforcementHard,
			}},
		}
		identity, active, identityErr := orgclient.CurrentBudgetIdentity(ctx, st)
		if identityErr != nil || !active {
			t.Fatalf("current budget identity: active=%v err=%v", active, identityErr)
		}
		pub, priv, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatalf("generate org signing key: %v", keyErr)
		}
		if err := st.UpsertOrgRoutingPolicy(ctx, store.OrgRoutingPolicyRow{
			Version: 1, Body: "{}", BodyHash: "fixture",
			ServerPubkey: base64.StdEncoding.EncodeToString(pub), ReceivedAt: now,
		}); err != nil {
			t.Fatalf("pin org signing key: %v", err)
		}
		doc, signErr := orgcontract.SignBudgetPolicy(priv, identity.OrgID, identity.UserID, body)
		if signErr != nil {
			t.Fatalf("SignBudgetPolicy: %v", signErr)
		}
		if err := st.SaveOrgBudget(ctx, doc, `"fixture"`, orgcontract.PublicKeyPinHash(pub), identity); err != nil {
			t.Fatalf("SaveOrgBudget: %v", err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatalf("close fixture DB: %v", err)
	}

	cfgPath := filepath.Join(dir, "config.toml")
	guardEnabled := guardMode != "off"
	body := fmt.Sprintf("[observer]\ndb_path = %q\n[guard]\nenabled = %v\nmode = %q\n[guard.budget]\nfrom_org = true\n",
		dbPath, guardEnabled, guardMode)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath, dbPath
}

// exhaustManagedBudgetLaunchBudget records enough verified native usage to put
// the fixture's monthly TOKEN cap over the line. The counters and provenance
// are the ones a managed read accepts (jsonl / approximate, every counter
// present) — usage the cap can actually be measured against, rather than rows
// that would be reported as unavailable accounting and deny for a different
// reason than the one under test.
func exhaustManagedBudgetLaunchBudget(t *testing.T, dbPath, tool string) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open budget launch fixture DB: %v", err)
	}
	defer func() { _ = database.Close() }()
	if _, err := store.New(database).IngestBudgetUsage(ctx, nil, []models.TokenEvent{{
		SessionID: "spent-" + tool, SourceEventID: "spent-1", Tool: tool,
		Model: "fixture-model", ProjectRoot: t.TempDir(), SourceFile: "fixture",
		Timestamp:   time.Now().UTC(),
		InputTokens: managedBudgetLaunchFixtureCapTokens, OutputTokens: 1,
		Source: "jsonl", Reliability: "approximate",
	}}, nil); err != nil {
		t.Fatalf("record over-cap usage: %v", err)
	}
}

func rewriteBudgetLaunchGrant(t *testing.T, dbPath string, mutate func(*store.EnrolmentGrant)) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open budget launch fixture DB: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	enrolment, err := st.LoadEnrolment(ctx)
	if err != nil || enrolment == nil {
		t.Fatalf("load budget launch enrolment: enrolment=%+v err=%v", enrolment, err)
	}
	orgKey := orgclient.OrgKey(enrolment.OrgServerURL, enrolment.OrgID)
	grant, ok, err := st.LoadEnrolmentGrant(ctx, orgKey)
	if err != nil || !ok {
		t.Fatalf("load budget launch grant: ok=%v err=%v", ok, err)
	}
	mutate(&grant)
	if err := st.WriteEnrolmentGrant(ctx, grant); err != nil {
		t.Fatalf("rewrite budget launch grant: %v", err)
	}
}

func rewriteBudgetLaunchEnrolment(t *testing.T, dbPath string, mutate func(*store.Enrolment)) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open budget launch fixture DB: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	enrolment, err := st.LoadEnrolment(ctx)
	if err != nil || enrolment == nil {
		t.Fatalf("load budget launch enrolment: enrolment=%+v err=%v", enrolment, err)
	}
	mutate(enrolment)
	if err := st.WriteEnrolment(ctx, *enrolment); err != nil {
		t.Fatalf("rewrite budget launch enrolment: %v", err)
	}
}
