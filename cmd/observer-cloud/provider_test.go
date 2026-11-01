package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/inference"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// clearProviderEnv blanks every variable the provider wiring reads, so a test
// sees only what it sets.
func clearProviderEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		envInferenceProvider, envAnthropicAPIKey, envAnthropicAPIKeyFile, envAnthropicEffort,
		envAnthropicPromptCache, envFoundryAPIKey,
		"SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE", "SBCI_PROVIDER_RETENTION_POLICY_VERSION",
		"SBCI_PROVIDER_RETENTION_DISCLOSED_BY", "SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE",
		"SBCI_CONTENT_LOGGING_ATTESTED_BY",
	} {
		t.Setenv(v, "")
	}
}

func TestChooseProviderFamily(t *testing.T) {
	cases := []struct {
		val     string
		want    inference.Family
		wantErr bool
	}{
		{"", inference.FamilyAnthropic, false},
		{"anthropic", inference.FamilyAnthropic, false},
		{" Foundry ", inference.FamilyFoundry, false},
		{"azure", "", true},
		{"openai", "", true},
	}
	for _, c := range cases {
		clearProviderEnv(t)
		t.Setenv(envInferenceProvider, c.val)
		got, err := chooseProviderFamily()
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%q: got %q err=%v", c.val, got, err)
		}
	}
}

func TestChooseCredentialsPerFamily(t *testing.T) {
	anthropicRoute := store.RouteInfo{RouteID: "a", Dialect: string(inference.DialectAnthropicMessages)}
	foundryRoute := store.RouteInfo{RouteID: "f", Dialect: string(inference.DialectChatCompletions)}
	ctx := context.Background()

	keyFile := filepath.Join(t.TempDir(), "anthropic.key")
	if err := os.WriteFile(keyFile, []byte("  sk-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name          string
		family        inference.Family
		env           map[string]string
		anthropicKey  string
		anthropicOK   bool
		foundryKey    string
		foundryOK     bool
		wantErrSubstr string
	}{
		{
			name: "anthropic key from env", family: inference.FamilyAnthropic,
			env:          map[string]string{envAnthropicAPIKey: "sk-env", envFoundryAPIKey: "foundry-key"},
			anthropicKey: "sk-env", anthropicOK: true,
		},
		{
			name: "anthropic key from file", family: inference.FamilyAnthropic,
			env:          map[string]string{envAnthropicAPIKeyFile: keyFile},
			anthropicKey: "sk-from-file", anthropicOK: true,
		},
		{
			name: "env beats file", family: inference.FamilyAnthropic,
			env:          map[string]string{envAnthropicAPIKey: "sk-env", envAnthropicAPIKeyFile: keyFile},
			anthropicKey: "sk-env", anthropicOK: true,
		},
		{
			name: "anthropic absent", family: inference.FamilyAnthropic,
			env: map[string]string{envFoundryAPIKey: "foundry-key"},
		},
		{
			name: "missing key file is an error", family: inference.FamilyAnthropic,
			env:           map[string]string{envAnthropicAPIKeyFile: filepath.Join(t.TempDir(), "nope")},
			wantErrSubstr: envAnthropicAPIKeyFile,
		},
		{
			name: "foundry family ignores the anthropic key", family: inference.FamilyFoundry,
			env:        map[string]string{envAnthropicAPIKey: "sk-env", envFoundryAPIKey: "foundry-key"},
			foundryKey: "foundry-key", foundryOK: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearProviderEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			src, err := chooseCredentials(quietLog(), c.family)
			if c.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErrSubstr) {
					t.Fatalf("err = %v, want one naming %s", err, c.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			k, ok, _ := src.ProviderKey(ctx, anthropicRoute)
			if k != c.anthropicKey || ok != c.anthropicOK {
				t.Errorf("anthropic route: %q %v, want %q %v", k, ok, c.anthropicKey, c.anthropicOK)
			}
			k, ok, _ = src.ProviderKey(ctx, foundryRoute)
			if k != c.foundryKey || ok != c.foundryOK {
				t.Errorf("foundry route: %q %v, want %q %v", k, ok, c.foundryKey, c.foundryOK)
			}
		})
	}
}

func TestChooseInferenceProviderWiresOnlyTheFamily(t *testing.T) {
	clearProviderEnv(t)
	r, err := chooseInferenceProvider(quietLog(), inference.FamilyAnthropic)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Supports(inference.DialectAnthropicMessages) || r.Supports(inference.DialectChatCompletions) || r.Supports(inference.DialectResponsesStoreFalse) {
		t.Fatal("anthropic router must serve exactly anthropic_messages")
	}
	r, err = chooseInferenceProvider(quietLog(), inference.FamilyFoundry)
	if err != nil {
		t.Fatal(err)
	}
	if r.Supports(inference.DialectAnthropicMessages) || !r.Supports(inference.DialectChatCompletions) || !r.Supports(inference.DialectResponsesStoreFalse) {
		t.Fatal("foundry router must serve exactly the two foundry dialects")
	}
	t.Setenv(envAnthropicEffort, "max")
	if _, err := chooseInferenceProvider(quietLog(), inference.FamilyAnthropic); err == nil {
		t.Fatal("an unsupported effort must fail startup")
	}
}

func TestChooseAttestorDisclosedOnlyFamily(t *testing.T) {
	ctx := context.Background()
	route := store.RouteInfo{RouteID: "r", Dialect: string(inference.DialectAnthropicMessages)}
	cases := []struct {
		name        string
		env         map[string]string
		wantGate    bool
		wantRefusal string
	}{
		{name: "nothing configured refuses", wantRefusal: "requires the provider_retention_disclosed"},
		{
			name:        "operator-attested ContentLogging does not apply",
			env:         map[string]string{"SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE": "anthropic:messages:claude-haiku-5-5"},
			wantRefusal: "does not apply",
		},
		{
			name: "both modes conflict",
			env: map[string]string{
				"SBCI_CONTENT_LOGGING_ATTESTED_RESOURCE":     "x",
				"SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE": "anthropic:messages:claude-haiku-5-5",
			},
			wantRefusal: "conflicting",
		},
		{
			name: "disclosed mode builds the gate",
			env: map[string]string{
				"SBCI_PROVIDER_RETENTION_DISCLOSED_RESOURCE": "anthropic:messages:claude-haiku-5-5",
				"SBCI_PROVIDER_RETENTION_POLICY_VERSION":     "2",
			},
			wantGate: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearProviderEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			a := chooseAttestor(nil, quietLog(), inference.FamilyAnthropic)
			if c.wantGate {
				if _, ok := a.(*jobs.AttestationGate); !ok {
					t.Fatalf("want *jobs.AttestationGate, got %T", a)
				}
				return
			}
			att, err := a.Attest(ctx, route, time.Now())
			if err != nil || att.Verified || !strings.Contains(att.Reason, c.wantRefusal) {
				t.Fatalf("got %+v err=%v, want a refusal containing %q", att, err, c.wantRefusal)
			}
		})
	}
}

func TestTablePricerUsesThePricingTable(t *testing.T) {
	p := tablePricer()
	route := store.RouteInfo{RouteID: "r", Deployment: "claude-haiku-5-5", Dialect: string(inference.DialectAnthropicMessages)}
	at := time.Now()
	res := inference.Response{Usage: inference.Usage{Input: 1_000_000, Output: 1_000_000, CacheRead: 1_000_000, CacheWrite: 1_000_000}}
	usd, ver, ok := p(route, res, at)
	if !ok {
		t.Fatal("the pricing table must price claude-haiku-5-5")
	}
	row, found := cost.NewTable().LookupAt("claude-haiku-5-5", at)
	if !found {
		t.Fatal("pricing table has no claude-haiku-5-5 row")
	}
	want := cost.Compute(row, cost.TokenBundle{Input: 1_000_000, Output: 1_000_000, CacheRead: 1_000_000, CacheCreation: 1_000_000})
	if usd != want || usd <= 0 {
		t.Fatalf("usd = %v, want %v from the table", usd, want)
	}
	if !strings.HasPrefix(ver, "pricing-table:") {
		t.Fatalf("version = %q", ver)
	}
	if _, _, ok := p(store.RouteInfo{Deployment: "luna"}, res, at); ok {
		t.Fatal("a Foundry deployment label must not price from the table")
	}
}

func TestPlanAnthropicBind(t *testing.T) {
	priced := func(string) (cost.Pricing, bool) { return cost.Pricing{Input: 0.10, Output: 0.50}, true }
	unpriced := func(string) (cost.Pricing, bool) { return cost.Pricing{}, false }
	zero := func(string) (cost.Pricing, bool) { return cost.Pricing{Input: 0, Output: 0.5}, true }
	haiku := store.RouteInfo{RouteID: "session_enrichment.claude-haiku-5-5.v1", Deployment: "claude-haiku-5-5", Dialect: "anthropic_messages"}
	luna := store.RouteInfo{RouteID: "session_enrichment.luna.v1", Deployment: "luna", Dialect: "chat_completions"}

	cases := []struct {
		name     string
		route    store.RouteInfo
		endpoint string
		lookup   func(string) (cost.Pricing, bool)
		wantErr  string
	}{
		{name: "default endpoint", route: haiku, lookup: priced},
		{name: "explicit https origin", route: haiku, endpoint: "https://gw.example.com/", lookup: priced},
		{name: "foundry route refused", route: luna, lookup: priced, wantErr: "not an Anthropic dialect"},
		{name: "unpriced model refused", route: haiku, lookup: unpriced, wantErr: "no row"},
		{name: "zero price refused", route: haiku, lookup: zero, wantErr: "zero or negative"},
		{name: "http refused", route: haiku, endpoint: "http://api.anthropic.com", lookup: priced, wantErr: "https origin"},
		{name: "path refused", route: haiku, endpoint: "https://api.anthropic.com/v1", lookup: priced, wantErr: "https origin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan, err := planAnthropicBind(c.route, c.endpoint, "", c.lookup, "pricing-table:test")
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			b := plan.Binding
			if b.TenantID != "anthropic" || b.SubscriptionID != "default" || b.ARMResourceID != "anthropic:messages:claude-haiku-5-5" ||
				b.APIVersion != "2023-06-01" || b.Endpoint == "" || b.Endpoint != b.EndpointAudience || strings.HasSuffix(b.Endpoint, "/") {
				t.Fatalf("binding = %+v", b)
			}
			if plan.InputPerMTok != 0.10 || plan.OutputPerMTok != 0.50 || plan.PriceVersion != "pricing-table:test" {
				t.Fatalf("price = %+v", plan)
			}
		})
	}
}

func TestRoutesToRetire(t *testing.T) {
	bound := store.RouteInfo{RouteID: "se.haiku", Feature: "session_enrichment", Environment: "production"}
	active := []store.RouteInfo{
		{RouteID: "se.haiku", Feature: "session_enrichment", Environment: "production"},
		{RouteID: "se.luna", Feature: "session_enrichment", Environment: "production"},
		{RouteID: "se.sol", Feature: "session_enrichment", Environment: "production"},
		{RouteID: "se.prove", Feature: "session_enrichment", Environment: "nonproduction"},
		{RouteID: "other.x", Feature: "other", Environment: "production"},
	}
	got := routesToRetire(bound, active)
	if strings.Join(got, ",") != "se.luna,se.sol" {
		t.Fatalf("retire = %v, want [se.luna se.sol] (never the bound route, another environment or another feature)", got)
	}
	if got := routesToRetire(bound, active[:1]); len(got) != 0 {
		t.Fatalf("retire with only the bound route active = %v, want none", got)
	}
}
