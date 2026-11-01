package integration

import (
	"slices"
	"testing"
)

// TestEvaluateRouteGateTable pins the ordered gate table, one case per row
// plus the precedence between rows.
func TestEvaluateRouteGateTable(t *testing.T) {
	byok := &RouteGate{
		CredentialEnv:  []string{"K1", "K2"},
		ModelEnv:       []string{"M1"},
		ModelArguments: []string{"--model"},
	}
	keyOnly := &RouteGate{CredentialEnv: []string{"K1"}}
	cases := []struct {
		name string
		gate *RouteGate
		in   RouteGateInput
		want RouteGateOutcome
	}{
		{"nil gate always routes", nil, RouteGateInput{}, RouteGateRouted},
		{"row 1: own endpoint wins over everything", byok, RouteGateInput{OwnEndpoint: true, CredentialPresent: true, ModelPresent: true}, RouteGateOwnEndpoint},
		{"row 2: no credential launches unrouted", byok, RouteGateInput{}, RouteGateNoCredential},
		{"row 2: no credential even with a model", byok, RouteGateInput{ModelPresent: true}, RouteGateNoCredential},
		{"row 3: foreign provider type launches unrouted", byok, RouteGateInput{CredentialPresent: true, ModelPresent: true, ForeignProvider: true}, RouteGateForeignProvider},
		{"row 3: foreign provider wins over a missing model", byok, RouteGateInput{CredentialPresent: true, ForeignProvider: true}, RouteGateForeignProvider},
		{"row 2 before row 3: no credential with a foreign type", byok, RouteGateInput{ForeignProvider: true}, RouteGateNoCredential},
		{"row 4: credential without model is refused", byok, RouteGateInput{CredentialPresent: true}, RouteGateModelRequired},
		{"row 5 (CLI-6): a saved sign-in choice routes with its caveat", keyOnly, RouteGateInput{CredentialPresent: true, AuthPinned: true}, RouteGateRoutedAuthPinned},
		{"row 2 before row 5: no credential with a saved sign-in", keyOnly, RouteGateInput{AuthPinned: true}, RouteGateNoCredential},
		{"row 6: credential and model route", byok, RouteGateInput{CredentialPresent: true, ModelPresent: true}, RouteGateRouted},
		{"a lane needing no model routes on the credential", keyOnly, RouteGateInput{CredentialPresent: true}, RouteGateRouted},
	}
	for _, tc := range cases {
		if got := EvaluateRouteGate(tc.gate, tc.in); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func lookupFrom(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// TestRouteGateProviderType pins the provider-type probe (pass-2 review
// C156-19): unset, empty and a routable type (any case) are not foreign;
// any other value, in the env var or the argv key, is.
func TestRouteGateProviderType(t *testing.T) {
	g := RouteGate{
		ProviderTypeEnv:       "PT",
		RoutableProviderTypes: []string{"openai"},
		ProviderTypeArguments: []string{"--provider-type"},
	}
	cases := []struct {
		name string
		env  map[string]string
		args []string
		want bool
	}{
		{"unset", map[string]string{}, nil, false},
		{"empty", map[string]string{"PT": " "}, nil, false},
		{"routable", map[string]string{"PT": "openai"}, nil, false},
		{"routable any case", map[string]string{"PT": "OpenAI"}, nil, false},
		{"anthropic", map[string]string{"PT": "anthropic"}, nil, true},
		{"azure", map[string]string{"PT": "azure"}, nil, true},
		{"argv separate value", map[string]string{}, []string{"--provider-type", "anthropic"}, true},
		{"argv equals form", map[string]string{}, []string{"--provider-type=azure"}, true},
		{"argv routable", map[string]string{}, []string{"--provider-type", "openai"}, false},
		{"argv after -- is data", map[string]string{}, []string{"--", "--provider-type", "anthropic"}, false},
		{"routable env, foreign argv", map[string]string{"PT": "openai"}, []string{"--provider-type=anthropic"}, true},
	}
	for _, tc := range cases {
		if got := g.ProviderTypeForeign(lookupFrom(tc.env), tc.args); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	if (RouteGate{}).ProviderTypeForeign(lookupFrom(map[string]string{"PT": "x"}), nil) {
		t.Error("a gate with no ProviderTypeEnv reported a foreign type")
	}
}

// TestRouteGatePresence pins the presence-only probes: an empty value is not
// "set", a model argument needs a value, and argv after "--" is ignored.
func TestRouteGatePresence(t *testing.T) {
	g := RouteGate{
		CredentialEnv:  []string{"K1", "K2"},
		ModelEnv:       []string{"M1"},
		ModelArguments: []string{"--model"},
	}
	credCases := []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{}, false},
		{map[string]string{"K1": ""}, false},
		{map[string]string{"K1": "  "}, false},
		{map[string]string{"K2": "x"}, true},
		{map[string]string{"OTHER": "x"}, false},
	}
	for _, tc := range credCases {
		if got := g.CredentialPresent(lookupFrom(tc.env)); got != tc.want {
			t.Errorf("CredentialPresent(%v) = %v, want %v", tc.env, got, tc.want)
		}
	}
	modelCases := []struct {
		name     string
		env      map[string]string
		args     []string
		launcher string
		want     bool
	}{
		{"nothing", nil, nil, "", false},
		{"launcher flag", nil, nil, "gpt-5", true},
		{"model env", map[string]string{"M1": "gpt-5"}, nil, "", true},
		{"empty model env", map[string]string{"M1": ""}, nil, "", false},
		{"argv space form", nil, []string{"--model", "gpt-5"}, "", true},
		{"argv equals form", nil, []string{"--model=gpt-5"}, "", true},
		{"argv dangling key", nil, []string{"--model"}, "", false},
		{"argv empty equals", nil, []string{"--model="}, "", false},
		{"argv after --", nil, []string{"--", "--model", "gpt-5"}, "", false},
	}
	for _, tc := range modelCases {
		if got := g.ModelPresent(lookupFrom(tc.env), tc.args, tc.launcher); got != tc.want {
			t.Errorf("ModelPresent %s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestGatedRoutesAreWellFormed: a gate is a property of a LAUNCHER route (the
// only kind decided per launch), names a credential, forwards every name it
// reads across the attach socket (credentials through AuthEnv), and says
// what the product uses instead.
func TestGatedRoutesAreWellFormed(t *testing.T) {
	gated := 0
	for _, c := range Capabilities() {
		if c.Proxy == nil || c.Proxy.Gate == nil {
			continue
		}
		gated++
		g := c.Proxy.Gate
		if c.Proxy.Kind != RouteLauncher {
			t.Errorf("%s: gate on a %s route; only launcher routes are decided per launch", c.Tool, c.Proxy.Kind)
		}
		if len(g.CredentialEnv) == 0 {
			t.Errorf("%s: gate names no credential env", c.Tool)
		}
		if g.UnroutedBecause == "" {
			t.Errorf("%s: gate has no UnroutedBecause text", c.Tool)
		}
		if c.Proxy.PromptScope == "" {
			t.Errorf("%s: a conditional route must say which turns it carries (PromptScope)", c.Tool)
		}
		for _, k := range g.CredentialEnv {
			if !slices.Contains(c.AuthEnv, k) {
				t.Errorf("%s: gate credential %s is not in AuthEnv (attach would hide it from the decision)", c.Tool, k)
			}
		}
		names := c.Proxy.GateEnvNames()
		for _, k := range append(append([]string{}, g.CredentialEnv...), g.ModelEnv...) {
			if !slices.Contains(names, k) {
				t.Errorf("%s: GateEnvNames misses %s", c.Tool, k)
			}
		}
		if !slices.Contains(names, c.Proxy.EnvVar) {
			t.Errorf("%s: GateEnvNames misses the route's own %s", c.Tool, c.Proxy.EnvVar)
		}
	}
	if gated == 0 {
		t.Fatal("no gated route in the registry; copilot-cli's BYOK lane must be gated")
	}
}

// TestCopilotCLIRouteIsGatedOnBYOK pins the grounded row: the BYOK lane is
// conditional on the provider credential and needs a model, so a GitHub
// sign-in launch is never advertised as routed.
func TestCopilotCLIRouteIsGatedOnBYOK(t *testing.T) {
	c, ok := For("copilot-cli")
	if !ok || c.Proxy == nil || c.Proxy.Gate == nil {
		t.Fatal("copilot-cli has no gated proxy route")
	}
	g := c.Proxy.Gate
	if !slices.Equal(g.CredentialEnv, []string{"COPILOT_PROVIDER_API_KEY", "COPILOT_PROVIDER_API_KEY_COMMAND", "COPILOT_PROVIDER_BEARER_TOKEN"}) {
		t.Errorf("CredentialEnv = %v", g.CredentialEnv)
	}
	if !g.RequiresModel() || !slices.Contains(g.ModelEnv, "COPILOT_MODEL") {
		t.Errorf("BYOK needs an explicit model; gate = %+v", g)
	}
	w, ok := WrappedCommandFor("copilot-cli")
	if !ok || !w.RouteConditional {
		t.Errorf("WrappedCommandFor(copilot-cli).RouteConditional = false; the wrapped form must not read as plainly routed")
	}
}

// TestGeminiCLIRouteIsGatedOnAPIKey pins T-345: GOOGLE_GEMINI_BASE_URL is read
// only by Gemini CLI's API-key and gateway auth types (installed 0.62.0 bundle,
// 2026-10-04), so the route applies only with GEMINI_API_KEY present, needs no
// model, and a routed launch carries the caveat for a saved Google/Vertex
// sign-in the gate cannot see.
func TestGeminiCLIRouteIsGatedOnAPIKey(t *testing.T) {
	c, ok := For("gemini-cli")
	if !ok || c.Proxy == nil || c.Proxy.Gate == nil {
		t.Fatal("gemini-cli has no gated proxy route")
	}
	g := c.Proxy.Gate
	if !slices.Equal(g.CredentialEnv, []string{"GEMINI_API_KEY"}) {
		t.Errorf("CredentialEnv = %v", g.CredentialEnv)
	}
	if g.RequiresModel() {
		t.Errorf("the API-key lane needs no explicit model; gate = %+v", g)
	}
	if g.RoutedCaveat == "" {
		t.Error("a routed gemini launch must name the saved sign-in lane it cannot see")
	}
	if got := EvaluateRouteGate(g, RouteGateInput{}); got != RouteGateNoCredential {
		t.Errorf("no key: %s, want %s", got, RouteGateNoCredential)
	}
	if got := EvaluateRouteGate(g, RouteGateInput{CredentialPresent: true}); got != RouteGateRouted {
		t.Errorf("key: %s, want %s", got, RouteGateRouted)
	}
	w, ok := WrappedCommandFor("gemini-cli")
	if !ok || !w.RouteConditional {
		t.Error("WrappedCommandFor(gemini-cli).RouteConditional = false; the wrapped form must not read as plainly routed")
	}
}
