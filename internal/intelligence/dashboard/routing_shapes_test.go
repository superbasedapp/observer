package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// The routing shape editors (routing_shapes.go): the Settings > Routing cards
// replace one [routing] shape each through a Set* field of the routing
// section body. These pin, for every shape: the dry run previews and writes
// nothing, the real save round-trips through the file, an absent (or null)
// field keeps the file's value, every refusal row answers 400 with the file
// untouched, key_pool is never touched, and the RulesTOML escape hatch keeps
// its behaviour beside them.

// routingShapesSeed carries every shape the cards edit, the secret key pool
// none of them may touch, and a custom rule plus a privacy rule that both
// name the "secrets" path class. policy = "custom" so the seed loads in a
// build without proxy.routing too.
const routingShapesSeed = `[observer]
log_level = "info"

[routing]
enabled = true
mode = "advise"
policy = "custom"

[routing.tiers]
"claude-opus-4-8" = "opus-class"

[routing.path_classes]
secrets = ["**/vault/**", "**/*.pem"]

[routing.key_pool]
anthropic = ["sk-ant-prior-1", "sk-ant-prior-2"]

[routing.reliability.fallbacks]
"claude-opus-4-8" = ["claude-sonnet-4-6"]

[[routing.local_upstreams]]
name = "ollama"
base_url = "http://localhost:11434/v1"
models = ["qwen3:32b"]

[[routing.rules]]
name = "secrets-deny"
when.path_class = "secrets"
action.deny_providers = ["openai"]
action.reason = "privacy_hold"

[[routing.budget.scopes]]
scope = "global"
limit_usd = 100.0
window = "month"

[[routing.privacy.rules]]
path_class = "secrets"
local_only = true
`

func newRoutingShapesServer(t *testing.T) (*Server, string) {
	t.Helper()
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(routingShapesSeed), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	return server, cfgPath
}

// routingShapesBody builds the body a shape card sends: the GET /api/config
// Routing payload spread whole, plus the card's field(s).
func routingShapesBody(t *testing.T, s *Server, extra map[string]any) string {
	t.Helper()
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /api/config: %d %s", rr.Code, rr.Body.String())
	}
	var got struct {
		Config struct {
			Routing map[string]any `json:"Routing"`
		} `json:"config"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Config.Routing == nil {
		t.Fatal("GET /api/config carries no Routing section")
	}
	for k, v := range extra {
		got.Config.Routing[k] = v
	}
	b, err := json.Marshal(got.Config.Routing)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func reloadRoutingShapes(t *testing.T, cfgPath string) config.RoutingConfig {
	t.Helper()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	return cfg.Routing
}

// routingShapeViews keys every shape (and the two neighbours no card may
// change: custom rules and the key pool) by its Set* field name.
func routingShapeViews(rc config.RoutingConfig) map[string]any {
	return map[string]any{
		"SetTiers":          rc.Tiers,
		"SetPathClasses":    rc.PathClasses,
		"SetBudgetScopes":   rc.Budget.Scopes,
		"SetPrivacyRules":   rc.Privacy.Rules,
		"SetLocalUpstreams": rc.LocalUpstreams,
		"SetFallbacks":      rc.Reliability.Fallbacks,
		"Rules":             rc.Rules,
		"KeyPool":           rc.KeyPool,
	}
}

func TestRoutingShapes_RoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		value any
		want  any
	}{
		{
			name: "tiers_replace", field: "SetTiers",
			value: map[string]string{"claude-haiku-4-5": "haiku-class", "gpt-5": "sonnet-class"},
			want:  map[string]string{"claude-haiku-4-5": "haiku-class", "gpt-5": "sonnet-class"},
		},
		{name: "tiers_clear", field: "SetTiers", value: map[string]string{}, want: map[string]string(nil)},
		{
			name: "path_classes_replace", field: "SetPathClasses",
			value: map[string][]string{"secrets": {"**/vault/**", "**/*.pem", "**/*.key"}, "infra": {"infra/**"}},
			want:  map[string][]string{"secrets": {"**/vault/**", "**/*.pem", "**/*.key"}, "infra": {"infra/**"}},
		},
		{
			name: "budget_scopes_replace", field: "SetBudgetScopes",
			value: []config.RoutingBudgetScopeConfig{
				{Scope: "project:alpha", LimitUSD: 50, Window: "week", Bands: []float64{0.6, 0.9}, Exhausted: "degrade_all"},
				{Scope: "tier:opus-class", LimitUSD: 20, Window: "day"},
			},
			want: []config.RoutingBudgetScopeConfig{
				{Scope: "project:alpha", LimitUSD: 50, Window: "week", Bands: []float64{0.6, 0.9}, Exhausted: "degrade_all"},
				{Scope: "tier:opus-class", LimitUSD: 20, Window: "day"},
			},
		},
		{
			name: "budget_scopes_clear", field: "SetBudgetScopes",
			value: []config.RoutingBudgetScopeConfig{}, want: []config.RoutingBudgetScopeConfig(nil),
		},
		{
			name: "privacy_rules_replace", field: "SetPrivacyRules",
			value: []config.RoutingPrivacyRuleConfig{
				{Project: "alpha", LocalOnly: true},
				{PathClass: "secrets", DenyProviders: []string{"*"}, AllowProviders: []string{"local"}},
			},
			want: []config.RoutingPrivacyRuleConfig{
				{Project: "alpha", LocalOnly: true},
				{PathClass: "secrets", DenyProviders: []string{"*"}, AllowProviders: []string{"local"}},
			},
		},
		{
			name: "local_upstreams_replace", field: "SetLocalUpstreams",
			value: []config.RoutingLocalUpstreamConfig{
				{Name: "lmstudio", BaseURL: "http://127.0.0.1:1234/v1", Models: []string{"qwen3-coder"}},
				{Name: "gpu-box", BaseURL: "https://gpu.example.test/v1", Models: []string{"llama-4", "qwen3:32b"}},
			},
			want: []config.RoutingLocalUpstreamConfig{
				{Name: "lmstudio", BaseURL: "http://127.0.0.1:1234/v1", Models: []string{"qwen3-coder"}},
				{Name: "gpu-box", BaseURL: "https://gpu.example.test/v1", Models: []string{"llama-4", "qwen3:32b"}},
			},
		},
		{
			name: "local_upstreams_clear", field: "SetLocalUpstreams",
			value: []config.RoutingLocalUpstreamConfig{}, want: []config.RoutingLocalUpstreamConfig(nil),
		},
		{
			name: "fallbacks_replace", field: "SetFallbacks",
			value: map[string][]string{
				"claude-opus-4-8": {"claude-sonnet-4-6", "claude-haiku-4-5"},
				"sonnet-class":    {"claude-haiku-4-5"},
			},
			want: map[string][]string{
				"claude-opus-4-8": {"claude-sonnet-4-6", "claude-haiku-4-5"},
				"sonnet-class":    {"claude-haiku-4-5"},
			},
		},
		{name: "fallbacks_clear", field: "SetFallbacks", value: map[string][]string{}, want: map[string][]string(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cfgPath := newRoutingShapesServer(t)
			seed := routingShapeViews(reloadRoutingShapes(t, cfgPath))
			body := routingShapesBody(t, s, map[string]any{tc.field: tc.value})

			// Dry run: every check, the diff, nothing written.
			before, _ := os.ReadFile(cfgPath)
			rr := putSection(t, s, "routing?dry_run=1", body, false)
			if rr.Code != http.StatusOK {
				t.Fatalf("dry run: %d %s", rr.Code, rr.Body.String())
			}
			m := decodeMap(t, rr)
			if m["dry_run"] != true || m["would_write"] != true {
				t.Fatalf("dry run flags: %v", m)
			}
			if diff, _ := m["diff"].(string); strings.TrimSpace(diff) == "" {
				t.Fatalf("dry run must carry the diff of the write: %v", m)
			}
			if after, _ := os.ReadFile(cfgPath); !bytes.Equal(before, after) {
				t.Fatal("a dry run must not touch the file")
			}

			// Real save, then the file says exactly the replacement.
			rr = putSection(t, s, "routing", body, true)
			if rr.Code != http.StatusOK {
				t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
			}
			got := routingShapeViews(reloadRoutingShapes(t, cfgPath))
			if !reflect.DeepEqual(got[tc.field], tc.want) {
				t.Errorf("%s after save = %#v, want %#v", tc.field, got[tc.field], tc.want)
			}
			for k, v := range got {
				if k != tc.field && !reflect.DeepEqual(v, seed[k]) {
					t.Errorf("%s save changed %s: %#v, was %#v", tc.field, k, v, seed[k])
				}
			}
		})
	}
}

// An absent or null Set* field keeps the shape, even when the body's Go-name
// fields (the GET payload spread, as the section form sends it) are zeroed,
// and a body that names the key pool in any form never reaches it.
func TestRoutingShapes_AbsentNullAndKeyPoolPreserve(t *testing.T) {
	s, cfgPath := newRoutingShapesServer(t)
	seed := routingShapeViews(reloadRoutingShapes(t, cfgPath))

	body := routingShapesBody(t, s, map[string]any{
		"DecisionLogRetentionDays": 200, // a knob change, so the save writes
		"Tiers":                    map[string]string{},
		"PathClasses":              map[string][]string{},
		"Budget":                   map[string]any{"Scopes": []any{}},
		"Privacy":                  map[string]any{"Rules": []any{}},
		"LocalUpstreams":           []any{},
		"Rules":                    []any{},
		"KeyPool":                  map[string][]string{"anthropic": {"sk-ant-new-1"}},
		"SetKeyPool":               map[string][]string{"anthropic": {"sk-ant-new-2"}},
		"SetTiers":                 nil,
		"SetFallbacks":             nil,
	})
	rr := putSection(t, s, "routing", body, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("knob save: %d %s", rr.Code, rr.Body.String())
	}
	rc := reloadRoutingShapes(t, cfgPath)
	if rc.DecisionLogRetentionDays != 200 {
		t.Fatalf("knob not saved: %d", rc.DecisionLogRetentionDays)
	}
	for k, v := range routingShapeViews(rc) {
		if !reflect.DeepEqual(v, seed[k]) {
			t.Errorf("%s changed without its Set* field: %#v, was %#v", k, v, seed[k])
		}
	}

	// Every Set* field at once, with the key pool named both ways again: the
	// pool stays exactly as the file had it.
	body = routingShapesBody(t, s, map[string]any{
		"KeyPool":           map[string][]string{"anthropic": {"sk-ant-new-3"}},
		"SetKeyPool":        map[string][]string{"openai": {"sk-new-4"}},
		"SetTiers":          map[string]string{"gpt-5": "sonnet-class"},
		"SetPathClasses":    map[string][]string{"secrets": {"**/*.pem"}},
		"SetBudgetScopes":   []config.RoutingBudgetScopeConfig{{Scope: "global", LimitUSD: 10, Window: "day"}},
		"SetPrivacyRules":   []config.RoutingPrivacyRuleConfig{{Project: "alpha", LocalOnly: true}},
		"SetLocalUpstreams": []config.RoutingLocalUpstreamConfig{{Name: "lm", BaseURL: "http://localhost:1234/v1", Models: []string{"m1"}}},
		"SetFallbacks":      map[string][]string{"gpt-5": {"gpt-5-mini"}},
	})
	rr = putSection(t, s, "routing", body, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("all-shapes save: %d %s", rr.Code, rr.Body.String())
	}
	rc = reloadRoutingShapes(t, cfgPath)
	if !reflect.DeepEqual(rc.KeyPool, seed["KeyPool"]) {
		t.Errorf("key_pool changed through a shape save: %#v, was %#v", rc.KeyPool, seed["KeyPool"])
	}
	if rc.Tiers["gpt-5"] != "sonnet-class" || len(rc.LocalUpstreams) != 1 || rc.LocalUpstreams[0].Name != "lm" {
		t.Errorf("all-shapes save did not land: tiers=%v upstreams=%v", rc.Tiers, rc.LocalUpstreams)
	}
}

func TestRoutingShapes_Refusals(t *testing.T) {
	type up = config.RoutingLocalUpstreamConfig
	for _, tc := range []struct {
		name  string
		field string
		value any
		want  []string // substrings of the 400 body
		never string   // a substring the 400 body must not echo
	}{
		{name: "tiers_unknown_tier", field: "SetTiers", value: map[string]string{"gpt-5": "super-class"}, want: []string{"Tier overrides", `tier "super-class" is not one of`}},
		{name: "tiers_empty_model", field: "SetTiers", value: map[string]string{"": "haiku-class"}, want: []string{"a model is empty"}},
		{name: "tiers_spaced_model", field: "SetTiers", value: map[string]string{" gpt-5": "haiku-class"}, want: []string{"spaces at the start or end"}},
		{name: "tiers_not_a_table", field: "SetTiers", value: []string{"gpt-5"}, want: []string{"Tier overrides:"}},
		{name: "path_class_no_patterns", field: "SetPathClasses", value: map[string][]string{"secrets": {"**/*.pem"}, "empty": {}}, want: []string{`class "empty" has no path patterns`}},
		{name: "path_class_bad_glob", field: "SetPathClasses", value: map[string][]string{"secrets": {"[unclosed"}}, want: []string{"is not a valid glob"}},
		{name: "path_class_empty_pattern", field: "SetPathClasses", value: map[string][]string{"secrets": {""}}, want: []string{"a pattern is empty"}},
		{
			name: "path_class_still_used", field: "SetPathClasses", value: map[string][]string{},
			want: []string{"still used by privacy rule 1", `still used by custom rule "secrets-deny"`},
		},
		{name: "budget_limit_zero", field: "SetBudgetScopes", value: []config.RoutingBudgetScopeConfig{{Scope: "global", Window: "month"}}, want: []string{"limit_usd"}},
		{name: "budget_bad_window", field: "SetBudgetScopes", value: []config.RoutingBudgetScopeConfig{{Scope: "global", LimitUSD: 5, Window: "year"}}, want: []string{"window"}},
		{name: "budget_bad_scope", field: "SetBudgetScopes", value: []config.RoutingBudgetScopeConfig{{Scope: "team:x", LimitUSD: 5, Window: "day"}}, want: []string{"scope"}},
		{name: "budget_bands_descending", field: "SetBudgetScopes", value: []config.RoutingBudgetScopeConfig{{Scope: "global", LimitUSD: 5, Window: "day", Bands: []float64{0.9, 0.5}}}, want: []string{"ascending"}},
		{name: "budget_bad_exhausted", field: "SetBudgetScopes", value: []config.RoutingBudgetScopeConfig{{Scope: "global", LimitUSD: 5, Window: "day", Exhausted: "explode"}}, want: []string{"exhausted"}},
		{name: "budget_unknown_tier", field: "SetBudgetScopes", value: []config.RoutingBudgetScopeConfig{{Scope: "tier:mega-class", LimitUSD: 5, Window: "day"}}, want: []string{`tier "mega-class" is not one of`}},
		{name: "budget_spaced_target", field: "SetBudgetScopes", value: []config.RoutingBudgetScopeConfig{{Scope: "project: alpha", LimitUSD: 5, Window: "day"}}, want: []string{"spaces at the start or end"}},
		{
			name: "budget_duplicate", field: "SetBudgetScopes",
			value: []config.RoutingBudgetScopeConfig{{Scope: "global", LimitUSD: 5, Window: "day"}, {Scope: "global", LimitUSD: 9, Window: "day"}},
			want:  []string{"row 2 repeats row 1"},
		},
		{name: "budget_unknown_field", field: "SetBudgetScopes", value: json.RawMessage(`[{"Scope":"global","Limit":5,"Window":"day"}]`), want: []string{"Budget scopes", "unknown field"}},
		{name: "privacy_no_selector", field: "SetPrivacyRules", value: []config.RoutingPrivacyRuleConfig{{LocalOnly: true}}, want: []string{"needs a selector"}},
		{name: "privacy_no_effect", field: "SetPrivacyRules", value: []config.RoutingPrivacyRuleConfig{{Project: "alpha"}}, want: []string{"needs an effect"}},
		{name: "privacy_undefined_class", field: "SetPrivacyRules", value: []config.RoutingPrivacyRuleConfig{{PathClass: "nope", LocalOnly: true}}, want: []string{`path class "nope" is not defined`}},
		{name: "privacy_uppercase_provider", field: "SetPrivacyRules", value: []config.RoutingPrivacyRuleConfig{{Project: "alpha", DenyProviders: []string{"OpenAI"}}}, want: []string{"lowercase"}},
		{name: "privacy_star_in_allow", field: "SetPrivacyRules", value: []config.RoutingPrivacyRuleConfig{{Project: "alpha", DenyProviders: []string{"openai"}, AllowProviders: []string{"*"}}}, want: []string{"only works in the deny list"}},
		{name: "privacy_empty_provider", field: "SetPrivacyRules", value: []config.RoutingPrivacyRuleConfig{{Project: "alpha", DenyProviders: []string{""}}}, want: []string{"a provider name is empty"}},
		{name: "upstream_no_name", field: "SetLocalUpstreams", value: []up{{BaseURL: "http://localhost:1/v1", Models: []string{"m"}}}, want: []string{"a name is empty"}},
		{
			name: "upstream_name_twice", field: "SetLocalUpstreams",
			value: []up{{Name: "a", BaseURL: "http://localhost:1/v1", Models: []string{"m1"}}, {Name: "a", BaseURL: "http://localhost:2/v1", Models: []string{"m2"}}},
			want:  []string{`"a" is listed twice`},
		},
		{name: "upstream_ftp", field: "SetLocalUpstreams", value: []up{{Name: "a", BaseURL: "ftp://localhost/v1", Models: []string{"m"}}}, want: []string{"must start with http:// or https://"}},
		{name: "upstream_no_host", field: "SetLocalUpstreams", value: []up{{Name: "a", BaseURL: "http:///v1", Models: []string{"m"}}}, want: []string{"names no host"}},
		{
			name: "upstream_userinfo", field: "SetLocalUpstreams",
			value: []up{{Name: "a", BaseURL: "http://user:hunter2@localhost:11434/v1", Models: []string{"m"}}},
			want:  []string{"user name or password"}, never: "hunter2",
		},
		{
			name: "upstream_query", field: "SetLocalUpstreams",
			value: []up{{Name: "a", BaseURL: "http://localhost:11434/v1?key=abc123", Models: []string{"m"}}},
			want:  []string{"?query or #fragment"}, never: "abc123",
		},
		{name: "upstream_no_models", field: "SetLocalUpstreams", value: []up{{Name: "a", BaseURL: "http://localhost:1/v1"}}, want: []string{"at least one model is required"}},
		{
			name: "upstream_model_twice", field: "SetLocalUpstreams",
			value: []up{{Name: "a", BaseURL: "http://localhost:1/v1", Models: []string{"m"}}, {Name: "b", BaseURL: "http://localhost:2/v1", Models: []string{"m"}}},
			want:  []string{`model "m" is served by both "a" and "b"`},
		},
		{name: "fallback_empty_chain", field: "SetFallbacks", value: map[string][]string{"gpt-5": {}}, want: []string{"has no fallback models"}},
		{name: "fallback_self", field: "SetFallbacks", value: map[string][]string{"gpt-5": {"gpt-5"}}, want: []string{"falls back to itself"}},
		{name: "fallback_twice", field: "SetFallbacks", value: map[string][]string{"gpt-5": {"gpt-5-mini", "gpt-5-mini"}}, want: []string{`lists "gpt-5-mini" twice`}},
		{name: "fallback_empty_from", field: "SetFallbacks", value: map[string][]string{"": {"gpt-5-mini"}}, want: []string{"a model or tier is empty"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cfgPath := newRoutingShapesServer(t)
			before, _ := os.ReadFile(cfgPath)
			body := routingShapesBody(t, s, map[string]any{tc.field: tc.value})
			for _, q := range []string{"routing?dry_run=1", "routing"} {
				rr := putSection(t, s, q, body, true)
				if rr.Code != http.StatusBadRequest {
					t.Fatalf("%s: code = %d, want 400 (%s)", q, rr.Code, rr.Body.String())
				}
				got := rr.Body.String()
				for _, w := range tc.want {
					if !strings.Contains(got, w) {
						t.Errorf("%s: refusal %q does not say %q", q, got, w)
					}
				}
				if !strings.Contains(got, "file untouched") {
					t.Errorf("%s: refusal must say the file is untouched: %q", q, got)
				}
				if tc.never != "" && strings.Contains(got, tc.never) {
					t.Errorf("%s: refusal echoes %q: %q", q, tc.never, got)
				}
			}
			if after, _ := os.ReadFile(cfgPath); !bytes.Equal(before, after) {
				t.Fatal("a refused shape save mutated the file")
			}
		})
	}
}

// Only a model a local upstream serves may sit in the local tier: the
// privacy basis treats that tier as this machine, so a cloud model there
// would pass a local-only privacy rule.
func TestRoutingShapes_LocalTierPins(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  map[string]any
		code  int
		want  string
		check func(rc config.RoutingConfig) bool
	}{
		{
			name: "cloud_model_to_local_refused",
			edit: map[string]any{"SetTiers": map[string]string{"qwen3:32b": "local", "gpt-5": "local"}},
			code: http.StatusBadRequest, want: `model "gpt-5": only a model a local upstream serves can be in the local tier`,
		},
		{
			name: "served_model_to_local_saved",
			edit: map[string]any{"SetTiers": map[string]string{"qwen3:32b": "local", "gpt-5": "haiku-class"}},
			code: http.StatusOK,
			check: func(rc config.RoutingConfig) bool {
				return rc.Tiers["qwen3:32b"] == "local" && rc.Tiers["gpt-5"] == "haiku-class"
			},
		},
		{
			name: "removing_the_endpoint_of_a_local_pin_refused",
			edit: map[string]any{"SetLocalUpstreams": []config.RoutingLocalUpstreamConfig{}},
			code: http.StatusBadRequest, want: `model "qwen3:32b" is set to the local tier under Tier overrides`,
		},
		{
			name: "moving_the_pinned_model_to_another_endpoint_saved",
			edit: map[string]any{"SetLocalUpstreams": []config.RoutingLocalUpstreamConfig{
				{Name: "lmstudio", BaseURL: "http://127.0.0.1:1234/v1", Models: []string{"qwen3:32b"}},
			}},
			code: http.StatusOK,
			check: func(rc config.RoutingConfig) bool {
				return len(rc.LocalUpstreams) == 1 && rc.LocalUpstreams[0].Name == "lmstudio"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, cfgPath := newRoutingShapesServer(t)
			seed := strings.Replace(routingShapesSeed, `"claude-opus-4-8" = "opus-class"`,
				"\"claude-opus-4-8\" = \"opus-class\"\n\"qwen3:32b\" = \"local\"", 1)
			if err := os.WriteFile(cfgPath, []byte(seed), 0o644); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(cfgPath)
			rr := putSection(t, s, "routing", routingShapesBody(t, s, tc.edit), true)
			if rr.Code != tc.code {
				t.Fatalf("code = %d, want %d (%s)", rr.Code, tc.code, rr.Body.String())
			}
			if tc.want != "" && !strings.Contains(rr.Body.String(), tc.want) {
				t.Errorf("refusal %q does not say %q", rr.Body.String(), tc.want)
			}
			if tc.code != http.StatusOK {
				if after, _ := os.ReadFile(cfgPath); !bytes.Equal(before, after) {
					t.Fatal("a refused save mutated the file")
				}
				return
			}
			if rc := reloadRoutingShapes(t, cfgPath); !tc.check(rc) {
				t.Errorf("saved section = %+v", rc)
			}
		})
	}
}

// The RulesTOML escape hatch keeps its behaviour beside the Set* fields:
// both in one body apply, and the custom rules gate still runs.
func TestRoutingShapes_RulesTOMLUnchanged(t *testing.T) {
	if testOmitted["proxy.routing"] {
		t.Skip("proxy.routing is compiled out: every rules fragment is refused")
	}
	s, cfgPath := newRoutingShapesServer(t)

	// A refused fragment refuses the whole body, shapes included.
	bad := "[[routing.rules]]\nname = \"r\"\nwhen.turn_kind = \"read_only\"\naction.route_to_tier = \"super-class\"\n"
	before, _ := os.ReadFile(cfgPath)
	rr := putSection(t, s, "routing", routingShapesBody(t, s, map[string]any{
		"SetTiers": map[string]string{"gpt-5": "sonnet-class"}, "RulesTOML": bad,
	}), true)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "routing rules refused") {
		t.Fatalf("bad fragment beside a shape: %d %s", rr.Code, rr.Body.String())
	}
	if after, _ := os.ReadFile(cfgPath); !bytes.Equal(before, after) {
		t.Fatal("a refused rules fragment mutated the file")
	}

	// An empty fragment clears the rules; the tier override lands with it.
	rr = putSection(t, s, "routing", routingShapesBody(t, s, map[string]any{
		"SetTiers": map[string]string{"gpt-5": "sonnet-class"}, "RulesTOML": "",
	}), true)
	if rr.Code != http.StatusOK {
		t.Fatalf("clear rules + tiers: %d %s", rr.Code, rr.Body.String())
	}
	rc := reloadRoutingShapes(t, cfgPath)
	if len(rc.Rules) != 0 || rc.Tiers["gpt-5"] != "sonnet-class" {
		t.Errorf("rules=%v tiers=%v", rc.Rules, rc.Tiers)
	}
}

// newRoutingLintErrors blocks a lint error the save introduces and never one
// the file already carried.
func TestNewRoutingLintErrors(t *testing.T) {
	if testOmitted["proxy.routing"] {
		t.Skip("proxy.routing is compiled out: no compiler lint")
	}
	rule := config.RoutingRuleConfig{Name: "secrets-deny"}
	rule.When.PathClass = "secrets"
	rule.Action.DenyProviders = []string{"openai"}
	withClass := config.RoutingConfig{
		Mode: "advise", Policy: "custom",
		PathClasses: map[string][]string{"secrets": {"**/*.pem"}},
		Rules:       []config.RoutingRuleConfig{rule},
	}
	withoutClass := withClass
	withoutClass.PathClasses = nil

	for _, tc := range []struct {
		name       string
		base, next config.RoutingConfig
		wantErrors int
	}{
		{name: "clean_stays_clean", base: withClass, next: withClass, wantErrors: 0},
		{name: "introduced_dangling_class", base: withClass, next: withoutClass, wantErrors: 1},
		{name: "already_dangling_is_not_new", base: withoutClass, next: withoutClass, wantErrors: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := newRoutingLintErrors(tc.base, tc.next)
			if len(got) != tc.wantErrors {
				t.Fatalf("newRoutingLintErrors = %v, want %d error(s)", got, tc.wantErrors)
			}
			for _, p := range got {
				if !strings.Contains(p, "path_class_ref") {
					t.Errorf("unexpected finding %q", p)
				}
			}
		})
	}
}

// A lint error the file already carries does not block an unrelated shape
// save (the daemon starts with it; it is the rules editor's to fix).
func TestRoutingShapes_PreexistingLintDoesNotBlock(t *testing.T) {
	s, cfgPath := newRoutingShapesServer(t)
	seed := strings.Replace(routingShapesSeed, "[[routing.rules]]\nname = \"secrets-deny\"\nwhen.path_class = \"secrets\"",
		"[[routing.rules]]\nname = \"secrets-deny\"\nwhen.path_class = \"ghost\"", 1)
	if err := os.WriteFile(cfgPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	rr := putSection(t, s, "routing", routingShapesBody(t, s, map[string]any{
		"SetTiers": map[string]string{"gpt-5": "sonnet-class"},
	}), true)
	if rr.Code != http.StatusOK {
		t.Fatalf("shape save over a pre-existing lint finding: %d %s", rr.Code, rr.Body.String())
	}
	if got := reloadRoutingShapes(t, cfgPath).Tiers["gpt-5"]; got != "sonnet-class" {
		t.Errorf("tier override not saved: %q", got)
	}
}

// routingGlobValid follows the path-class matcher's own forms.
func TestRoutingGlobValid(t *testing.T) {
	for _, tc := range []struct {
		pat  string
		want bool
	}{
		{"**/*.pem", true},
		{"infra/**", true},
		{"**/vault/**", true},
		{"src/*.go", true},
		{"file?.txt", true},
		{"[abc]*.env", true},
		{"[unclosed", false},
		{"**/[", false},
		{"a[]b", false},
	} {
		if got := routingGlobValid(tc.pat); got != tc.want {
			t.Errorf("routingGlobValid(%q) = %v, want %v", tc.pat, got, tc.want)
		}
	}
}
