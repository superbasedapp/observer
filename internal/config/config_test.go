package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsAreValid(t *testing.T) {
	t.Parallel()
	if err := Validate(Default()); err != nil {
		t.Fatalf("Default() failed validation: %v", err)
	}
}

// TestOTelExporterDefaultsAreOff pins the solo-local invariant for the M4
// exporter: a default config leaves [exporter.otel] disabled (so start.go
// starts no exporter goroutine and the daemon makes zero OTLP calls) while the
// non-gating fields carry the documented privacy-preserving defaults.
func TestOTelExporterDefaultsAreOff(t *testing.T) {
	t.Parallel()
	o := Default().Exporter.OTel
	if o.Enabled {
		t.Error("Exporter.OTel.Enabled must default to false (solo-local invariant)")
	}
	if o.EmitPromptContent {
		t.Error("EmitPromptContent must default to false")
	}
	if o.EmitUserEmail {
		t.Error("EmitUserEmail must default to false")
	}
	if o.Endpoint != DefaultOTelEndpoint {
		t.Errorf("Endpoint: got %q want %q", o.Endpoint, DefaultOTelEndpoint)
	}
	if o.PollIntervalSeconds != DefaultOTelPollIntervalSeconds {
		t.Errorf("PollIntervalSeconds: got %d want %d", o.PollIntervalSeconds, DefaultOTelPollIntervalSeconds)
	}
	if o.SemconvStability != DefaultOTelSemconvStability {
		t.Errorf("SemconvStability: got %q want %q", o.SemconvStability, DefaultOTelSemconvStability)
	}
}

// TestDefaultCompressTypesIsJSONLogsCode pins V7-24 (v1.7.23, 2026-06-01).
// The default `compress_types` is restored to ["json","logs","code"]
// after V7-22's temporary {} flip was re-measured on the V7-22 binary
// at n=8 and found to be safe — V7-22's preceding fixes (V7-19 nil-trap
// + V7-21 tools-defs gate) closed enough of the re-marshal pathway that
// per-type compression no longer cascades on the V7-22+ binary.
//
// Empirical headline (n=8 vs n=4 OFF on V7-22 binary):
//
//	OFF (no proxy):                $1.148 / 15.0 turns  CV 7.5%
//	B proxy, compress_types=[]:    $1.118 / 15.5 turns  CV 9.1%  -2.6%
//	B proxy, this default:         $1.069 / 14.9 turns  CV 7.6%  -6.9%
//
// "text" is omitted by choice — TextCompressor head-tail elision is
// the v1.4.38 regression class. "tools" is opt-in (V7-21). Stash is
// opt-in and cache-breaking (V7-24).
//
// Operators MUST set ENABLE_TOOL_SEARCH=true in the launching shell
// for the proxy to be a net win — without it the Claude Code SDK
// eager-inlines MCP schemas (~+21K tokens/turn) under ANTHROPIC_BASE_URL.
//
// See docs/v1.7.23-compression-savings-empirical-2026-06-01.md.
//
// History:
//
//	pre-v1.4.40: ["json","logs"]
//	v1.4.40:     ["json","logs","code"] (CodeCompressor became content-preserving)
//	v1.7.22:     []                     (V7-22 flip — V7-21 binary cascade)
//	v1.7.23:     ["json","logs","code"] (V7-24 — V7-22 binary cascade resolved)
func TestDefaultCompressTypesIsJSONLogsCode(t *testing.T) {
	t.Parallel()
	got := Default().Compression.Conversation.CompressTypes
	want := []string{"json", "logs", "code"}
	if len(got) != len(want) {
		t.Errorf("CompressTypes: got %v, want %v (V7-24)", got, want)
		return
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("CompressTypes[%d]: got %q, want %q", i, got[i], w)
		}
	}
}

func TestLoadAppliesGlobalTOML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	body := `
[observer]
log_level = "debug"

[observer.watch]
max_file_size_mb = 200

[proxy]
port = 9999
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: p, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Observer.LogLevel != "debug" {
		t.Errorf("log_level: got %q, want %q", cfg.Observer.LogLevel, "debug")
	}
	if cfg.Observer.Watch.MaxFileSizeMB != 200 {
		t.Errorf("max_file_size_mb: got %d, want 200", cfg.Observer.Watch.MaxFileSizeMB)
	}
	if cfg.Proxy.Port != 9999 {
		t.Errorf("proxy.port: got %d, want 9999", cfg.Proxy.Port)
	}
	// Unrelated defaults preserved.
	if !cfg.Compression.Shell.Enabled {
		t.Error("compression.shell.enabled should default true")
	}
}

// TestEmptyEnabledAdaptersDisablesWatch pins the explicit-empty-list
// semantics. A user who writes `enabled_adapters = []` in
// config.toml expects the watcher to skip every adapter — not to
// silently fall through to Default()'s populated list.
// BurntSushi/toml correctly preserves the nil vs. non-nil-empty
// distinction (key absent → leaves Default() alone, key present
// with `[]` → overwrites with []string{}). Pair this with the
// registry.Detected nil-vs-empty fix in internal/adapter/registry.go.
func TestEmptyEnabledAdaptersDisablesWatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	body := `
[observer.watch]
enabled_adapters = []
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: p, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Observer.Watch.EnabledAdapters == nil {
		t.Fatal("EnabledAdapters is nil — expected non-nil empty slice (the registry distinguishes these)")
	}
	if len(cfg.Observer.Watch.EnabledAdapters) != 0 {
		t.Errorf("EnabledAdapters: got %v, want non-nil empty slice", cfg.Observer.Watch.EnabledAdapters)
	}
}

func TestProjectOverridesGlobal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	gp := filepath.Join(dir, "global.toml")
	pp := filepath.Join(dir, "project.toml")
	if err := os.WriteFile(gp, []byte(`[observer]
log_level = "warn"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pp, []byte(`[observer]
log_level = "debug"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: gp, ProjectPath: pp, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Observer.LogLevel != "debug" {
		t.Errorf("project should override global: got %q", cfg.Observer.LogLevel)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"OBSERVER_OBSERVER_LOG_LEVEL":               "warn",
		"OBSERVER_PROXY_PORT":                       "1234",
		"OBSERVER_COMPRESSION_CONVERSATION_ENABLED": "true",
		"OBSERVER_OBSERVER_WATCH_ENABLED_ADAPTERS":  "claude-code,codex",
	}
	cfg, err := Load(LoadOptions{GlobalPath: "", Env: func(k string) string { return env[k] }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Observer.LogLevel != "warn" {
		t.Errorf("log_level: got %q", cfg.Observer.LogLevel)
	}
	if cfg.Proxy.Port != 1234 {
		t.Errorf("port: got %d", cfg.Proxy.Port)
	}
	if !cfg.Compression.Conversation.Enabled {
		t.Errorf("conversation.enabled not overridden")
	}
	if got, want := cfg.Observer.Watch.EnabledAdapters, []string{"claude-code", "codex"}; !equalSlice(got, want) {
		t.Errorf("enabled_adapters: got %v want %v", got, want)
	}
}

func TestValidateRejectsBadLogLevel(t *testing.T) {
	t.Parallel()
	c := Default()
	c.Observer.LogLevel = "trace"
	if err := Validate(c); err == nil {
		t.Fatal("expected error for log_level=trace")
	}
}

// TestValidateAdmissionOnJudgeError pins the Arc-3 posture enum: an unknown
// on_judge_error value is a load-time error, the two valid values + empty pass,
// and a negative judge_retries is rejected.
func TestValidateAdmissionOnJudgeError(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"", "fail_open", "fail_closed"} {
		c := Default()
		c.Observability.Admission.OnJudgeError = v
		if err := Validate(c); err != nil {
			t.Fatalf("on_judge_error=%q should validate, got %v", v, err)
		}
	}
	c := Default()
	c.Observability.Admission.OnJudgeError = "queue_retry"
	if err := Validate(c); err == nil {
		t.Fatal("expected error for on_judge_error=queue_retry (not offered)")
	}
	c = Default()
	c.Observability.Admission.JudgeRetries = -1
	if err := Validate(c); err == nil {
		t.Fatal("expected error for negative judge_retries")
	}
}

// TestValidateProxyUpstreamsRejectsReservedAutoID pins the gateway config
// plane spec Phase 2 rule: "auto" is a reserved virtual lane id — a
// [proxy.upstreams] entry literally keyed "auto" is a config validation
// error, since Proxy.SetUpstreams routes "auto" through resolveAutoLane
// rather than treating it as a real configured lane.
func TestValidateProxyUpstreamsRejectsReservedAutoID(t *testing.T) {
	t.Parallel()
	c := Default()
	c.Proxy.Upstreams = map[string]string{"auto": "https://openrouter.ai/api"}
	if err := Validate(c); err == nil {
		t.Fatal("expected error for proxy.upstreams containing the reserved id \"auto\"")
	}
}

// TestValidateProxyAutoDefaultLaneMustNameConfiguredLane pins the Phase 2
// rule that auto_default_lane, when set, must name a lane actually present
// in proxy.upstreams — an unresolvable default is a config mistake caught
// at validation time, not a runtime fail-open case.
func TestValidateProxyAutoDefaultLaneMustNameConfiguredLane(t *testing.T) {
	t.Parallel()

	t.Run("naming an unconfigured lane is rejected", func(t *testing.T) {
		c := Default()
		c.Proxy.Upstreams = map[string]string{"openrouter": "https://openrouter.ai/api"}
		c.Proxy.AutoDefaultLane = "does-not-exist"
		if err := Validate(c); err == nil {
			t.Fatal("expected error for auto_default_lane naming a lane absent from proxy.upstreams")
		}
	})

	t.Run("naming a configured lane is accepted", func(t *testing.T) {
		c := Default()
		c.Proxy.Upstreams = map[string]string{"openrouter": "https://openrouter.ai/api"}
		c.Proxy.AutoDefaultLane = "openrouter"
		if err := Validate(c); err != nil {
			t.Fatalf("auto_default_lane naming a configured lane should validate: %v", err)
		}
	})

	t.Run("unset (empty) is accepted", func(t *testing.T) {
		c := Default()
		c.Proxy.Upstreams = map[string]string{"openrouter": "https://openrouter.ai/api"}
		if err := Validate(c); err != nil {
			t.Fatalf("unset auto_default_lane should validate: %v", err)
		}
	})
}

// TestValidateProxyOrgRoute pins the P5a node-local bootstrap shape for
// Proxy.SetOrgGatewayRoute (docs/plans/plane-b-dual-mode-gateway-rbac-ia-
// design-2026-08-29.md Sol S7/S8): the zero value ([proxy.org_route] absent)
// is always valid and inert, mode is restricted to the exact wire vocabulary
// ("" / "gateway" — no "node" synonym), gateway mode requires a parseable
// primary URL, and node mode must not carry dead primary/fallback values.
func TestValidateProxyOrgRoute(t *testing.T) {
	t.Parallel()

	t.Run("zero value (no [proxy.org_route] section) is accepted", func(t *testing.T) {
		c := Default()
		if err := Validate(c); err != nil {
			t.Fatalf("zero-value proxy.org_route should validate: %v", err)
		}
	})

	t.Run("gateway mode requires a non-empty primary", func(t *testing.T) {
		c := Default()
		c.Proxy.OrgRoute = ProxyOrgRouteConfig{Mode: "gateway"}
		if err := Validate(c); err == nil {
			t.Fatal("expected error for mode=gateway with empty primary")
		}
	})

	t.Run("gateway mode with a malformed primary URL is rejected", func(t *testing.T) {
		c := Default()
		c.Proxy.OrgRoute = ProxyOrgRouteConfig{Mode: "gateway", Primary: "://not-a-url"}
		if err := Validate(c); err == nil {
			t.Fatal("expected error for mode=gateway with a malformed primary URL")
		}
	})

	t.Run("gateway mode with a malformed fallback URL is rejected", func(t *testing.T) {
		c := Default()
		c.Proxy.OrgRoute = ProxyOrgRouteConfig{
			Mode:      "gateway",
			Primary:   "https://gateway.example.com",
			Fallbacks: []string{"https://ok.example.com", "://also-not-a-url"},
		}
		if err := Validate(c); err == nil {
			t.Fatal("expected error for mode=gateway with a malformed fallback URL")
		}
	})

	t.Run("gateway mode with valid primary and fallbacks is accepted", func(t *testing.T) {
		c := Default()
		c.Proxy.OrgRoute = ProxyOrgRouteConfig{
			Mode:      "gateway",
			Primary:   "https://gateway.example.com",
			Fallbacks: []string{"https://openrouter.ai/api", "https://api.anthropic.com"},
		}
		if err := Validate(c); err != nil {
			t.Fatalf("mode=gateway with valid primary/fallbacks should validate: %v", err)
		}
	})

	t.Run(`"node" is not a recognized synonym for the empty string`, func(t *testing.T) {
		c := Default()
		c.Proxy.OrgRoute = ProxyOrgRouteConfig{Mode: "node"}
		if err := Validate(c); err == nil {
			t.Fatal(`expected error for mode="node" — the wire vocabulary is "" or "gateway", never "node"`)
		}
	})

	t.Run("node mode (empty) rejects a leftover primary", func(t *testing.T) {
		c := Default()
		c.Proxy.OrgRoute = ProxyOrgRouteConfig{Primary: "https://gateway.example.com"}
		if err := Validate(c); err == nil {
			t.Fatal("expected error for mode=\"\" carrying a dead primary value")
		}
	})

	t.Run("node mode (empty) rejects leftover fallbacks", func(t *testing.T) {
		c := Default()
		c.Proxy.OrgRoute = ProxyOrgRouteConfig{Fallbacks: []string{"https://openrouter.ai/api"}}
		if err := Validate(c); err == nil {
			t.Fatal("expected error for mode=\"\" carrying dead fallback values")
		}
	})
}

// TestValidateJudgeUseOrgRelayAmbiguousTransport pins the C1 judge relay spec
// §3 validation rule: use_org_relay=true combined with a non-empty base_url
// OR api_key_env on the SAME resolved judge block is a config error (the
// relay ignores both — ambiguous transport). Checked on both
// [observability.judge] and its [observability.admission.judge] override,
// independently, since Validate loops over both blocks.
func TestValidateJudgeUseOrgRelayAmbiguousTransport(t *testing.T) {
	t.Parallel()

	t.Run("use_org_relay alone is fine", func(t *testing.T) {
		c := Default()
		c.Observability.Judge.UseOrgRelay = true
		if err := Validate(c); err != nil {
			t.Fatalf("use_org_relay=true with no base_url/api_key_env should validate: %v", err)
		}
	})

	t.Run("base_url alone (no relay) is fine", func(t *testing.T) {
		c := Default()
		c.Observability.Judge.BaseURL = "http://127.0.0.1:11434/v1"
		if err := Validate(c); err != nil {
			t.Fatalf("base_url alone should validate: %v", err)
		}
	})

	t.Run("use_org_relay + base_url on the shared judge block is rejected", func(t *testing.T) {
		c := Default()
		c.Observability.Judge.UseOrgRelay = true
		c.Observability.Judge.BaseURL = "http://127.0.0.1:11434/v1"
		if err := Validate(c); err == nil {
			t.Fatal("expected error for use_org_relay=true + base_url set on the same block")
		}
	})

	t.Run("use_org_relay + api_key_env on the shared judge block is rejected", func(t *testing.T) {
		c := Default()
		c.Observability.Judge.UseOrgRelay = true
		c.Observability.Judge.APIKeyEnv = "SOME_KEY"
		if err := Validate(c); err == nil {
			t.Fatal("expected error for use_org_relay=true + api_key_env set on the same block")
		}
	})

	t.Run("use_org_relay + base_url on the admission override block is rejected", func(t *testing.T) {
		c := Default()
		c.Observability.Admission.Judge.UseOrgRelay = true
		c.Observability.Admission.Judge.BaseURL = "http://127.0.0.1:11434/v1"
		if err := Validate(c); err == nil {
			t.Fatal("expected error for use_org_relay=true + base_url set on the admission override block")
		}
	})

	t.Run("use_org_relay on admission override, base_url only on the shared block, is fine", func(t *testing.T) {
		// The two fields must be ambiguous on the SAME resolved block — this
		// case sets UseOrgRelay on the admission override and BaseURL only on
		// the unrelated shared block, so Validate's per-block loop must not
		// cross-contaminate the two.
		c := Default()
		c.Observability.Admission.Judge.UseOrgRelay = true
		c.Observability.Judge.BaseURL = "http://127.0.0.1:11434/v1"
		if err := Validate(c); err != nil {
			t.Fatalf("use_org_relay on one block + base_url only on the other should validate: %v", err)
		}
	})
}

// TestValidateBrowserIngestTimeoutCap pins the finding-2 guard: the browser
// ingest deadline bounds the daemon's end-to-end DB work (db.Open +
// store.Ingest, started before db.Open), and it MUST stay below the native
// host's 40s reply cap so a slow ingest is never killed mid-write. Validate
// rejects a value above the maximum, and IngestTimeout() clamps DOWN as a
// belt-and-suspenders backstop for a config that bypassed Validate.
func TestValidateBrowserIngestTimeoutCap(t *testing.T) {
	t.Parallel()

	// The default config validates and resolves to a bound strictly under the
	// 40s host cap.
	if err := Validate(Default()); err != nil {
		t.Fatalf("Default() failed validation: %v", err)
	}
	if got := Default().Browser.IngestTimeout(); got >= 40*time.Second {
		t.Fatalf("default IngestTimeout %v must stay below the 40s host cap", got)
	}

	// At the maximum: accepted.
	c := Default()
	c.Browser.IngestTimeoutMS = maxBrowserIngestTimeoutMS
	if err := Validate(c); err != nil {
		t.Fatalf("ingest_timeout_ms == max must pass: %v", err)
	}

	// Above the maximum (e.g. the reviewer's 60000): rejected.
	c = Default()
	c.Browser.IngestTimeoutMS = 60000
	if err := Validate(c); err == nil {
		t.Fatal("expected error for browser.ingest_timeout_ms above the maximum")
	}

	// IngestTimeout() clamps an over-max value DOWN even without Validate, so
	// the end-to-end bound can never exceed the host cap.
	if got := (BrowserConfig{IngestTimeoutMS: 60000}).IngestTimeout(); got != maxBrowserIngestTimeoutMS*time.Millisecond {
		t.Errorf("IngestTimeout(60000ms) = %v, want clamp to %dms", got, maxBrowserIngestTimeoutMS)
	}
	// A zero / unset value resolves to the default (not the clamp).
	if got := (BrowserConfig{}).IngestTimeout(); got != defaultBrowserIngestTimeoutMS*time.Millisecond {
		t.Errorf("IngestTimeout(unset) = %v, want default %dms", got, defaultBrowserIngestTimeoutMS)
	}
}

// TestValidateOrgClientPolicy pins [org_client.policy]'s two rules (plan
// §6.4): every listed family must be in the v1 closed set, and
// preauthorize_enforce must be a subset of accept_families.
func TestValidateOrgClientPolicy(t *testing.T) {
	t.Parallel()

	// Default (both empty) always validates.
	if err := Validate(Default()); err != nil {
		t.Fatalf("Default() failed validation: %v", err)
	}

	// A supported family in both lists, correctly subset, validates.
	c := Default()
	c.OrgClient.Policy.AcceptFamilies = []string{"admission.input", "egress.routing_guardrail"}
	c.OrgClient.Policy.PreauthorizeEnforce = []string{"admission.input"}
	if err := Validate(c); err != nil {
		t.Fatalf("valid accept/preauthorize lists failed validation: %v", err)
	}

	// Unsupported family in accept_families is rejected.
	c = Default()
	c.OrgClient.Policy.AcceptFamilies = []string{"not.a.family"}
	if err := Validate(c); err == nil {
		t.Fatal("expected error for unsupported accept_families entry")
	}

	// Unsupported family in preauthorize_enforce is rejected, even if it's
	// (nonsensically) also in accept_families.
	c = Default()
	c.OrgClient.Policy.AcceptFamilies = []string{"not.a.family"}
	c.OrgClient.Policy.PreauthorizeEnforce = []string{"not.a.family"}
	if err := Validate(c); err == nil {
		t.Fatal("expected error for unsupported preauthorize_enforce entry")
	}

	// preauthorize_enforce NOT a subset of accept_families is rejected, even
	// though both families are individually supported.
	c = Default()
	c.OrgClient.Policy.AcceptFamilies = []string{"admission.input"}
	c.OrgClient.Policy.PreauthorizeEnforce = []string{"egress.routing_guardrail"}
	if err := Validate(c); err == nil {
		t.Fatal("expected error: preauthorize_enforce must be a subset of accept_families")
	}
}

// TestValidateOrgClientPolicyNodeAttrs pins the P0-10 Phase B node targeting
// attributes: each key is optional, but a value that could never corroborate
// (padded, oversize, control characters) is rejected at load rather than
// silently never matching.
func TestValidateOrgClientPolicyNodeAttrs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "all three unset (the default)", mutate: func(*Config) {}},
		{
			name: "all three set to plain values",
			mutate: func(c *Config) {
				c.OrgClient.Policy.NodeWorkspace = "acme"
				c.OrgClient.Policy.NodeEnvironment = "prod"
				c.OrgClient.Policy.NodeService = "billing-api"
			},
		},
		{
			name:   "only one set",
			mutate: func(c *Config) { c.OrgClient.Policy.NodeEnvironment = "staging" },
		},
		{
			name:    "leading whitespace",
			mutate:  func(c *Config) { c.OrgClient.Policy.NodeWorkspace = " acme" },
			wantErr: "node_workspace",
		},
		{
			name:    "trailing whitespace",
			mutate:  func(c *Config) { c.OrgClient.Policy.NodeEnvironment = "prod\n" },
			wantErr: "node_environment",
		},
		{
			name:    "oversize",
			mutate:  func(c *Config) { c.OrgClient.Policy.NodeService = strings.Repeat("a", 129) },
			wantErr: "over the 128-byte maximum",
		},
		{
			name:    "control character",
			mutate:  func(c *Config) { c.OrgClient.Policy.NodeService = "api\x07x" },
			wantErr: "control character",
		},
		{
			name:   "at the size limit is fine",
			mutate: func(c *Config) { c.OrgClient.Policy.NodeService = strings.Repeat("a", 128) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			tc.mutate(&c)
			err := Validate(c)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateEmailBlock(t *testing.T) {
	t.Parallel()
	// A disabled [email] block never fails validation.
	c := Default()
	c.Email.TLSMode = "nonsense" // ignored while disabled
	if err := Validate(c); err != nil {
		t.Fatalf("disabled email must not fail validation: %v", err)
	}
	// Enabled but structurally invalid fails.
	c = Default()
	c.Email.Enabled = true
	c.Email.From = "obs@x" // missing host
	if err := Validate(c); err == nil {
		t.Fatal("expected error for enabled email with no host")
	}
	// Enabled and valid passes.
	c = Default()
	c.Email.Enabled = true
	c.Email.Host = "smtp.example.com"
	c.Email.From = "obs@x"
	if err := Validate(c); err != nil {
		t.Fatalf("valid email block rejected: %v", err)
	}
}

func TestValidateRejectsBadConversationMode(t *testing.T) {
	t.Parallel()
	c := Default()
	c.Compression.Conversation.Enabled = true
	c.Compression.Conversation.Mode = "sillystring"
	if err := Validate(c); err == nil {
		t.Fatal("expected error for conversation.mode=sillystring")
	}
}

// TestLoadAppliesDashboardAddr pins that [dashboard].addr round-trips through
// Load — the durable dashboard listen-address setting (issue #8).
func TestLoadAppliesDashboardAddr(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	body := `
[dashboard]
addr = "127.0.0.1:8082"
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: p, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Dashboard.Addr != "127.0.0.1:8082" {
		t.Errorf("dashboard.addr: got %q, want 127.0.0.1:8082", cfg.Dashboard.Addr)
	}
}

// TestLoadDropsMalformedDashboardAddrEnv pins finding #3: a malformed
// OBSERVER_DASHBOARD_ADDR must NOT fail Load (matching setEnvValue's silent
// drop of bad int/float/bool env values). Instead the bad value is dropped and
// the config-file value is preserved, so a valid --dashboard-addr flag —
// which outranks the env var in resolveDashboardAddr — can still win.
func TestLoadDropsMalformedDashboardAddrEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	body := `
[dashboard]
addr = "127.0.0.1:8082"
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	env := func(k string) string {
		if k == "OBSERVER_DASHBOARD_ADDR" {
			return "garbage:notaport"
		}
		return ""
	}
	cfg, err := Load(LoadOptions{GlobalPath: p, Env: env})
	if err != nil {
		t.Fatalf("Load must not fail on a malformed env dashboard addr: %v", err)
	}
	if cfg.Dashboard.Addr != "127.0.0.1:8082" {
		t.Errorf("malformed env value must be dropped, preserving the file value: got %q, want 127.0.0.1:8082", cfg.Dashboard.Addr)
	}
}

// TestLoadAppliesValidDashboardAddrEnv pins that a WELL-FORMED
// OBSERVER_DASHBOARD_ADDR still overrides the config-file value at load.
func TestLoadAppliesValidDashboardAddrEnv(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte("[dashboard]\naddr = \"127.0.0.1:8082\"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	env := func(k string) string {
		if k == "OBSERVER_DASHBOARD_ADDR" {
			return "127.0.0.1:9999"
		}
		return ""
	}
	cfg, err := Load(LoadOptions{GlobalPath: p, Env: env})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Dashboard.Addr != "127.0.0.1:9999" {
		t.Errorf("valid env value must override the file: got %q, want 127.0.0.1:9999", cfg.Dashboard.Addr)
	}
}

// TestDefaultDashboardAddrEmpty pins that the zero-value/default [dashboard].addr
// is empty — the built-in 127.0.0.1:8081 default is applied downstream in
// cmd/observer, not baked into the config layer.
func TestDefaultDashboardAddrEmpty(t *testing.T) {
	t.Parallel()
	if got := Default().Dashboard.Addr; got != "" {
		t.Errorf("default dashboard.addr: got %q, want empty", got)
	}
}

// TestValidateDashboardAddr table-checks the host:port validation on
// [dashboard].addr, following the proxy.port-range check's loud-error style.
func TestValidateDashboardAddr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{"empty is valid (default applies)", "", false},
		{"loopback host:port", "127.0.0.1:8082", false},
		{"all-interfaces host:port", "0.0.0.0:8082", false},
		{"ipv6 loopback", "[::1]:8082", false},
		{"host only, no port", "127.0.0.1", true},
		{"missing port after colon", "127.0.0.1:", true},
		{"zero port", "127.0.0.1:0", true},
		{"garbage", "not-an-address", true},
		// #2 hardening: numeric port required, in 1–65535.
		{"port above 65535", "127.0.0.1:65536", true},
		{"negative port", "127.0.0.1:-1", true},
		{"service-name port", "127.0.0.1:http", true},
		{"max valid port", "127.0.0.1:65535", false},
		// #2 decision: an EMPTY host (bind-all-interfaces) is ACCEPTED at the
		// shape layer — it stays gated by dashboard.CheckRemoteBind, which
		// fails closed unless [remote] is armed. Only the port is shape-checked.
		{"empty host, valid port", ":8082", false},
		{"empty host, port out of range", ":70000", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Default()
			c.Dashboard.Addr = tc.addr
			err := Validate(c)
			if tc.wantErr && err == nil {
				t.Fatalf("dashboard.addr=%q: expected error, got nil", tc.addr)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("dashboard.addr=%q: unexpected error: %v", tc.addr, err)
			}
		})
	}
}

func TestMissingGlobalFileIsNotAnError(t *testing.T) {
	t.Parallel()
	cfg, err := Load(LoadOptions{
		GlobalPath: filepath.Join(t.TempDir(), "does-not-exist.toml"),
		Env:        func(string) string { return "" },
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Observer.LogLevel != "info" {
		t.Errorf("expected default log_level, got %q", cfg.Observer.LogLevel)
	}
}

func TestExpandHome(t *testing.T) {
	t.Parallel()
	cfg, err := Load(LoadOptions{GlobalPath: "", Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Observer.DBPath == "~/.observer/observer.db" {
		t.Errorf("DBPath not expanded: %s", cfg.Observer.DBPath)
	}
}

// TestDefaultLogsConfig pins the v1.7.6 LogsCompressor defaults
// (MaxLines=200, Head=100, Tail=100) — same numbers as the
// prior hardcoded NewLogsCompressor constructor, now operator-tunable
// per docs/codex-compression-recipe.md.
func TestDefaultLogsConfig(t *testing.T) {
	t.Parallel()
	logs := Default().Compression.Conversation.Logs
	if logs.MaxLines != 200 {
		t.Errorf("MaxLines: got %d want 200", logs.MaxLines)
	}
	if logs.Head != 100 {
		t.Errorf("Head: got %d want 100", logs.Head)
	}
	if logs.Tail != 100 {
		t.Errorf("Tail: got %d want 100", logs.Tail)
	}
}

// TestValidateAcceptsZeroMaxLines pins that MaxLines=0 (the
// "disable truncation" sentinel) passes validation — this is the
// codex-variant recipe's setting.
func TestValidateAcceptsZeroMaxLines(t *testing.T) {
	t.Parallel()
	c := Default()
	c.Compression.Conversation.Logs.MaxLines = 0
	c.Compression.Conversation.Logs.Head = 0
	c.Compression.Conversation.Logs.Tail = 0
	if err := Validate(c); err != nil {
		t.Fatalf("MaxLines=0 must be valid: %v", err)
	}
}

// TestValidateRejectsNegativeLogsKnobs pins the contract that
// MaxLines/Head/Tail must be >= 0.
func TestValidateRejectsNegativeLogsKnobs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"negative_max_lines", func(c *Config) { c.Compression.Conversation.Logs.MaxLines = -1 }},
		{"negative_head", func(c *Config) { c.Compression.Conversation.Logs.Head = -1 }},
		{"negative_tail", func(c *Config) { c.Compression.Conversation.Logs.Tail = -1 }},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Default()
			tc.mutate(&c)
			if err := Validate(c); err == nil {
				t.Fatalf("Validate %s: expected error, got nil", tc.name)
			}
		})
	}
}

// TestLoadLogsConfigRoundtrips pins that TOML round-trips through
// [Load] into the LogsConfig fields. The codex-variant recipe's
// `max_lines = 0` is the load-bearing case (recipe in
// docs/recipes/codex-variant.toml relies on this).
func TestLoadLogsConfigRoundtrips(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "observer.toml")
	body := []byte(`
[compression.conversation.logs]
max_lines = 500
head      = 250
tail      = 250
`)
	if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Compression.Conversation.Logs.MaxLines; got != 500 {
		t.Errorf("MaxLines: got %d want 500", got)
	}
	if got := cfg.Compression.Conversation.Logs.Head; got != 250 {
		t.Errorf("Head: got %d want 250", got)
	}
	if got := cfg.Compression.Conversation.Logs.Tail; got != 250 {
		t.Errorf("Tail: got %d want 250", got)
	}
}

// TestDefaultStashMaxTotalMBIs1024 pins the v1.7.6 stash cap bump
// (256 → 1024 MB) per V7-13 Gap 2 (ii). Code-agent workloads churn
// large file reads at a rate that fills 256 MB fast; 1024 is the
// new working-set cap.
func TestDefaultStashMaxTotalMBIs1024(t *testing.T) {
	t.Parallel()
	got := Default().Compression.Conversation.Stash.MaxTotalMB
	if got != 1024 {
		t.Errorf("Stash.MaxTotalMB: got %d want 1024", got)
	}
}

// TestIntelligenceMCPGetFile_DefaultsAreSafe pins the v1.7.8
// [intelligence.mcp.get_file] defaults: enabled, 100 KB cap, deny
// patterns covering the standard secrets/SCM/dep paths.
func TestIntelligenceMCPGetFile_DefaultsAreSafe(t *testing.T) {
	t.Parallel()
	got := Default().Intelligence.MCP.GetFile
	if !got.Enabled {
		t.Errorf("GetFile.Enabled: want true (V7-12 ships ON by default)")
	}
	if got.MaxResponseKB != 100 {
		t.Errorf("GetFile.MaxResponseKB: got %d want 100", got.MaxResponseKB)
	}
	want := []string{".env*", ".git/**", "node_modules/**", ".ssh/**", "*.key"}
	denyIdx := map[string]bool{}
	for _, p := range got.DenyPaths {
		denyIdx[p] = true
	}
	for _, p := range want {
		if !denyIdx[p] {
			t.Errorf("GetFile.DenyPaths missing canonical default %q", p)
		}
	}
	if !Default().Intelligence.MCP.Audit.Enabled {
		t.Errorf("Audit.Enabled: want true (forensic value high, opt-out via TOML)")
	}
}

// TestIntelligenceMCPGetSymbols_DefaultsAreSane pins the v1.7.9
// [intelligence.mcp.get_symbols] defaults: enabled, 20/20 caller/
// callee caps (V7-12 spec).
func TestIntelligenceMCPGetSymbols_DefaultsAreSane(t *testing.T) {
	t.Parallel()
	got := Default().Intelligence.MCP.GetSymbols
	if !got.Enabled {
		t.Errorf("GetSymbols.Enabled: want true (V7-12 ships ON by default)")
	}
	if got.MaxCallers != 20 {
		t.Errorf("GetSymbols.MaxCallers: got %d want 20", got.MaxCallers)
	}
	if got.MaxCallees != 20 {
		t.Errorf("GetSymbols.MaxCallees: got %d want 20", got.MaxCallees)
	}
}

// TestIntelligenceMCPGetRelations_DefaultsAreSane pins the v1.7.10
// [intelligence.mcp.get_relations] defaults: enabled, depth 5 cap,
// 100-result cap (V7-12 spec).
func TestIntelligenceMCPGetRelations_DefaultsAreSane(t *testing.T) {
	t.Parallel()
	got := Default().Intelligence.MCP.GetRelations
	if !got.Enabled {
		t.Errorf("GetRelations.Enabled: want true (V7-12 ships ON by default)")
	}
	if got.MaxDepth != 5 {
		t.Errorf("GetRelations.MaxDepth: got %d want 5", got.MaxDepth)
	}
	if got.MaxResults != 100 {
		t.Errorf("GetRelations.MaxResults: got %d want 100", got.MaxResults)
	}
}

// TestIntelligenceMCPRetrieveStashed_DefaultsAreSane pins the
// v1.7.11 [intelligence.mcp.retrieve_stashed] defaults: enabled, 25
// shas per call (matches get_symbols's batch cap).
func TestIntelligenceMCPRetrieveStashed_DefaultsAreSane(t *testing.T) {
	t.Parallel()
	got := Default().Intelligence.MCP.RetrieveStashed
	if !got.Enabled {
		t.Errorf("RetrieveStashed.Enabled: want true (ships ON by default)")
	}
	if got.MaxShasPerCall != 25 {
		t.Errorf("RetrieveStashed.MaxShasPerCall: got %d want 25", got.MaxShasPerCall)
	}
}

// TestIntelligenceMCPFeatures_DefaultIsEmpty pins the V7-16 default:
// Features is an empty slice (NOT nil) so TOML round-trips emit
// `features = []` consistently. Empty list semantically = "no filter
// applied"; non-empty becomes a strict allow-list scoped to the four
// V7-12 tools.
func TestIntelligenceMCPFeatures_DefaultIsEmpty(t *testing.T) {
	t.Parallel()
	got := Default().Intelligence.MCP.Features
	if got == nil {
		t.Errorf("Features: got nil, want []string{} (round-trip stability)")
	}
	if len(got) != 0 {
		t.Errorf("Features: got %v, want empty slice (no filter applied by default)", got)
	}
}

// TestUnsupportedDenyPatterns surfaces silently-dead patterns at
// startup. Called by `observer serve` to emit one warning per
// unsupported entry; this test pins the supported / unsupported
// syntax decision.
func TestUnsupportedDenyPatterns(t *testing.T) {
	t.Parallel()
	g := IntelligenceMCPGetFileConfig{
		DenyPaths: []string{
			".env*",        // supported
			"*.key",        // supported
			".git/**",      // supported
			"src/?oo.ts",   // supported
			"src/[ab].ts",  // unsupported — char class
			"src/{a,b}.ts", // unsupported — braces
			`src/\*.ts`,    // unsupported — escape
		},
	}
	bad := g.UnsupportedDenyPatterns()
	wantBad := map[string]bool{
		"src/[ab].ts":  true,
		"src/{a,b}.ts": true,
		`src/\*.ts`:    true,
	}
	if len(bad) != len(wantBad) {
		t.Fatalf("got %d unsupported patterns (%v), want %d", len(bad), bad, len(wantBad))
	}
	for _, p := range bad {
		if !wantBad[p] {
			t.Errorf("pattern %q reported as unsupported but should have been supported", p)
		}
	}
}

func equalSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestGuardDefaults pins the guard partial-merge invariant (guard
// spec SS16 + operator decision D2): an install with NO [guard]
// section gets Enabled=true + Mode="observe" from Default() -- never
// zero values -- and a PARTIAL [guard] section keeps every unset
// field's default (the cachetrack live-daemon-captures-nothing bug
// class). Cloud features stay all-off (D1).
func TestGuardDefaults(t *testing.T) {
	t.Parallel()
	g := Default().Guard
	if !g.Enabled || g.Mode != "observe" {
		t.Errorf("guard defaults = enabled=%v mode=%q, want true/observe (D2)", g.Enabled, g.Mode)
	}
	if g.Strict {
		t.Error("guard.strict must default false (Q2 fail-open)")
	}
	if g.RetentionDays != 365 {
		t.Errorf("guard.retention_days = %d, want 365", g.RetentionDays)
	}
	if g.Rules.UserPolicy != "~/.observer/guard-policy.toml" || g.Rules.ProjectPolicy != ".observer/guard-policy.toml" {
		t.Errorf("guard.rules policy paths = %q / %q", g.Rules.UserPolicy, g.Rules.ProjectPolicy)
	}
	if !g.Taint.Enabled || g.Taint.DecayTurns != 10 {
		t.Errorf("guard.taint = %+v, want enabled/10", g.Taint)
	}
	if g.Boundary.AllowPaths != nil || g.Boundary.ProtectedBranches != nil {
		t.Errorf("guard.boundary slices must default nil (engine defaults apply): %+v", g.Boundary)
	}
	if g.Cloud.Enabled || g.Cloud.LLMJudge.Enabled || g.Cloud.Reputation.Enabled {
		t.Error("guard.cloud features must ALL default off (D1)")
	}
	if g.Alerts.MinSeverity != "high" || !g.Alerts.Desktop {
		t.Errorf("guard.alerts = %+v, want desktop/high", g.Alerts)
	}

	// Partial-merge: a [guard] section setting ONLY mode keeps every
	// other default (Enabled stays true, taint stays on).
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte("[guard]\nmode = \"enforce\"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: p})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Guard.Mode != "enforce" {
		t.Errorf("mode = %q, want enforce", cfg.Guard.Mode)
	}
	if !cfg.Guard.Enabled || !cfg.Guard.Taint.Enabled || cfg.Guard.RetentionDays != 365 {
		t.Errorf("partial [guard] section lost defaults: %+v", cfg.Guard)
	}

	// Validate rejects the known-bad shapes loudly.
	bad := Default()
	bad.Guard.Mode = "bogus"
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted guard.mode=bogus")
	}
	bad = Default()
	bad.Guard.Rules.CEL = true
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted guard.rules.cel=true (deferred Q1)")
	}
}

// TestGuardPromptDefaults pins [guard.prompt] (prompt-submit intervention
// build contract §8.1): the seeded defaults, the partial-merge invariant
// (including the map field — a config file that omits
// [guard.prompt.detectors] entirely must NOT nil out the seeded
// Detectors map, since some TOML decoders replace a whole map whenever
// any table under it is touched), and the validator's enum/pattern/TTL
// checks.
func TestGuardPromptDefaults(t *testing.T) {
	t.Parallel()
	p := Default().Guard.Prompt
	if !p.Enabled || p.Mode != "ask-once" {
		t.Errorf("guard.prompt defaults = enabled=%v mode=%q, want true/ask-once", p.Enabled, p.Mode)
	}
	if !p.HookLane || !p.ProxyLane {
		t.Errorf("guard.prompt hook_lane/proxy_lane must default true: %+v", p)
	}
	// FIX-8 (phase-2 review): the prompt lane must act on its own mode
	// out of the box, independent of [guard].mode's own "observe"
	// default — otherwise the ask-once defaults above would be
	// silently inert on a fresh install.
	if !p.EnforceIndependent {
		t.Error("guard.prompt.enforce_independent must default true")
	}
	if p.ReconsiderTTL != "30m" {
		t.Errorf("guard.prompt.reconsider_ttl = %q, want 30m", p.ReconsiderTTL)
	}
	if d, err := p.ReconsiderTTLDuration(); err != nil || d != 30*time.Minute {
		t.Errorf("ReconsiderTTLDuration() = %v, %v; want 30m, nil", d, err)
	}
	if !p.SuppressInCode {
		t.Error("guard.prompt.suppress_in_code must default true")
	}
	if p.MaxFindings != 64 {
		t.Errorf("guard.prompt.max_findings = %d, want 64", p.MaxFindings)
	}
	wantDetectors := map[string]string{
		"credit_card": "ask-once",
		"iban":        "ask-once",
		"us_ssn":      "ask-once",
		"uk_nino":     "ask-once",
		"in_aadhaar":  "ask-once",
		"in_pan":      "ask-once",
		"email":       "off",
		"phone_e164":  "off",
		"phone_nanp":  "off",
		"github_pat":  "block",
	}
	if len(p.Detectors) != len(wantDetectors) {
		t.Fatalf("guard.prompt.detectors = %+v, want %+v", p.Detectors, wantDetectors)
	}
	for id, mode := range wantDetectors {
		if p.Detectors[id] != mode {
			t.Errorf("guard.prompt.detectors[%q] = %q, want %q", id, p.Detectors[id], mode)
		}
	}

	// Partial-merge: a [guard.prompt] section setting ONLY mode keeps
	// every other default, INCLUDING the seeded Detectors map — the file
	// doesn't mention [guard.prompt.detectors] at all.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[guard.prompt]\nmode = \"block\"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Guard.Prompt
	if got.Mode != "block" {
		t.Errorf("mode = %q, want block", got.Mode)
	}
	if !got.Enabled || !got.HookLane || !got.ProxyLane || got.MaxFindings != 64 {
		t.Errorf("partial [guard.prompt] section lost scalar defaults: %+v", got)
	}
	if len(got.Detectors) != len(wantDetectors) {
		t.Errorf("partial [guard.prompt] section nil'd/shrank the seeded detectors map: %+v", got.Detectors)
	}
	for id, mode := range wantDetectors {
		if got.Detectors[id] != mode {
			t.Errorf("detectors[%q] = %q, want %q (seeded default must survive)", id, got.Detectors[id], mode)
		}
	}

	// A file that DOES set [guard.prompt.detectors] overrides that
	// table's contents (expected — the table was present in the file).
	cfgPath2 := filepath.Join(dir, "config2.toml")
	seed := "[guard.prompt.detectors]\nemail = \"warn\"\n"
	if err := os.WriteFile(cfgPath2, []byte(seed), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg2, err := Load(LoadOptions{GlobalPath: cfgPath2})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg2.Guard.Prompt.Detectors["email"] != "warn" {
		t.Errorf("explicit [guard.prompt.detectors] override lost: %+v", cfg2.Guard.Prompt.Detectors)
	}

	// Validate rejects the known-bad shapes loudly.
	bad := Default()
	bad.Guard.Prompt.Mode = "bogus"
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted guard.prompt.mode=bogus")
	}
	bad = Default()
	bad.Guard.Prompt.Detectors = map[string]string{"not_a_real_detector": "block"}
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted an unknown guard.prompt.detectors key")
	}
	bad = Default()
	bad.Guard.Prompt.Detectors = map[string]string{"credit_card": "bogus"}
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted an unknown guard.prompt.detectors mode value")
	}
	bad = Default()
	bad.Guard.Prompt.Allow = []string{"("}
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted an invalid guard.prompt.allow regex")
	}
	bad = Default()
	bad.Guard.Prompt.ReconsiderTTL = "not-a-duration"
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted an unparseable guard.prompt.reconsider_ttl")
	}
	bad = Default()
	bad.Guard.Prompt.ReconsiderTTL = "0s"
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted a zero guard.prompt.reconsider_ttl")
	}
	bad = Default()
	bad.Guard.Prompt.MaxFindings = -1
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted a negative guard.prompt.max_findings")
	}
}

// TestPredictDefaults pins the [predict] partial-merge invariant
// (docs/cost-predictor.md): default-ON with the tuning defaults, and a
// PARTIAL [predict] section keeps every unset field (the cachetrack
// live-daemon-captures-nothing bug class).
func TestPredictDefaults(t *testing.T) {
	t.Parallel()
	p := Default().Predict
	if !p.Enabled {
		t.Error("predict must default enabled=true")
	}
	if p.YoungSessionMessages != 3 || p.DefaultTurnsPerMessage != 12 || p.PriorWindowDays != 30 {
		t.Errorf("predict defaults = %+v, want 3/12/30", p)
	}

	// Partial-merge: a [predict] section setting ONLY enabled=false keeps
	// the other tuning defaults.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[predict]\nenabled = false\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Predict.Enabled {
		t.Error("enabled=false should override")
	}
	if cfg.Predict.YoungSessionMessages != 3 || cfg.Predict.DefaultTurnsPerMessage != 12 {
		t.Errorf("partial [predict] lost tuning defaults: %+v", cfg.Predict)
	}
}

// TestLocDefaults pins the [loc] partial-merge invariant
// (docs/loc-tracking.md): a config file with NO [loc] section gets the
// generated-token path and required=false, and a partial section that sets
// only one key keeps the other at its default. Getting this wrong is the
// cachetrack live-daemon-captures-nothing bug class in a new place — a
// zero-valued EditorTokenFile would make the daemon generate no token at
// all and silently drop the endpoint back to loopback-only.
func TestLocDefaults(t *testing.T) {
	t.Parallel()
	l := Default().Loc
	if l.EditorTokenFile != DefaultLocEditorTokenFile {
		t.Errorf("loc.editor_token_file default = %q, want %q", l.EditorTokenFile, DefaultLocEditorTokenFile)
	}
	if l.EditorTokenRequired {
		t.Error("loc.editor_token_required must default false this release (older extensions send no token)")
	}

	dir := t.TempDir()

	// No [loc] section at all: the seed survives, with "~/" expanded the
	// same way observer.db_path is.
	noSection := filepath.Join(dir, "none.toml")
	if err := os.WriteFile(noSection, []byte("[observer]\ndb_path = \"/tmp/x.db\"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: noSection})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Loc.EditorTokenFile == "" {
		t.Error("a config with no [loc] section must still resolve an editor token file")
	}
	if strings.HasPrefix(cfg.Loc.EditorTokenFile, "~/") {
		t.Errorf("loc.editor_token_file was not home-expanded: %q", cfg.Loc.EditorTokenFile)
	}
	if !strings.HasSuffix(filepath.ToSlash(cfg.Loc.EditorTokenFile), "/.observer/loc-editor-token") {
		t.Errorf("loc.editor_token_file = %q, want the observer home default", cfg.Loc.EditorTokenFile)
	}

	// Partial: only required=true. The path default must survive.
	partial := filepath.Join(dir, "partial.toml")
	if err := os.WriteFile(partial, []byte("[loc]\neditor_token_required = true\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err = Load(LoadOptions{GlobalPath: partial})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Loc.EditorTokenRequired {
		t.Error("editor_token_required = true should override")
	}
	if cfg.Loc.EditorTokenFile == "" {
		t.Error("partial [loc] lost the editor_token_file default")
	}

	// Partial the other way: only the path. required must stay false.
	pathOnly := filepath.Join(dir, "path.toml")
	body := "[loc]\neditor_token_file = \"" + filepath.ToSlash(filepath.Join(dir, "tok")) + "\"\n"
	if err := os.WriteFile(pathOnly, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err = Load(LoadOptions{GlobalPath: pathOnly})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Loc.EditorTokenRequired {
		t.Error("partial [loc] must not flip editor_token_required")
	}
	if filepath.ToSlash(cfg.Loc.EditorTokenFile) != filepath.ToSlash(filepath.Join(dir, "tok")) {
		t.Errorf("editor_token_file override lost: %q", cfg.Loc.EditorTokenFile)
	}
}

// TestCloudDefaults pins D15: an install with no [cloud] section leaves
// BaseURL/LoginPort/AutoSync at their zero values — identical to the
// pre-D15 behaviour where the CLI had no config-file layer at all.
func TestCloudDefaults(t *testing.T) {
	t.Parallel()
	c := Default().Cloud
	if c.BaseURL != "" || c.LoginPort != 0 || c.AutoSync {
		t.Errorf("cloud defaults = %+v, want zero value", c)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[cloud]\nbase_url = \"https://cloud.example.com\"\nlogin_port = 9800\nauto_sync = true\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Cloud.BaseURL != "https://cloud.example.com" {
		t.Errorf("base_url = %q, want https://cloud.example.com", cfg.Cloud.BaseURL)
	}
	if cfg.Cloud.LoginPort != 9800 {
		t.Errorf("login_port = %d, want 9800", cfg.Cloud.LoginPort)
	}
	if !cfg.Cloud.AutoSync {
		t.Error("auto_sync = false, want true")
	}
	if err := Validate(cfg); err != nil {
		t.Errorf("populated [cloud] should validate: %v", err)
	}
}

// TestCloudValidate pins the D15 validation rules: an out-of-range
// login_port or a non-http(s) base_url is a loud config error, while the
// zero value (no [cloud] section) always passes.
func TestCloudValidate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		cloud   CloudConfig
		wantErr bool
	}{
		{"zero value", CloudConfig{}, false},
		{"valid https", CloudConfig{BaseURL: "https://cloud.example.com"}, false},
		{"valid http", CloudConfig{BaseURL: "http://127.0.0.1:9000"}, false},
		{"valid port", CloudConfig{LoginPort: 9797}, false},
		{"port too low", CloudConfig{LoginPort: -1}, true},
		{"port too high", CloudConfig{LoginPort: 70000}, true},
		{"non-url base_url", CloudConfig{BaseURL: "not a url"}, true},
		{"non-http(s) scheme", CloudConfig{BaseURL: "ftp://cloud.example.com"}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := Default()
			cfg.Cloud = tc.cloud
			err := Validate(cfg)
			if tc.wantErr && err == nil {
				t.Errorf("Validate() with cloud=%+v: want error, got nil", tc.cloud)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() with cloud=%+v: unexpected error: %v", tc.cloud, err)
			}
		})
	}
}

// TestTasksDefaults pins the [tasks] partial-merge invariant
// (docs/task-tracking.md): default-ON with the documented tuning
// defaults, and a PARTIAL [tasks] section keeps every unset field (the
// cachetrack live-daemon-captures-nothing bug class).
func TestTasksDefaults(t *testing.T) {
	t.Parallel()
	tc := Default().Tasks
	if !tc.Enabled {
		t.Error("tasks must default enabled=true")
	}
	if tc.MatchMode != "exact" || tc.ConcurrentAttribution != "shared" {
		t.Errorf("tasks defaults = %+v, want match_mode=exact concurrent_attribution=shared", tc)
	}
	if tc.IncludeSidechains || tc.BackfillOnStart {
		t.Errorf("tasks defaults = %+v, want include_sidechains=false backfill_on_start=false", tc)
	}

	// Partial-merge: a [tasks] section setting ONLY enabled=false keeps
	// the other tuning defaults.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[tasks]\nenabled = false\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Tasks.Enabled {
		t.Error("enabled=false should override")
	}
	if cfg.Tasks.MatchMode != "exact" || cfg.Tasks.ConcurrentAttribution != "shared" {
		t.Errorf("partial [tasks] lost tuning defaults: %+v", cfg.Tasks)
	}
}

// TestTasksValidate pins the enum guards on tasks.match_mode and
// tasks.concurrent_attribution — deliberately NOT including a "split"
// option (§R2.3.2: bucketing, never splitting, an ambiguous
// concurrent-task attribution).
func TestTasksValidate(t *testing.T) {
	t.Parallel()
	good := Default()
	if err := Validate(good); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}

	bad := Default()
	bad.Tasks.MatchMode = "fuzzy"
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted tasks.match_mode=fuzzy")
	}

	bad = Default()
	bad.Tasks.ConcurrentAttribution = "split"
	if err := Validate(bad); err == nil {
		t.Error("Validate accepted tasks.concurrent_attribution=split")
	}
}

// TestProcessObservabilityDefaults pins the opt-in posture of the
// [observer.process] surface (docs/process-observability.md §11): the
// feature defaults OFF (D1, unlike Guard/CacheTrack/Advisor), and the
// non-zero defaults are inherited on a partial-merge so flipping just
// `enabled = true` yields a sane backend/queue/argv config rather than
// zeros that would fail Validate.
func TestProcessObservabilityDefaults(t *testing.T) {
	t.Parallel()
	p := Default().Observer.Process
	if p.Enabled {
		t.Error("observer.process.enabled must default to false (D1 — opt-in feature)")
	}
	if p.Backend != "auto" {
		t.Errorf("backend = %q, want auto", p.Backend)
	}
	if p.CaptureUnattributed {
		t.Error("capture_unattributed must default false (D5/§9.2.7)")
	}
	if p.RetentionDays != 30 || p.QueueSize != 10000 || p.BatchSize != 250 {
		t.Errorf("retention/queue/batch = %d/%d/%d, want 30/10000/250", p.RetentionDays, p.QueueSize, p.BatchSize)
	}
	// Unified poll rate defaults to 2000ms; the bridge override defaults to 0
	// (inherit). The 0-default is load-bearing: the dashboard "process poll
	// rate" knob writes PollIntervalMS, and BridgePollIntervalMS=0 keeps the
	// bridge on the same cadence unless the operator deliberately splits them.
	if p.PollIntervalMS != 2000 {
		t.Errorf("poll_interval_ms = %d, want 2000", p.PollIntervalMS)
	}
	if p.BridgePollIntervalMS != 0 {
		t.Errorf("bridge_poll_interval_ms = %d, want 0 (inherit)", p.BridgePollIntervalMS)
	}
	// Background cross-OS correlation sweep cadence defaults to 90s.
	if p.CorrelateIntervalMS != 90000 {
		t.Errorf("correlate_interval_ms = %d, want 90000", p.CorrelateIntervalMS)
	}
	if p.Argv.Mode != "preview" || p.Argv.MaxPreviewBytes != 512 || !p.Argv.StoreArgCount {
		t.Errorf("argv defaults = %+v, want preview/512/true", p.Argv)
	}
	if !p.Env.Enabled || !p.Env.StorePathHash {
		t.Errorf("env defaults = %+v, want enabled/path-hash", p.Env)
	}
	if p.Network.Enabled || p.Filesystem.Enabled || p.Executable.HashEnabled {
		t.Error("network/filesystem/executable-hash must ALL default off")
	}

	// Partial-merge: a section setting ONLY enabled keeps every other
	// default (backend stays auto, queue/batch/argv stay sane).
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer.process]\nenabled = true\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Observer.Process
	if !got.Enabled {
		t.Error("enabled = false after explicitly setting it true")
	}
	if got.Backend != "auto" || got.QueueSize != 10000 || got.BatchSize != 250 || got.Argv.Mode != "preview" {
		t.Errorf("partial [observer.process] section lost defaults: %+v", got)
	}
	if err := Validate(cfg); err != nil {
		t.Errorf("partial-merged process config failed Validate: %v", err)
	}

	// Validate rejects known-bad enums loudly — but ONLY when enabled.
	for _, mut := range []func(*Config){
		func(c *Config) { c.Observer.Process.Backend = "bogus" },
		func(c *Config) { c.Observer.Process.Argv.Mode = "bogus" },
		func(c *Config) { c.Observer.Process.Filesystem.Mode = "bogus" },
		func(c *Config) { c.Observer.Process.QueueSize = 0 },
		func(c *Config) { c.Observer.Process.PollIntervalMS = -1 },
		func(c *Config) { c.Observer.Process.BridgePollIntervalMS = -1 },
		func(c *Config) { c.Observer.Process.CorrelateIntervalMS = -1 },
	} {
		bad := Default()
		bad.Observer.Process.Enabled = true
		mut(&bad)
		if err := Validate(bad); err == nil {
			t.Error("Validate accepted a known-bad enabled process config")
		}
	}
	// A bogus backend on a DISABLED section must NOT fail (opt-in: stale
	// sections never break the daemon).
	off := Default()
	off.Observer.Process.Backend = "bogus"
	if err := Validate(off); err != nil {
		t.Errorf("Validate rejected a disabled process config with a bad enum: %v", err)
	}

	// Every backend selectProcessBackend (cmd/observer/processobs.go) accepts
	// must pass Validate when enabled — in particular "bridge", the cross-OS
	// backend that "auto" resolves to on WSL. Regression guard: the validator
	// once omitted "bridge" and spuriously rejected an explicit
	// backend = "bridge" the docs/comment documented as valid.
	for _, backend := range []string{"auto", "bridge", "both", "poll", "linux_ebpf", "etw", "endpointsecurity", "off"} {
		ok := Default()
		ok.Observer.Process.Enabled = true
		ok.Observer.Process.Backend = backend
		if err := Validate(ok); err != nil {
			t.Errorf("Validate rejected valid enabled process backend %q: %v", backend, err)
		}
	}
}

// TestProcessETWDefaults pins the [observer.process.etw] sub-block: the
// daemon-side ACCEPT listener the elevated Windows ETW capturer dials into
// (docs/plans/process-obs-etw-windows-parity-plan-2026-07-26.md §W3).
//
// Three properties matter here. (1) It is its OWN block — NOT an extension of
// [observer.process.network], whose name is already taken by capture of the
// target process's own connections (§7.2). (2) It partial-merges like every
// other sub-section, so a bare `[observer.process.etw] enabled = true`
// inherits a loopback addr and a sane timeout. (3) Its validation is gated on
// the PARENT `[observer.process].enabled` (the early return in
// validateProcessObs) but NOT on its own `enabled` — the same choice the
// Network/Filesystem enums make, so a bad value fails at the edit rather than
// at flip time.
func TestProcessETWDefaults(t *testing.T) {
	t.Parallel()

	e := Default().Observer.Process.ETW
	if e.Enabled {
		t.Error("observer.process.etw.enabled must default false (it opens a port; opt-in like the rest of [observer.process])")
	}
	if e.ListenAddr != "127.0.0.1:8823" {
		t.Errorf("listen_addr = %q, want the loopback default 127.0.0.1:8823", e.ListenAddr)
	}
	if e.AllowNonLoopback {
		t.Error("allow_non_loopback must default false")
	}
	if e.Token != "" || e.TokenPath != "" {
		t.Errorf("token/token_path must default empty (the daemon generates + persists one): %+v", e)
	}
	if e.HandshakeTimeoutMS != 10000 {
		t.Errorf("handshake_timeout_ms = %d, want 10000", e.HandshakeTimeoutMS)
	}

	// Partial-merge: enabling ONLY the sub-block keeps every seeded default.
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	body := "[observer.process]\nenabled = true\n\n[observer.process.etw]\nenabled = true\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Observer.Process.ETW
	if !got.Enabled || got.ListenAddr != "127.0.0.1:8823" || got.HandshakeTimeoutMS != 10000 {
		t.Errorf("partial [observer.process.etw] section lost defaults: %+v", got)
	}
	if err := Validate(cfg); err != nil {
		t.Errorf("partial-merged etw config failed Validate: %v", err)
	}

	// Bad values are rejected when process observability is enabled, whether
	// or not the ETW block itself is.
	for _, tt := range []struct {
		name string
		mut  func(*Config)
	}{
		{"negative timeout", func(c *Config) { c.Observer.Process.ETW.HandshakeTimeoutMS = -1 }},
		{"addr without a port", func(c *Config) { c.Observer.Process.ETW.ListenAddr = "127.0.0.1" }},
		{"garbage addr", func(c *Config) { c.Observer.Process.ETW.ListenAddr = "not an address" }},
		{"bad value in a DISABLED sub-block still fails", func(c *Config) {
			c.Observer.Process.ETW.Enabled = false
			c.Observer.Process.ETW.HandshakeTimeoutMS = -5
		}},
	} {
		bad := Default()
		bad.Observer.Process.Enabled = true
		bad.Observer.Process.ETW.Enabled = true
		tt.mut(&bad)
		if err := Validate(bad); err == nil {
			t.Errorf("Validate accepted %s", tt.name)
		}
	}

	// ...but a stale ETW section on a DISABLED [observer.process] never fails
	// the daemon (the parent opt-in gate).
	off := Default()
	off.Observer.Process.ETW.Enabled = true
	off.Observer.Process.ETW.HandshakeTimeoutMS = -1
	if err := Validate(off); err != nil {
		t.Errorf("Validate rejected a stale etw section under disabled process capture: %v", err)
	}
}

// TestBrowserIngestTimeoutDefaults pins the [browser].ingest_timeout_ms
// partial-merge invariant: the browser-capture DB ingest deadline is
// decoupled from the ~500ms blocking-hook timeout and defaults to a generous
// 35s, an absent key inherits that default, an explicit value is honored, and
// a zero / negative value resolves back to the default via IngestTimeout().
func TestBrowserIngestTimeoutDefaults(t *testing.T) {
	t.Parallel()

	// Default() carries the 35s default (must exceed the 30s SQLite
	// busy_timeout — GPT-5.6 review 2026-07-18 #3) and IngestTimeout() reflects it.
	if got := Default().Browser.IngestTimeoutMS; got != 35000 {
		t.Errorf("browser.ingest_timeout_ms default = %d, want 35000", got)
	}
	if got := Default().Browser.IngestTimeout(); got != 35*time.Second {
		t.Errorf("browser IngestTimeout() default = %v, want 35s", got)
	}

	// IngestTimeout() resolution: explicit values honored, zero/negative → default.
	for _, tc := range []struct {
		name string
		ms   int
		want time.Duration
	}{
		{"explicit", 3000, 3 * time.Second},
		{"zero", 0, 35 * time.Second},
		{"negative", -1, 35 * time.Second},
	} {
		if got := (BrowserConfig{IngestTimeoutMS: tc.ms}).IngestTimeout(); got != tc.want {
			t.Errorf("%s: IngestTimeout(%d) = %v, want %v", tc.name, tc.ms, got, tc.want)
		}
	}

	// Partial-merge: a [browser] section that omits ingest_timeout_ms inherits
	// the 35s default (the cachetrack live-daemon-captures-nothing bug class).
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[browser]\nenabled = true\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Browser.IngestTimeoutMS != 35000 {
		t.Errorf("partial [browser] section lost ingest_timeout_ms default: %d", cfg.Browser.IngestTimeoutMS)
	}

	// An explicit value overrides.
	cfgPath2 := filepath.Join(dir, "config2.toml")
	if err := os.WriteFile(cfgPath2, []byte("[browser]\ningest_timeout_ms = 8000\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg2, err := Load(LoadOptions{GlobalPath: cfgPath2})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg2.Browser.IngestTimeout() != 8*time.Second {
		t.Errorf("explicit ingest_timeout_ms not honored: %v", cfg2.Browser.IngestTimeout())
	}
}

func TestLoadParsesObservabilityAlerts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	body := `
[observability]
enabled = true

[observability.alerts]
enabled = true
webhook_url = "https://example.test/hook"
eval_interval_minutes = 10

[[observability.alerts.rules]]
name = "err-rate"
metric = "error_rate"
comparator = "gte"
threshold = 0.1
window_minutes = 15
cooldown_minutes = 30

[[observability.alerts.rules]]
name = "spend"
metric = "cost_usd"
threshold = 5.0
window_minutes = 60
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: p, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	a := cfg.Observability.Alerts
	if !a.Enabled || a.WebhookURL != "https://example.test/hook" || a.EvalIntervalMinutes != 10 {
		t.Fatalf("alerts scalars = %+v", a)
	}
	if len(a.Rules) != 2 {
		t.Fatalf("rules len = %d, want 2", len(a.Rules))
	}
	r0 := a.Rules[0]
	if r0.Name != "err-rate" || r0.Metric != "error_rate" || r0.Comparator != "gte" ||
		r0.Threshold != 0.1 || r0.WindowMinutes != 15 || r0.CooldownMinutes != 30 {
		t.Errorf("rule[0] = %+v", r0)
	}
	if a.Rules[1].Metric != "cost_usd" || a.Rules[1].Threshold != 5.0 {
		t.Errorf("rule[1] = %+v", a.Rules[1])
	}
}

func TestValidateRejectsBadAlertMetric(t *testing.T) {
	t.Parallel()
	c := Default()
	c.Observability.Enabled = true
	c.Observability.Alerts.Enabled = true
	c.Observability.Alerts.Rules = []ObservabilityAlertRuleConfig{
		{Name: "bad", Metric: "made_up", Threshold: 1},
	}
	if err := Validate(c); err == nil {
		t.Fatal("expected error for alerts rule metric=made_up")
	}
}

func TestValidateRejectsBadAlertComparator(t *testing.T) {
	t.Parallel()
	c := Default()
	c.Observability.Enabled = true
	c.Observability.Alerts.Enabled = true
	c.Observability.Alerts.Rules = []ObservabilityAlertRuleConfig{
		{Name: "bad", Metric: "cost_usd", Comparator: "lt", Threshold: 1},
	}
	if err := Validate(c); err == nil {
		t.Fatal("expected error for alerts rule comparator=lt")
	}
}

func TestValidateAcceptsDisabledAlertsWithBadRule(t *testing.T) {
	t.Parallel()
	c := Default()
	// Disabled alerting must never fail the daemon, even with a stale bad rule.
	c.Observability.Alerts.Enabled = false
	c.Observability.Alerts.Rules = []ObservabilityAlertRuleConfig{
		{Name: "stale", Metric: "made_up"},
	}
	if err := Validate(c); err != nil {
		t.Fatalf("disabled alerts should not validate rules: %v", err)
	}
}

// TestDashboardOrgAnnouncementsDefaults pins the rail-R3 opt-out
// (docs/plans/dashboard-announcements-banner-plan-2026-07-31.md §4):
// default-ON, explicitly overridable to false, and — the leg that
// actually bites — a PARTIAL [dashboard] section that sets only `addr`
// must NOT silently disable the rail (the cachetrack partial-merge
// bug class: every install that had ever set a dashboard address would
// have lost org announcements the day the key was added).
func TestDashboardOrgAnnouncementsDefaults(t *testing.T) {
	t.Parallel()
	if !Default().Dashboard.OrgAnnouncements {
		t.Error("[dashboard].org_announcements must default to true")
	}

	write := func(t *testing.T, body string) Config {
		t.Helper()
		cfgPath := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return cfg
	}

	if cfg := write(t, "[observer]\ndb_path = \"/tmp/x.db\"\n"); !cfg.Dashboard.OrgAnnouncements {
		t.Error("no [dashboard] section should keep the rail on")
	}
	if cfg := write(t, "[dashboard]\naddr = \"127.0.0.1:8099\"\n"); !cfg.Dashboard.OrgAnnouncements {
		t.Error("a partial [dashboard] section (addr only) silently disabled the org rail")
	}
	cfg := write(t, "[dashboard]\norg_announcements = false\n")
	if cfg.Dashboard.OrgAnnouncements {
		t.Error("org_announcements = false must override the default")
	}
}

// TestTerminalSandboxDefaults pins the B9 [terminal.sandbox] defaults (plan
// §5): the master switch defaults OFF, but the mechanism knobs are seeded
// to the documented v1 shape so flipping just `enabled = true` yields a
// usable config rather than zeros. Mirrors TestProcessObservabilityDefaults'
// "default-off feature with non-zero seeded sub-defaults" shape and
// TestPredictDefaults' partial-merge check.
func TestTerminalSandboxDefaults(t *testing.T) {
	t.Parallel()
	s := Default().Terminal.Sandbox
	if s.Enabled {
		t.Error("terminal.sandbox.enabled must default to false")
	}
	if s.Backend != "bwrap" {
		t.Errorf("terminal.sandbox.backend default = %q, want bwrap", s.Backend)
	}
	if s.HomeMode != "tmpfs" {
		t.Errorf("terminal.sandbox.home_mode default = %q, want tmpfs", s.HomeMode)
	}
	if s.DefaultOn {
		t.Error("terminal.sandbox.default_on must default to false")
	}
	if s.AllowRemoteClone {
		t.Error("terminal.sandbox.allow_remote_clone must default to false")
	}
	if len(s.RemoteAllowedHosts) != 0 {
		t.Errorf("terminal.sandbox.remote_allowed_hosts default = %v, want empty", s.RemoteAllowedHosts)
	}
	if s.AllowWorktreeSource {
		t.Error("terminal.sandbox.allow_worktree_source must default to false")
	}
	if s.WorkspacesDir != "" {
		t.Errorf("terminal.sandbox.workspaces_dir default = %q, want empty", s.WorkspacesDir)
	}
	if s.WorkspaceRetentionDays != 0 {
		t.Errorf("terminal.sandbox.workspace_retention_days default = %d, want 0", s.WorkspaceRetentionDays)
	}
	if len(s.MaskPaths) != 0 || len(s.ExtraROBinds) != 0 || len(s.ExtraRWBinds) != 0 {
		t.Errorf("terminal.sandbox bind-list defaults should be empty, got mask=%v ro=%v rw=%v", s.MaskPaths, s.ExtraROBinds, s.ExtraRWBinds)
	}
	if s.PrepTimeoutSeconds != 300 {
		t.Errorf("terminal.sandbox.prep_timeout_seconds default = %d, want 300", s.PrepTimeoutSeconds)
	}

	// Partial-merge: a [terminal.sandbox] section setting ONLY enabled=true
	// keeps the seeded mechanism defaults (backend/home_mode/timeout), the
	// same partial-merge discipline as [terminal.launch].allow_install and
	// [predict].
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[terminal.sandbox]\nenabled = true\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Terminal.Sandbox.Enabled {
		t.Error("enabled=true should override")
	}
	if cfg.Terminal.Sandbox.Backend != "bwrap" || cfg.Terminal.Sandbox.HomeMode != "tmpfs" || cfg.Terminal.Sandbox.PrepTimeoutSeconds != 300 {
		t.Errorf("partial [terminal.sandbox] lost mechanism defaults: %+v", cfg.Terminal.Sandbox)
	}
}
