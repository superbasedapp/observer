package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// errPrivacyTestBoom is a sentinel used to assert config-load failures
// propagate out of the command instead of being swallowed.
var errPrivacyTestBoom = errors.New("boom")

// TestBuildPrivacySocketsDefault pins the socket table against the
// zero-config default: proxy + dashboard are always active (proxy per F8
// — the listener binds regardless of [proxy].enabled), everything else
// opt-in and off, and no remote-access row at all (default [remote] is
// disabled).
func TestBuildPrivacySocketsDefault(t *testing.T) {
	cfg := config.Default()
	sockets := buildPrivacySockets(cfg)

	want := map[string]struct {
		addr   string
		active bool
	}{
		"proxy":             {"127.0.0.1:8820", true},
		"dashboard":         {"127.0.0.1:8081", true},
		"browser-ingest":    {"127.0.0.1:8821", false},
		"otlp-ingest":       {"127.0.0.1:4317 (gRPC), 127.0.0.1:4318 (HTTP)", false},
		"processobs-accept": {"127.0.0.1:8823", false},
	}

	if len(sockets) != len(want) {
		t.Fatalf("got %d sockets, want %d (default [remote] is disabled, so no remote-access row): %+v", len(sockets), len(want), sockets)
	}

	for _, s := range sockets {
		w, ok := want[s.Name]
		if !ok {
			t.Fatalf("unexpected socket row %q", s.Name)
		}
		if s.Addr != w.addr {
			t.Errorf("socket %q addr = %q, want %q", s.Name, s.Addr, w.addr)
		}
		if s.Active != w.active {
			t.Errorf("socket %q active = %v, want %v", s.Name, s.Active, w.active)
		}
		if s.Purpose == "" {
			t.Errorf("socket %q has empty Purpose", s.Name)
		}
	}
}

// TestBuildPrivacySocketsProxyAlwaysActive pins F8: cfg.Proxy.Enabled=false
// must NOT flip the proxy socket's Active — buildProxy is called
// unconditionally by both `observer start` and `observer proxy start`, and
// cfg.Proxy.Enabled only gates a port-range validation, never the listener.
func TestBuildPrivacySocketsProxyAlwaysActive(t *testing.T) {
	cfg := config.Default()
	cfg.Proxy.Enabled = false

	sockets := buildPrivacySockets(cfg)
	var proxyRow *privacySocket
	for i := range sockets {
		if sockets[i].Name == "proxy" {
			proxyRow = &sockets[i]
		}
	}
	if proxyRow == nil {
		t.Fatalf("expected a proxy socket row, got none: %+v", sockets)
	}
	if !proxyRow.Active {
		t.Errorf("proxy socket Active = false with [proxy].enabled=false, want true (the listener binds regardless — F8)")
	}
	if !strings.Contains(proxyRow.Purpose, "REGARDLESS of [proxy].enabled") {
		t.Errorf("proxy socket Purpose does not explain the [proxy].enabled honesty note: %q", proxyRow.Purpose)
	}
}

// TestBuildPrivacySocketsOTLPORGate pins F3: the OTLP socket is Active when
// EITHER [ingest.otel].enabled OR [observability].enabled is set — the two
// gates are ORed at cmd/observer/start.go's shared-receiver bind, not
// ANDed and not exclusively tied to [ingest.otel].
func TestBuildPrivacySocketsOTLPORGate(t *testing.T) {
	tests := []struct {
		name          string
		otelEnabled   bool
		obsEnabled    bool
		wantActive    bool
		wantSubstring string
	}{
		{name: "both off", otelEnabled: false, obsEnabled: false, wantActive: false},
		{name: "ingest.otel only", otelEnabled: true, obsEnabled: false, wantActive: true},
		{name: "observability only", otelEnabled: false, obsEnabled: true, wantActive: true},
		{name: "both on", otelEnabled: true, obsEnabled: true, wantActive: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Ingest.OTel.Enabled = tt.otelEnabled
			cfg.Observability.Enabled = tt.obsEnabled

			sockets := buildPrivacySockets(cfg)
			var row *privacySocket
			for i := range sockets {
				if sockets[i].Name == "otlp-ingest" {
					row = &sockets[i]
				}
			}
			if row == nil {
				t.Fatalf("expected an otlp-ingest row, got none: %+v", sockets)
			}
			if row.Active != tt.wantActive {
				t.Errorf("otlp-ingest active = %v, want %v", row.Active, tt.wantActive)
			}
			if !strings.Contains(row.Purpose, "trace receiver") {
				t.Errorf("otlp-ingest Purpose does not mention the trace receiver: %q", row.Purpose)
			}
		})
	}
}

// TestBuildPrivacySocketsRemoteBoundVsArmed pins F10: [remote].enabled=true
// alone only ARMS the substrate — the socket's Active must reflect whether
// an exposure mode resolved to a concrete BOUND address, never render
// "[on]" with no address.
func TestBuildPrivacySocketsRemoteBoundVsArmed(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		bindAddr   string
		tsAddr     string
		wantAddr   string
		wantActive bool
	}{
		{
			name:       "lan mode with bind addr — bound",
			mode:       "lan",
			bindAddr:   "192.168.1.5:8081",
			wantAddr:   "192.168.1.5:8081",
			wantActive: true,
		},
		{
			name:       "lan mode with no bind addr — armed but not bound",
			mode:       "lan",
			bindAddr:   "",
			wantAddr:   "(exposure mode not yet configured — substrate armed, nothing bound)",
			wantActive: false,
		},
		{
			name:       "tailscale mode with backend addr — bound",
			mode:       "tailscale",
			tsAddr:     "127.0.0.1:58123",
			wantAddr:   "127.0.0.1:58123 (tailnet-local backend, TLS terminated by tailscale serve)",
			wantActive: true,
		},
		{
			name:       "tailscale mode with no backend addr — armed but not bound",
			mode:       "tailscale",
			tsAddr:     "",
			wantAddr:   "(exposure mode not yet configured — substrate armed, nothing bound)",
			wantActive: false,
		},
		{
			name:       "enabled but no mode chosen yet — armed but not bound",
			mode:       "off",
			wantAddr:   "(exposure mode not yet configured — substrate armed, nothing bound)",
			wantActive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Remote.Enabled = true
			cfg.Remote.Mode = tt.mode
			cfg.Remote.BindAddr = tt.bindAddr
			cfg.Remote.TailscaleBackendAddr = tt.tsAddr

			sockets := buildPrivacySockets(cfg)
			var got *privacySocket
			for i := range sockets {
				if sockets[i].Name == "remote-access" {
					got = &sockets[i]
				}
			}
			if got == nil {
				t.Fatalf("expected a remote-access row when [remote].enabled=true, got none: %+v", sockets)
			}
			if got.Addr != tt.wantAddr {
				t.Errorf("remote-access addr = %q, want %q", got.Addr, tt.wantAddr)
			}
			if got.Active != tt.wantActive {
				t.Errorf("remote-access active = %v, want %v (bound-vs-armed honesty — F10)", got.Active, tt.wantActive)
			}
		})
	}
}

// TestRemoteSocketAddrHelper drives remoteSocketAddr directly for the
// bound/addr pairing it returns.
func TestRemoteSocketAddrHelper(t *testing.T) {
	cfg := config.Default()
	cfg.Remote.Mode = "lan"
	cfg.Remote.BindAddr = "10.0.0.5:9090"
	addr, bound := remoteSocketAddr(cfg)
	if addr != "10.0.0.5:9090" || !bound {
		t.Errorf("remoteSocketAddr(lan bound) = (%q, %v), want (%q, true)", addr, bound, "10.0.0.5:9090")
	}

	cfg.Remote.Mode = "lan"
	cfg.Remote.BindAddr = ""
	addr, bound = remoteSocketAddr(cfg)
	if bound {
		t.Errorf("remoteSocketAddr(lan, no bind addr) bound = true, want false; addr=%q", addr)
	}
}

// TestBuildPrivacySocketsNonLoopbackHonesty pins F11: no socket's Purpose
// claims unique non-loopback capability, and every socket with its own
// allow_non_loopback escape hatch names it.
func TestBuildPrivacySocketsNonLoopbackHonesty(t *testing.T) {
	cfg := config.Default()
	cfg.Remote.Enabled = true
	cfg.Remote.Mode = "lan"
	cfg.Remote.BindAddr = "10.0.0.1:8081"

	sockets := buildPrivacySockets(cfg)

	wantEscapeHatch := map[string]bool{
		"browser-ingest":    true,
		"otlp-ingest":       true,
		"processobs-accept": true,
	}
	for _, s := range sockets {
		if strings.Contains(s.Purpose, "ONE listener") || strings.Contains(s.Purpose, "only listener") {
			t.Errorf("socket %q Purpose claims unique non-loopback capability, want that claim removed (F11): %q", s.Name, s.Purpose)
		}
		if wantEscapeHatch[s.Name] && !strings.Contains(s.Purpose, "allow_non_loopback") {
			t.Errorf("socket %q Purpose does not name its own allow_non_loopback escape hatch: %q", s.Name, s.Purpose)
		}
	}
}

// TestBuildPrivacyEgressDefault pins the egress table against the
// zero-config default: the always-on listener rows (proxy forwarding, TLS
// pre-warm — default prewarm_targets is non-empty) report active; every
// opt-in feature, including the four new F2 rows, reports inactive.
func TestBuildPrivacyEgressDefault(t *testing.T) {
	cfg := config.Default()
	rows := buildPrivacyEgress(cfg)

	wantActive := map[string]bool{
		"proxy forwarding":                     true,
		"Teams org push + policy poll":         false,
		"dashboard update check":               false,
		"org update manifest + artifact fetch": false,
		"observer summarize":                   false,
		"aggregate-share rail":                 false,
		"OTel exporter":                        false,
		"generalized observability (Plane A)":  false,
		"email / digest alerts":                false,
		"remote-access notify":                 false,
		"TLS pre-warm":                         true,
		"guard cloud webhooks":                 false,
		"guard cloud LLM judge":                false,
		"guard cloud reputation lookup":        false,
		"rolling conversation summarization":   false,
	}

	if len(rows) != len(wantActive) {
		t.Fatalf("got %d egress rows, want %d: %+v", len(rows), len(wantActive), rows)
	}

	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.Name] = true
		want, ok := wantActive[r.Name]
		if !ok {
			t.Fatalf("unexpected egress row %q", r.Name)
		}
		if r.Active != want {
			t.Errorf("egress %q active = %v, want %v", r.Name, r.Active, want)
		}
		if r.Gate == "" {
			t.Errorf("egress %q has empty Gate", r.Name)
		}
		if r.Detail == "" {
			t.Errorf("egress %q has empty Detail", r.Name)
		}
	}
	for name := range wantActive {
		if !seen[name] {
			t.Errorf("missing expected egress row %q", name)
		}
	}
}

// TestBuildPrivacyEgressTLSPrewarm pins F1: Active tracks
// len(cfg.Proxy.PrewarmTargets) > 0, and the Detail lists the configured
// targets (or the empty placeholder when explicitly emptied).
func TestBuildPrivacyEgressTLSPrewarm(t *testing.T) {
	tests := []struct {
		name       string
		targets    []string
		wantActive bool
		wantDetail string
	}{
		{
			name:       "default targets",
			targets:    []string{"https://chatgpt.com/", "https://api.openai.com/"},
			wantActive: true,
			wantDetail: "https://chatgpt.com/, https://api.openai.com/",
		},
		{
			name:       "explicit empty disables",
			targets:    []string{},
			wantActive: false,
			wantDetail: "(none configured)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Proxy.PrewarmTargets = tt.targets

			rows := buildPrivacyEgress(cfg)
			row := findEgressRow(t, rows, "TLS pre-warm")
			if row.Active != tt.wantActive {
				t.Errorf("TLS pre-warm active = %v, want %v", row.Active, tt.wantActive)
			}
			if !strings.Contains(row.Detail, tt.wantDetail) {
				t.Errorf("TLS pre-warm detail = %q, want substring %q", row.Detail, tt.wantDetail)
			}
			if !strings.Contains(row.Detail, "No session data") {
				t.Errorf("TLS pre-warm detail does not disclaim session data: %q", row.Detail)
			}
		})
	}
}

// TestBuildPrivacyEgressGuardCloudWebhooks pins F2's compound gate: both
// the sweep-dispatcher master gate (guard.enabled + mode != off +
// guard.cloud.enabled) AND at least one webhook URL must hold.
func TestBuildPrivacyEgressGuardCloudWebhooks(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*config.Config)
		wantActive bool
	}{
		{
			name:       "nothing set",
			mutate:     func(c *config.Config) {},
			wantActive: false,
		},
		{
			name: "cloud enabled, no webhook url",
			mutate: func(c *config.Config) {
				c.Guard.Cloud.Enabled = true
			},
			wantActive: false,
		},
		{
			name: "cloud enabled + webhook url, but mode off",
			mutate: func(c *config.Config) {
				c.Guard.Cloud.Enabled = true
				c.Guard.Cloud.Webhooks = []config.GuardWebhookConfig{{URL: "https://hooks.example/x", Kind: "generic"}}
				c.Guard.Mode = "off"
			},
			wantActive: false,
		},
		{
			name: "cloud enabled + webhook url, guard disabled",
			mutate: func(c *config.Config) {
				c.Guard.Enabled = false
				c.Guard.Cloud.Enabled = true
				c.Guard.Cloud.Webhooks = []config.GuardWebhookConfig{{URL: "https://hooks.example/x", Kind: "generic"}}
			},
			wantActive: false,
		},
		{
			name: "fully armed",
			mutate: func(c *config.Config) {
				c.Guard.Cloud.Enabled = true
				c.Guard.Cloud.Webhooks = []config.GuardWebhookConfig{{URL: "https://hooks.example/x", Kind: "generic"}}
			},
			wantActive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			tt.mutate(&cfg)
			rows := buildPrivacyEgress(cfg)
			row := findEgressRow(t, rows, "guard cloud webhooks")
			if row.Active != tt.wantActive {
				t.Errorf("guard cloud webhooks active = %v, want %v", row.Active, tt.wantActive)
			}
		})
	}
}

// TestBuildPrivacyEgressGuardCloudLLMJudge pins F2's LLM-judge row against
// the same sweep-dispatcher master gate plus its own per-feature enable.
func TestBuildPrivacyEgressGuardCloudLLMJudge(t *testing.T) {
	cfg := config.Default()
	cfg.Guard.Cloud.Enabled = true
	cfg.Guard.Cloud.LLMJudge.Enabled = true
	cfg.Guard.Cloud.LLMJudge.Endpoint = "https://judge.example/v1/chat/completions"

	rows := buildPrivacyEgress(cfg)
	row := findEgressRow(t, rows, "guard cloud LLM judge")
	if !row.Active {
		t.Errorf("guard cloud LLM judge active = false, want true when fully armed")
	}
	if !strings.Contains(row.Detail, "https://judge.example/v1/chat/completions") {
		t.Errorf("guard cloud LLM judge detail does not include the configured endpoint: %q", row.Detail)
	}

	// Master gate off (guard.cloud.enabled=false) must still flip Active
	// off even with LLMJudge.Enabled=true.
	cfg2 := config.Default()
	cfg2.Guard.Cloud.LLMJudge.Enabled = true
	rows2 := buildPrivacyEgress(cfg2)
	row2 := findEgressRow(t, rows2, "guard cloud LLM judge")
	if row2.Active {
		t.Errorf("guard cloud LLM judge active = true with [guard.cloud].enabled=false, want false")
	}
}

// TestBuildPrivacyEgressGuardCloudReputation pins F2's reputation row: it
// does NOT depend on [guard].enabled/mode or the sweep dispatcher — only
// its own double opt-in ([guard.cloud].enabled + [guard.cloud.reputation].enabled).
func TestBuildPrivacyEgressGuardCloudReputation(t *testing.T) {
	cfg := config.Default()
	cfg.Guard.Enabled = false // sweep dispatcher master gate OFF
	cfg.Guard.Cloud.Enabled = true
	cfg.Guard.Cloud.Reputation.Enabled = true

	rows := buildPrivacyEgress(cfg)
	row := findEgressRow(t, rows, "guard cloud reputation lookup")
	if !row.Active {
		t.Errorf("guard cloud reputation lookup active = false with double opt-in set (guard.enabled irrelevant), want true")
	}

	cfg2 := config.Default()
	cfg2.Guard.Cloud.Enabled = true
	rows2 := buildPrivacyEgress(cfg2) // Reputation.Enabled still false
	row2 := findEgressRow(t, rows2, "guard cloud reputation lookup")
	if row2.Active {
		t.Errorf("guard cloud reputation lookup active = true without [guard.cloud.reputation].enabled, want false")
	}
}

// TestBuildPrivacyEgressRollingSummarization pins F2's rolling-summary row:
// it tracks [compression.conversation.rolling].enabled directly,
// independent of [compression.conversation].enabled itself (matching
// cmd/observer/proxy_profiles.go's direct Rolling.Enabled check).
func TestBuildPrivacyEgressRollingSummarization(t *testing.T) {
	cfg := config.Default()
	cfg.Compression.Conversation.Enabled = false
	cfg.Compression.Conversation.Rolling.Enabled = true
	cfg.Compression.Conversation.Rolling.SummaryModel = "claude-haiku-4-5"
	cfg.Compression.Conversation.Rolling.OpenAISummaryModel = "gpt-5-nano"

	rows := buildPrivacyEgress(cfg)
	row := findEgressRow(t, rows, "rolling conversation summarization")
	if !row.Active {
		t.Errorf("rolling conversation summarization active = false with Rolling.Enabled=true (Conversation.Enabled=false), want true")
	}
	if !strings.Contains(row.Detail, "claude-haiku-4-5") || !strings.Contains(row.Detail, "gpt-5-nano") {
		t.Errorf("rolling conversation summarization detail missing model names: %q", row.Detail)
	}
}

// TestBuildPrivacyEgressArmedVsEffective pins F9: the Teams org-push and
// aggregate-share rows' Gate text must name the out-of-band credential
// this report cannot verify, and must say so explicitly.
func TestBuildPrivacyEgressArmedVsEffective(t *testing.T) {
	cfg := config.Default()
	rows := buildPrivacyEgress(cfg)

	orgRow := findEgressRow(t, rows, "Teams org push + policy poll")
	if !strings.Contains(orgRow.Gate, "Active reflects only this config flag") {
		t.Errorf("org push Gate missing the armed-vs-effective honesty clause: %q", orgRow.Gate)
	}
	if !strings.Contains(orgRow.Gate, "observer org status") {
		t.Errorf("org push Gate does not point at `observer org status`: %q", orgRow.Gate)
	}

	aggRow := findEgressRow(t, rows, "aggregate-share rail")
	if !strings.Contains(aggRow.Gate, "Active reflects only this config flag") {
		t.Errorf("aggregate-share Gate missing the armed-vs-effective honesty clause: %q", aggRow.Gate)
	}
	if !strings.Contains(aggRow.Gate, "observer aggregate status") {
		t.Errorf("aggregate-share Gate does not point at `observer aggregate status`: %q", aggRow.Gate)
	}
}

// TestBuildPrivacyEgressRemoteNotifyGate pins F4: the remote-access-notify
// row's gate is [remote.notify].enabled ALONE — [remote].enabled must play
// no part, because cmd/observer/attach_standalone.go wires OnExit for
// every terminal session, not just remote ones.
func TestBuildPrivacyEgressRemoteNotifyGate(t *testing.T) {
	tests := []struct {
		name          string
		remoteEnabled bool
		notifyEnabled bool
		wantActive    bool
	}{
		{name: "both off", remoteEnabled: false, notifyEnabled: false, wantActive: false},
		{name: "remote on, notify off", remoteEnabled: true, notifyEnabled: false, wantActive: false},
		{name: "remote off, notify on — still fires (F4)", remoteEnabled: false, notifyEnabled: true, wantActive: true},
		{name: "both on", remoteEnabled: true, notifyEnabled: true, wantActive: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Remote.Enabled = tt.remoteEnabled
			cfg.Remote.Notify.Enabled = tt.notifyEnabled

			rows := buildPrivacyEgress(cfg)
			row := findEgressRow(t, rows, "remote-access notify")
			if row.Active != tt.wantActive {
				t.Errorf("remote-access notify active = %v, want %v", row.Active, tt.wantActive)
			}
		})
	}
	// The gate text itself must not require [remote].enabled.
	cfg := config.Default()
	rows := buildPrivacyEgress(cfg)
	row := findEgressRow(t, rows, "remote-access notify")
	if !strings.Contains(row.Gate, "[remote.notify].enabled") {
		t.Errorf("remote-access notify Gate does not name [remote.notify].enabled: %q", row.Gate)
	}
	if !strings.Contains(row.Gate, "NOT part of this gate") {
		t.Errorf("remote-access notify Gate does not disclaim [remote].enabled: %q", row.Gate)
	}
}

// TestBuildPrivacyEgressGatedRowsFlipActive drives each simple opt-in
// egress gate individually and asserts only that row's Active flips
// (alongside the always-on proxy-forwarding + TLS-pre-warm rows).
func TestBuildPrivacyEgressGatedRowsFlipActive(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*config.Config)
		rowName    string
		alsoActive []string
	}{
		{
			name: "org client enabled",
			mutate: func(c *config.Config) {
				c.OrgClient.Enabled = true
				c.OrgClient.OrgServerURL = "https://org.example"
			},
			rowName: "Teams org push + policy poll",
			// Enrolling arms TWO rails, not one: the push/poll above and the
			// update manifest fetch, which rides the same connection to the
			// same host and is gated on the same enrolment (ruling R8).
			alsoActive: []string{"org update manifest + artifact fetch"},
		},
		{
			name:    "aggregate share enabled",
			mutate:  func(c *config.Config) { c.AggregateShare.Enabled = true },
			rowName: "aggregate-share rail",
		},
		{
			name:    "otel exporter enabled",
			mutate:  func(c *config.Config) { c.Exporter.OTel.Enabled = true },
			rowName: "OTel exporter",
		},
		{
			name:    "observability enabled",
			mutate:  func(c *config.Config) { c.Observability.Enabled = true },
			rowName: "generalized observability (Plane A)",
		},
		{
			name:    "email enabled",
			mutate:  func(c *config.Config) { c.Email.Enabled = true },
			rowName: "email / digest alerts",
		},
		{
			name:    "remote notify enabled (alone — F4)",
			mutate:  func(c *config.Config) { c.Remote.Notify.Enabled = true },
			rowName: "remote-access notify",
		},
	}

	alwaysOn := map[string]bool{
		"proxy forwarding": true,
		"TLS pre-warm":     true,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			tt.mutate(&cfg)
			rows := buildPrivacyEgress(cfg)

			also := map[string]bool{}
			for _, n := range tt.alsoActive {
				also[n] = true
			}
			for _, r := range rows {
				want := r.Name == tt.rowName || alwaysOn[r.Name] || also[r.Name]
				if r.Active != want {
					t.Errorf("row %q active = %v, want %v (only %q plus the always-on rows should be active)", r.Name, r.Active, want, tt.rowName)
				}
			}
		})
	}
}

// TestBuildPrivacyReportSchemaAndDocsURL pins the top-level envelope
// fields that JSON consumers (the website artifact, tooling) depend on.
func TestBuildPrivacyReportSchemaAndDocsURL(t *testing.T) {
	report := buildPrivacyReport(config.Default())
	if report.Schema != privacyJSONSchema {
		t.Errorf("Schema = %q, want %q", report.Schema, privacyJSONSchema)
	}
	if report.DocsURL == "" {
		t.Errorf("DocsURL is empty")
	}
	if len(report.Sockets) == 0 {
		t.Errorf("Sockets is empty")
	}
	if len(report.Egress) != 15 {
		t.Errorf("Egress len = %d, want 15", len(report.Egress))
	}
}

// TestPrivacyCmdJSONOutput drives the cobra command end to end with an
// injected config and asserts the --json output round-trips into the same
// shape buildPrivacyReport produces directly.
func TestPrivacyCmdJSONOutput(t *testing.T) {
	cfg := config.Default()
	cfg.OrgClient.Enabled = true
	cfg.OrgClient.OrgServerURL = "https://org.example"

	deps := privacyDeps{loadConfig: func() (config.Config, error) { return cfg, nil }}
	cmd := newPrivacyCmdWith(deps)
	cmd.SetArgs([]string{"--json"})

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	var got privacyReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal output: %v\noutput: %s", err, out.String())
	}

	want := buildPrivacyReport(cfg)
	if got.Schema != want.Schema {
		t.Errorf("Schema = %q, want %q", got.Schema, want.Schema)
	}
	if len(got.Sockets) != len(want.Sockets) {
		t.Errorf("Sockets len = %d, want %d", len(got.Sockets), len(want.Sockets))
	}
	if len(got.Egress) != len(want.Egress) {
		t.Errorf("Egress len = %d, want %d", len(got.Egress), len(want.Egress))
	}
}

// TestPrivacyCmdTextOutput drives the cobra command's default (non-JSON)
// path and checks the honesty-critical strings are present: every row
// name, the four new F2 rows, and the QUALIFIED closing "no automatic
// phone-home" line (F1).
func TestPrivacyCmdTextOutput(t *testing.T) {
	cfg := config.Default()
	deps := privacyDeps{loadConfig: func() (config.Config, error) { return cfg, nil }}
	cmd := newPrivacyCmdWith(deps)
	cmd.SetArgs(nil)

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	text := out.String()
	for _, want := range []string{
		"Listening sockets",
		"Outbound network paths",
		"proxy",
		"dashboard",
		"Teams org push + policy poll",
		"TLS pre-warm",
		"guard cloud webhooks",
		"guard cloud LLM judge",
		"guard cloud reputation lookup",
		"rolling conversation summarization",
		"the one automatic call is",
		"TLS pre-warm HEAD request",
		privacyDocsURL,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output missing %q\noutput:\n%s", want, text)
		}
	}
	// The old unqualified claim must be gone.
	if strings.Contains(text, "No telemetry, no analytics, no crash reporting, no automatic phone-home.") {
		t.Errorf("output still carries the UNQUALIFIED phone-home claim, want it qualified by the TLS pre-warm exception (F1)")
	}
}

// TestPrivacyCmdLongTextQualifiesPhoneHomeClaim pins F1's Long-help half of
// the qualification.
func TestPrivacyCmdLongTextQualifiesPhoneHomeClaim(t *testing.T) {
	cmd := newPrivacyCmd()
	if !strings.Contains(cmd.Long, "one narrow exception") {
		t.Errorf("Long help does not name the TLS pre-warm exception: %q", cmd.Long)
	}
	if !strings.Contains(cmd.Long, "TLS pre-warm") {
		t.Errorf("Long help does not mention TLS pre-warm: %q", cmd.Long)
	}
}

// TestPrivacyCmdLoadConfigError propagates a config-load failure instead
// of silently rendering an empty/default report.
func TestPrivacyCmdLoadConfigError(t *testing.T) {
	deps := privacyDeps{loadConfig: func() (config.Config, error) {
		return config.Config{}, errPrivacyTestBoom
	}}
	cmd := newPrivacyCmdWith(deps)
	cmd.SetArgs(nil)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.Execute(); err == nil {
		t.Fatalf("Execute: expected an error, got nil")
	}
}

// findEgressRow is a small test helper: locate a row by name or fail.
func findEgressRow(t *testing.T, rows []privacyEgress, name string) privacyEgress {
	t.Helper()
	for _, r := range rows {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no egress row named %q in %+v", name, rows)
	return privacyEgress{}
}

// TestBuildPrivacyEgressTeamsPollIsDisclosedAsObservable pins security
// finding 4. The per-cycle GET /api/agent/announcement is a
// server-observable signal — inherent to any fetch rail, covered by the
// consent enrolment already implies, and impossible for a node-side
// switch to remove ([dashboard].org_announcements silences the BANNER,
// not the request). The one thing it must not be is silent, so the row
// says it out loud, next to the same statement about the push.
func TestBuildPrivacyEgressTeamsPollIsDisclosedAsObservable(t *testing.T) {
	cfg := config.Default()
	row := findEgressRow(t, buildPrivacyEgress(cfg), "Teams org push + policy poll")

	// The announcement fetch is named at all…
	if !strings.Contains(row.Detail, "announcement") {
		t.Fatalf("Teams row does not mention the announcement fetch: %q", row.Detail)
	}
	// …and its server-observability is stated, not implied by silence.
	for _, want := range []string{"can SEE the request", "poll"} {
		if !strings.Contains(row.Detail, want) {
			t.Errorf("Teams row does not disclose that the poll itself is observable (missing %q): %q", want, row.Detail)
		}
	}
	// The honest counterpart stays: no read receipt exists.
	if !strings.Contains(row.Detail, "acknowledgment wire") {
		t.Errorf("Teams row dropped the no-read-receipt statement: %q", row.Detail)
	}
}
