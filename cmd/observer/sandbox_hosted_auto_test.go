//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_hosted_auto_test.go pins decisions SBXD-1, SBXD-3 and SBXD-4
// (docs/decisions/sandbox-terminal-decisions-2026-11.md) at the cmd seams:
// the per-tool line under auto, the selection custody, the consent facts
// and the per-tool settings.

// TestHostedKeyNoticeAuto: under auto every tool gets a line naming the
// custody it resolved to, none blocks, the paste offer names the provider
// that would keep the key home, and the in-box sources show only when the
// key goes in the box.
func TestHostedKeyNoticeAuto(t *testing.T) {
	nothing := sandboxcred.HomeKeyFacts{Custody: "auto", InjectionSelected: true, InjectionBuilt: true}
	stored := nothing
	stored.StoredProviders = []string{"openai"}
	cases := []struct {
		name     string
		facts    sandboxcred.HomeKeyFacts
		tool     string
		custody  string
		keepHome []string
		toolKeys bool
	}{
		{"opencode with no key: in the box, offer OpenAI to keep it home", nothing, "opencode", "in_box_api_key", []string{"openai"}, true},
		{"opencode with its OpenAI key stored: kept home", stored, "opencode", "home_relay", nil, false},
		{"claude-code with no Anthropic key: in the box, offer it", stored, "claude-code", "in_box_api_key", []string{"anthropic"}, false},
		{"droid (no proxy route): in the box, nothing to offer", stored, "droid", "in_box_api_key", nil, false},
	}
	for _, tc := range cases {
		n := hostedKeyNoticeFor(tc.facts, config.TerminalSandboxHostedConfig{}, tc.tool)
		if n == nil || n.Severity != dashapi.SandboxKeyAdvisory || n.Custody != tc.custody || n.Message == "" {
			t.Fatalf("%s: notice %+v", tc.name, n)
		}
		var offered []string
		for _, p := range n.KeepHome {
			offered = append(offered, p.ID)
			if p.Label == "" {
				t.Errorf("%s: offer %+v has no label", tc.name, p)
			}
		}
		if strings.Join(offered, ",") != strings.Join(tc.keepHome, ",") {
			t.Errorf("%s: keep-home offers %v, want %v", tc.name, offered, tc.keepHome)
		}
		if (n.ToolKeys != nil) != tc.toolKeys || n.LoginSeed != nil && tc.tool != "claude-code" {
			t.Errorf("%s: sources %+v %+v", tc.name, n.ToolKeys, n.LoginSeed)
		}
		for _, b := range []string{"home_relay", "in_box", "auto", "`", "["} {
			if strings.Contains(n.Message, b) {
				t.Errorf("%s: the line %q carries %q", tc.name, n.Message, b)
			}
		}
	}
	// The per-tool value wins, and the line says it was chosen in settings.
	hc := config.TerminalSandboxHostedConfig{KeyCustodyByTool: map[string]string{"opencode": "in_box_api_key"}, ToolKeys: map[string]bool{"opencode": true}}
	n := hostedKeyNoticeFor(stored, hc, "opencode")
	if n == nil || n.Custody != "in_box_api_key" || !strings.Contains(n.Message, "settings") || n.ToolKeys == nil || !n.ToolKeys.On || !strings.Contains(n.Message, "OpenCode saved itself") {
		t.Fatalf("per-tool in-box with saved keys: %+v", n)
	}
	// An explicit home_relay node sees exactly the old line (none for a
	// served one-provider tool).
	old := sandboxcred.HomeKeyFacts{Custody: "home_relay", InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"anthropic"}}
	if n := hostedKeyNoticeFor(old, config.TerminalSandboxHostedConfig{}, "claude-code"); n != nil {
		t.Fatalf("explicit home_relay, served: %+v", n)
	}
}

// TestHostedSelectionCustody: a selection with no tool reads an explicit
// custody as set, and auto as the custody it can fall back to.
func TestHostedSelectionCustody(t *testing.T) {
	vendor, _ := sandboxbackend.Get(sandboxbackend.BackendDaytona)
	org, _ := sandboxbackend.Get(sandboxbackend.BackendOpenShellOrg)
	cases := []struct {
		custody vocab.KeyCustody
		row     sandboxbackend.Capability
		want    vocab.KeyCustody
	}{
		{vocab.CustodyHomeRelay, vendor, vocab.CustodyHomeRelay},
		{vocab.CustodyInBoxAPIKey, vendor, vocab.CustodyInBoxAPIKey},
		{vocab.CustodyAuto, vendor, vocab.CustodyInBoxAPIKey},
		{vocab.CustodyAuto, org, vocab.CustodyHomeRelay},
		{vocab.CustodyInBoxAPIKey, org, vocab.CustodyInBoxAPIKey}, // its probe row R2 refuses it
	}
	for _, tc := range cases {
		if got := hostedSelectionCustody(tc.custody, tc.row); got != tc.want {
			t.Errorf("%s on %s: %s, want %s", tc.custody, tc.row.ID, got, tc.want)
		}
	}
	if !hostedRowRefusesInBox(org) || hostedRowRefusesInBox(vendor) {
		t.Fatal("the org-hosted row keeps every key home; the vendor rows offer in-box")
	}
}

// TestHostedConsentCustodyFact: the consent's custody fact is the node
// value exactly (as every record had) unless a per-tool value is set.
func TestHostedConsentCustodyFact(t *testing.T) {
	for _, c := range []string{"home_relay", "auto", "in_box_api_key"} {
		if got := hostedConsentCustody(config.TerminalSandboxHostedConfig{KeyCustody: c}); got != c {
			t.Errorf("%s: %q", c, got)
		}
	}
	got := hostedConsentCustody(config.TerminalSandboxHostedConfig{KeyCustody: "auto", KeyCustodyByTool: map[string]string{"droid": "in_box_api_key", "codex": "home_relay"}})
	if got != "auto; codex=home_relay,droid=in_box_api_key" {
		t.Fatalf("with per-tool values: %q", got)
	}
}

// TestHostedConsentStoredKeySet (decision SBXD-3): storing a key never
// reopens a home_relay node's consent, and reopens an in-box (or auto)
// node's naming the stored-key field; the opted-in sources bind the same
// way.
func TestHostedConsentStoredKeySet(t *testing.T) {
	facts := func(hc config.TerminalSandboxHostedConfig, stored []string, refused bool) sandboxremote.ConsentFacts {
		f := sandboxremote.ConsentFacts{Provider: "daytona", Custody: hostedConsentCustody(hc)}
		f.InBoxKeys, f.ToolKeys, f.LoginSeed = hostedConsentKeyFacts(hc, true, stored, refused)
		return f
	}
	for _, tc := range []struct {
		name    string
		hc      config.TerminalSandboxHostedConfig
		refused bool
		want    string
	}{
		{"home_relay node", config.TerminalSandboxHostedConfig{KeyCustody: "home_relay"}, false, sandboxremote.ConsentOK},
		{"in-box node", config.TerminalSandboxHostedConfig{KeyCustody: "in_box_api_key"}, false, sandboxremote.ConsentChangedPrefix + "in_box_keys"},
		{"auto node", config.TerminalSandboxHostedConfig{KeyCustody: "auto"}, false, sandboxremote.ConsentChangedPrefix + "in_box_keys"},
		{"auto on the row that keeps keys home", config.TerminalSandboxHostedConfig{KeyCustody: "auto"}, true, sandboxremote.ConsentOK},
		{"home_relay node with one tool in the box", config.TerminalSandboxHostedConfig{KeyCustody: "home_relay", KeyCustodyByTool: map[string]string{"droid": "in_box_api_key"}}, false, sandboxremote.ConsentChangedPrefix + "in_box_keys"},
	} {
		before := facts(tc.hc, nil, tc.refused)
		rec := sandboxremote.NewConsent(before, "t")
		after := facts(tc.hc, []string{"openai"}, tc.refused)
		if v := sandboxremote.CheckConsent(&rec, after); v != tc.want {
			t.Errorf("%s: storing a key: %s, want %s", tc.name, v, tc.want)
		}
	}
	// Opting a tool in to its own saved keys or its login reopens an in-box
	// node's consent, and is inert on a home_relay node.
	inBox := config.TerminalSandboxHostedConfig{KeyCustody: "in_box_api_key"}
	rec := sandboxremote.NewConsent(facts(inBox, nil, false), "t")
	inBox.ToolKeys = map[string]bool{"opencode": true}
	if v := sandboxremote.CheckConsent(&rec, facts(inBox, nil, false)); v != sandboxremote.ConsentChangedPrefix+"tool_keys" {
		t.Errorf("opting OpenCode in: %s", v)
	}
	inBox.LoginSeed = map[string]bool{"claude-code": true}
	if _, _, l := hostedConsentKeyFacts(inBox, true, nil, false); l != "claude-code" {
		t.Errorf("login seed fact %q", l)
	}
	home := config.TerminalSandboxHostedConfig{KeyCustody: "home_relay", ToolKeys: map[string]bool{"opencode": true}}
	if a, b, c := hostedConsentKeyFacts(home, true, []string{"openai"}, false); a+b+c != "" {
		t.Errorf("a home_relay node binds %q %q %q", a, b, c)
	}
}

// TestHostedConsentChangeWords: each new consent field has plain words.
func TestHostedConsentChangeWords(t *testing.T) {
	for _, f := range []string{"in_box_keys", "tool_keys", "login_seed"} {
		why := consentChangeReason(sandboxremote.ConsentChangedPrefix + f)
		if strings.Contains(why, "your settings changed") || strings.Contains(why, "_") {
			t.Errorf("%s: %q", f, why)
		}
	}
}

// TestHostedConsentCaptureAuto: under auto the consent states both capture
// levels when they differ, and one where the row keeps every key home.
func TestHostedConsentCaptureAuto(t *testing.T) {
	got := hostedConsentCapture(sandboxbackend.BackendDaytona, vocab.TierInternet, vocab.CustodyAuto)
	home := hostedConsentCapture(sandboxbackend.BackendDaytona, vocab.TierInternet, vocab.CustodyHomeRelay)
	box := hostedConsentCapture(sandboxbackend.BackendDaytona, vocab.TierInternet, vocab.CustodyInBoxAPIKey)
	if home != box && !strings.Contains(got, "when the key stays on this machine") {
		t.Fatalf("auto capture %q (home %q, box %q)", got, home, box)
	}
	if home == box && got != home {
		t.Fatalf("auto capture %q, want %q", got, home)
	}
	if got := hostedConsentCapture(sandboxbackend.BackendOpenShellOrg, vocab.TierInternet, vocab.CustodyAuto); strings.Contains(got, "in the box") {
		t.Fatalf("the org-hosted row under auto: %q", got)
	}
}

// TestHostedLaunchCustodyAuto: under the default auto, Create's own
// resolution keeps the key home for a tool this machine serves and puts it
// in the box for one it does not, so no launch is refused on its custody;
// the org-hosted row resolves to home_relay.
func TestHostedLaunchCustodyAuto(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	hostedTestEnv(t, map[string]string{"E2B_API_KEY": "e2b_FAKEKEY_000111"})
	t.Cleanup(func() { hostedListed.Store(false) })
	calls := 0
	cfg := hostedTestConfig(sandboxbackend.BackendE2B)
	if cfg.Hosted.KeyCustody != string(vocab.CustodyAuto) {
		t.Fatalf("the default custody is %q", cfg.Hosted.KeyCustody)
	}
	d := hostedTestDriver(t, sandboxbackend.BackendE2B, cfg, &calls)
	d.homeKey = sandboxcred.HomeKeyFacts{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"anthropic"}}
	d.full = nil
	for tool, want := range map[string]vocab.KeyCustody{"claude-code": vocab.CustodyHomeRelay, "droid": vocab.CustodyInBoxAPIKey, "codex": vocab.CustodyInBoxAPIKey} {
		got, v, _ := d.hostedLaunchCustody(tool)
		if got != want || !v.OK {
			t.Errorf("%s: %s (%+v), want %s served", tool, got, v, want)
		}
	}
	d.cfg.KeyCustodyByTool = map[string]string{"claude-code": "in_box_api_key"}
	if got, _, _ := d.hostedLaunchCustody("claude-code"); got != vocab.CustodyInBoxAPIKey {
		t.Errorf("the per-tool value: %s", got)
	}
	org := hostedTestDriver(t, sandboxbackend.BackendE2B, cfg, &calls)
	org.vendor.ID = sandboxbackend.BackendOpenShellOrg
	org.full = nil
	if got, v, _ := org.hostedLaunchCustody("droid"); got != vocab.CustodyHomeRelay || v.OK {
		t.Errorf("auto on the org-hosted row: %s %+v, want home_relay refused (nothing serves it)", got, v)
	}
}
