//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// sandbox_hosted_custody_test.go pins the hosted model key custody fix
// (docs/audits/hosted-sandbox-key-custody-2026-11-18.md): the setup
// checklist, the probe, the per-tool line of the sandbox probe and Create
// all answer from the one table (sandboxcred.HomeKey), so a checklist that
// reads ready never meets a custody refusal at Start.

// TestHostedCustodySpellings: the table's custody strings are the
// vocabulary's (sandboxcred spells them to stay free of the vocab package).
func TestHostedCustodySpellings(t *testing.T) {
	cases := []struct {
		custody vocab.KeyCustody
		code    string
	}{
		{vocab.CustodyInBoxAPIKey, sandboxcred.HomeKeyServedInBox},
		{vocab.CustodyInBoxOAuthSeed, sandboxcred.HomeKeyLoginNotBuilt},
		{vocab.CustodyProviderInjected, sandboxcred.HomeKeyCustodyNotOffered},
		{vocab.CustodyHomeRelay, sandboxcred.HomeKeyNothingServes},
	}
	for _, tc := range cases {
		if got := sandboxcred.HomeKey(sandboxcred.HomeKeyFacts{Custody: string(tc.custody)}).Code; got != tc.code {
			t.Errorf("%s: code %s, want %s", tc.custody, got, tc.code)
		}
	}
	if sandboxcred.VerdictCode != verdictHostedCustody {
		t.Errorf("the table's refusal code %q is not the selection table's %q", sandboxcred.VerdictCode, verdictHostedCustody)
	}
}

// TestHostedKeyNoticePerTool: the per-tool line names a tool whose model key
// injection cannot serve, from the tool's capability row, never its name.
func TestHostedKeyNoticePerTool(t *testing.T) {
	ready := sandboxcred.HomeKeyFacts{Custody: "home_relay", InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"anthropic"}}
	inBox := sandboxcred.HomeKeyFacts{Custody: "in_box_api_key"}
	inBoxEnv := inBox
	inBoxEnv.InBoxEnvProviders = []string{"openai"}
	cases := []struct {
		name     string
		facts    sandboxcred.HomeKeyFacts
		tool     string
		code     string // "" for no notice
		severity string
	}{
		{"one provider, key stored", ready, "claude-code", "", ""},
		{"one provider, no key", ready, "codex", sandboxcred.HomeKeyToolKeyMissing, dashapi.SandboxKeyBlocking},
		{"a tool that picks its own provider gets the stored ones (H2)", ready, "crush", sandboxcred.HomeKeyServedInjection, dashapi.SandboxKeyAdvisory},
		{"a tool with no proxy route cannot take injection", ready, "droid", sandboxcred.HomeKeyToolProvider, dashapi.SandboxKeyBlocking},
		{"nothing serves the default", sandboxcred.HomeKeyFacts{}, "opencode", sandboxcred.HomeKeyNothingServes, dashapi.SandboxKeyBlocking},
		{"the org route serves every tool", sandboxcred.HomeKeyFacts{OrgRoute: true}, "opencode", "", ""},
		{"the key in the box, none found: said, not blocking (H3)", inBox, "opencode", sandboxcred.HomeKeyInBoxNoKey, dashapi.SandboxKeyAdvisory},
		{"the key in the box from the environment: named, not blocking", inBoxEnv, "opencode", sandboxcred.HomeKeyServedInBox, dashapi.SandboxKeyAdvisory},
		{"the key in the box, a vendor-locked tool whose key is absent", inBoxEnv, "claude-code", sandboxcred.HomeKeyInBoxNoKey, dashapi.SandboxKeyAdvisory},
	}
	for _, tc := range cases {
		n := hostedKeyNotice(tc.facts, tc.tool)
		switch {
		case tc.code == "" && n != nil:
			t.Errorf("%s: notice %+v, want none", tc.name, n)
		case tc.code != "" && (n == nil || n.Code != tc.code || n.Message == "" || n.Technical == "" || n.Severity != tc.severity):
			t.Errorf("%s: notice %+v, want code %s (%s) with a message and a detail", tc.name, n, tc.code, tc.severity)
		}
	}
}

// TestHostedToolRouteFromTheRegistry: the providers a tool's route carries
// come from its capability row (route lanes and covered built-in provider
// overrides), and a vendor-locked tool keeps its one provider.
func TestHostedToolRouteFromTheRegistry(t *testing.T) {
	cases := []struct {
		tool       string
		injectable []string
	}{
		{"claude-code", []string{"anthropic"}},
		{"codex", []string{"openai"}},
		{"grok", []string{"xai"}},
		{"hermes", []string{"openrouter"}},                                        // its route lane addresses openrouter.ai
		{"pi", []string{"anthropic", "openai", "google", "xai", "openrouter"}},    // its covered built-in providers
		{"opencode", []string{"openai"}},                                          // its route is the openai provider entry (CarriesProviders)
		{"aider", []string{"openai"}},                                             // OPENAI_API_BASE
		{"goose", []string{"openai"}},                                             // OPENAI_HOST
		{"gemini-cli", []string{"google"}},                                        // GOOGLE_GEMINI_BASE_URL
		{"crush", []string{"anthropic", "openai", "google", "xai", "openrouter"}}, // the registry does not say
		{"droid", nil}, // no proxy route
	}
	for _, tc := range cases {
		if got := sandboxcred.InjectableProviders(hostedToolRoute(tc.tool)); !slices.Equal(got, tc.injectable) {
			t.Errorf("%s: injectable %v, want %v", tc.tool, got, tc.injectable)
		}
	}
	if hostedUpstreamHost("https://openrouter.ai/api") != "openrouter.ai" || hostedUpstreamHost("::") != "" {
		t.Error("hostedUpstreamHost")
	}
}

// TestHostedNoLaunchRefusedThatRanBefore: for every sandbox-launchable tool
// and every node posture, a hosted launch the one-provider rule passed
// still passes, so widening injection to more tools never refuses a launch
// that ran before (H2).
func TestHostedNoLaunchRefusedThatRanBefore(t *testing.T) {
	old := func(f sandboxcred.HomeKeyFacts, tool string) bool {
		spec, _ := integration.For(tool)
		one := ""
		if spec.Model.Catalog.Kind == integration.ModelCatalogVendor && len(spec.Model.Catalog.Providers) == 1 {
			if p, ok := sandboxcred.ProviderFor(spec.Model.Catalog.Providers[0]); ok {
				one = p.ID
			}
		}
		switch {
		case f.Custody == "in_box_api_key":
			return true
		case f.Custody != "" && f.Custody != "home_relay":
			return false
		case f.OrgRoute:
			return true
		case !f.InjectionSelected || !f.InjectionBuilt || len(f.StoredProviders) == 0:
			return false
		}
		return one != "" && slices.Contains(f.StoredProviders, one)
	}
	postures := []sandboxcred.HomeKeyFacts{{}, {OrgRoute: true}, {Custody: "in_box_api_key"}}
	for _, stored := range [][]string{{"anthropic"}, {"openai"}, {"xai"}, {"anthropic", "openai", "google", "xai", "openrouter"}} {
		postures = append(postures, sandboxcred.HomeKeyFacts{Custody: "home_relay", InjectionSelected: true, InjectionBuilt: true, StoredProviders: stored})
	}
	checked := 0
	for _, c := range integration.Capabilities() {
		if !integration.TerminalLaunchable(c) || len(c.Sandbox.StateRW) == 0 {
			continue
		}
		for _, f := range postures {
			checked++
			if old(f, c.Tool) && !sandboxcred.HomeKey(hostedHomeKeyForTool(f, c.Tool)).OK {
				t.Errorf("%s under %+v: passed before, refused now", c.Tool, f)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no launch checked")
	}
}

// TestHostedKeyFactsOfNeedsAListedRow: the per-tool line is computed only
// while a hosted row is listed.
func TestHostedKeyFactsOfNeedsAListedRow(t *testing.T) {
	if _, ok := hostedKeyFactsOf(nil); ok {
		t.Fatal("facts with no driver")
	}
	unlisted := &hostedDriver{r: &sandboxRuntime{cfg: hostedTestConfig("bwrap")}}
	unlisted.vendor.ID = sandboxbackend.BackendDaytona
	if _, ok := hostedKeyFactsOf(map[string]sandboxDriver{sandboxbackend.BackendDaytona: unlisted}); ok {
		t.Fatal("facts from an unlisted row")
	}
	listed := &hostedDriver{r: &sandboxRuntime{cfg: hostedTestConfig("bwrap", sandboxbackend.BackendDaytona)}, homeKey: sandboxcred.HomeKeyFacts{OrgRoute: true}}
	listed.vendor.ID = sandboxbackend.BackendDaytona
	listed.cfg.KeyCustody = "in_box_api_key"
	f, ok := hostedKeyFactsOf(map[string]sandboxDriver{sandboxbackend.BackendDaytona: listed})
	if !ok || !f.OrgRoute || f.Custody != "in_box_api_key" {
		t.Fatalf("facts %+v ok %v, want the driver's own with its custody", f, ok)
	}
}

// TestHostedCreateRefusesTheKeyBeforeAnything: Create refuses a tool whose
// model key cannot reach the agent with the typed, plain refusal, before
// the probe, any workspace or any vendor call.
func TestHostedCreateRefusesTheKeyBeforeAnything(t *testing.T) {
	skipDriverOffHost(t, "the hosted drivers")
	hostedTestEnv(t, map[string]string{"E2B_API_KEY": "e2b_FAKEKEY_000111"})
	t.Cleanup(func() { hostedListed.Store(false) })
	calls := 0
	cfg := hostedTestConfig(sandboxbackend.BackendE2B)
	// An explicit home_relay: the launch rule every node had before auto.
	cfg.Hosted.KeyCustody = string(vocab.CustodyHomeRelay)
	d := hostedTestDriver(t, sandboxbackend.BackendE2B, cfg, &calls)
	d.homeKey = sandboxcred.HomeKeyFacts{InjectionSelected: true, InjectionBuilt: true, StoredProviders: []string{"anthropic"}}
	d.full = nil // the facts above, not the build's config, are judged
	// A tool whose model requests never reach the proxy (no proxy route in
	// its capability row): injection cannot serve it.
	_, err := d.Create(context.Background(), termsvc.PrepareRequest{Tool: "droid", ProjectRoot: t.TempDir()})
	var refusal *dashapi.SandboxStepRefusal
	if !errors.As(err, &refusal) || refusal.Code != verdictHostedCustody || !strings.Contains(refusal.Technical, sandboxcred.HomeKeyToolProvider) {
		t.Fatalf("Create = %v, want the typed refusal naming the tool's provider", err)
	}
	if strings.Contains(refusal.Message, "home_relay") || strings.Contains(refusal.Message, "`") {
		t.Errorf("the message carries internal names: %q", refusal.Message)
	}
	if calls != 0 {
		t.Errorf("client built %d times", calls)
	}
	// The same node launches a tool whose provider has a stored key: the
	// custody check passes, so Create goes on to its next refusal.
	_, err = d.Create(context.Background(), termsvc.PrepareRequest{Tool: "claude-code", ProjectRoot: t.TempDir()})
	if errors.As(err, &refusal) {
		t.Fatalf("claude-code with its key stored was refused on custody: %v", err)
	}
}

// TestHostedCustodySetupFact: the setup step reads done exactly when the
// configured custody can reach the agent on this node, and says why in
// plain words when it cannot.
func TestHostedCustodySetupFact(t *testing.T) {
	read := sandboxConfigKeyFacts["terminal.sandbox.hosted.key_custody"]
	if read == nil {
		t.Fatal("no reader for the custody key")
	}
	cfg := config.Default()
	// The default is auto (decision SBXD-1): the step reads done, since
	// every launch resolves to a custody that reaches the agent.
	if done, _ := read(cfg); !done {
		t.Fatal("the default custody (auto) reads missing")
	}
	cfg.Terminal.Sandbox.Hosted.KeyCustody = string(vocab.CustodyHomeRelay)
	if done, why := read(cfg); done || why == "" || strings.Contains(why, "home_relay") {
		t.Fatalf("an explicit home_relay with nothing serving it: done %v, why %q", done, why)
	}
	cfg.Terminal.Sandbox.Hosted.KeyCustody = string(vocab.CustodyInBoxAPIKey)
	if done, _ := read(cfg); !done {
		t.Fatal("the key in the box reads missing")
	}
	cfg = config.Default()
	cfg.Proxy.OrgRoute.Mode = "gateway"
	if done, _ := read(cfg); !done {
		t.Fatal("the org route reads missing")
	}
}

// TestHostedCustodySetupWritesAndRestores: the step's remedy writes its own
// value (never "true") and the previous value comes back on undo.
func TestHostedCustodySetupWritesAndRestores(t *testing.T) {
	p, ok := sandboxsetup.Lookup("hosted-custody")
	if !ok || len(p.Remedies) == 0 {
		t.Fatal("no hosted-custody prerequisite")
	}
	rem := p.Remedies[0]
	if rem.Channel != sandboxsetup.ChConfig || rem.Value != string(vocab.CustodyInBoxAPIKey) || rem.Disclosure == "" || rem.Action == "" {
		t.Fatalf("remedy %+v", rem)
	}
	r := newSetupRig(t, setupBaseConfig)
	ctx := context.Background()
	prev, err := writeConfigKey(ctx, r.svc.run.writeConfig, rem.Package, rem.Value)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Load(config.LoadOptions{GlobalPath: r.cfgPath})
	if cfg.Terminal.Sandbox.Hosted.KeyCustody != rem.Value {
		t.Fatalf("custody = %q", cfg.Terminal.Sandbox.Hosted.KeyCustody)
	}
	if _, err := writeConfigKey(ctx, r.svc.run.writeConfig, rem.Package, prev); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(config.LoadOptions{GlobalPath: r.cfgPath})
	if cfg.Terminal.Sandbox.Hosted.KeyCustody != string(vocab.CustodyAuto) {
		t.Fatalf("after undo custody = %q, want the default auto back", cfg.Terminal.Sandbox.Hosted.KeyCustody)
	}
}

// TestHostedRowsListTheCustodyStep: every hosted row the generic driver
// probes lists the step its custody verdict names, before the consent step
// (the consent's facts carry the custody, so the custody is chosen first).
func TestHostedRowsListTheCustodyStep(t *testing.T) {
	for _, id := range sandboxbackend.IDs() {
		row, _ := sandboxbackend.Get(id)
		if row.Iso.Location != vocab.LocationRemote || row.Maturity == sandboxbackend.MaturityPlanned || id == sandboxbackend.BackendOpenShellOrg {
			continue
		}
		at, consent := -1, -1
		for i, s := range row.Setup {
			switch s {
			case "hosted-custody":
				at = i
			case "hosted-consent":
				consent = i
			}
		}
		if at < 0 || consent < 0 || at > consent {
			t.Errorf("%s: setup %v, want hosted-custody before hosted-consent", id, row.Setup)
		}
	}
}

// TestHostedConsentStepReopensOnAChangedFact: a consent recorded for other
// facts (the custody step's remedy changes the custody) reads missing with a
// plain reason, so the person agrees again before the next upload; a
// matching one reads done.
func TestHostedConsentStepReopensOnAChangedFact(t *testing.T) {
	r := newSetupRig(t, setupBaseConfig)
	h := r.svc.host
	h.hostedConsent = func(string) bool { return true }
	row := sandboxbackend.Capability{ID: sandboxbackend.BackendDaytona, Setup: []string{"hosted-consent"}}
	cases := []struct {
		change  string
		present bool
		words   string
	}{
		{"", true, ""},
		{sandboxremote.ConsentChangedPrefix + "custody", false, "how the agent gets its model key"},
		{sandboxremote.ConsentChangedPrefix + "region", false, "the region"},
		{sandboxremote.ConsentStaleVersion, false, "older version"},
		{sandboxremote.ConsentChangedPrefix + "something_new", false, "your settings"},
	}
	for _, tc := range cases {
		h.hostedConsentChange = func(config.Config, string) string { return tc.change }
		f, ok := passiveFacts(h, config.Default(), row, nil)["hosted-consent"]
		if !ok || f.Present != tc.present || !strings.Contains(f.Reason, tc.words) {
			t.Errorf("change %q: fact %+v ok %v, want present %v with %q", tc.change, f, ok, tc.present, tc.words)
		}
		if strings.Contains(f.Reason, "consent_changed") || strings.Contains(f.Reason, "_") {
			t.Errorf("change %q: reason %q carries a code", tc.change, f.Reason)
		}
	}
}

// TestHostedAcceptedSourcesMatchTheLaunch: the sources a hosted row lists
// for the dialog are exactly those its launch resolves (what
// workspace.DeliveryFor maps from the row's deliveries, then a box-side
// clone's gates), for every tier and with each remote-clone gate open and
// shut (lane CLONE), so the probe and the launch can never disagree. The
// URL is a valid public one, which the probe never judges.
func TestHostedAcceptedSourcesMatchTheLaunch(t *testing.T) {
	open := config.Default().Terminal.Sandbox
	open.AllowRemoteClone, open.RemoteAllowedHosts = true, []string{"github.com"}
	off := open
	off.AllowRemoteClone = false
	noHosts := open
	noHosts.RemoteAllowedHosts = nil
	cfgs := map[string]config.TerminalSandboxConfig{"gates open": open, "switch off": off, "no hosts": noHosts}
	for name, cfg := range cfgs {
		for _, tier := range []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone} {
			for _, id := range sandboxremote.VendorIDs() {
				v, _ := sandboxremote.VendorFor(id)
				listed, _, ok := hostedAcceptedSources(id, tier, cfg)
				if !ok {
					t.Fatalf("%s: no list", id)
				}
				for _, src := range hostedSourceOrder {
					req := termsvc.PrepareRequest{WorkspaceSource: string(src), WorkspaceRemote: "https://github.com/example/repo.git", ProjectRoot: "/home/dev/app"}
					_, err := hostedSourceDelivery(context.Background(), v, req, tier, cfg)
					takes := err == nil
					if takes != slices.Contains(listed, string(src)) {
						t.Errorf("%s, %s, %s: source %s listed %v, launch resolves it %v (%v)", name, tier, id, src, slices.Contains(listed, string(src)), takes, err)
					}
				}
			}
		}
	}
	// Every vendor row takes the box-side clone with the gates open on the
	// internet tier (lane CLONE, item H7).
	for _, id := range sandboxremote.VendorIDs() {
		if listed, _, _ := hostedAcceptedSources(id, vocab.TierInternet, open); !slices.Contains(listed, "clone-remote") {
			t.Errorf("%s does not offer clone-remote: %v", id, listed)
		}
	}
	if _, _, ok := hostedAcceptedSources(sandboxbackend.BackendBwrap, vocab.TierInternet, open); ok {
		t.Error("a local row got a hosted source list")
	}
}
