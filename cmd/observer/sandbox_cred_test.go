//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

const credTestKey = "sk-ant-api03-REAL-USER-KEY-for-tests-only"

// credEnvForTest makes the component active with an in-memory keystore
// under a fresh observer dir.
func credEnvForTest(t *testing.T, active bool) (string, *keystore.MemStore) {
	t.Helper()
	obs := filepath.Join(t.TempDir(), ".observer")
	ks := &keystore.MemStore{}
	oldActive, oldKeys, oldObs, oldOther := credActive, credKeysFn, credObserverDir, credOtherHomeRelay
	credActive = func(context.Context) bool { return active }
	credKeysFn = func(string) keystore.Store { return ks }
	credObserverDir = func() string { return obs }
	credOtherHomeRelay = func() bool { return false }
	t.Cleanup(func() {
		credActive, credKeysFn, credObserverDir, credOtherHomeRelay = oldActive, oldKeys, oldObs, oldOther
		credStates.Range(func(k, _ any) bool { credStates.Delete(k); return true })
	})
	return obs, ks
}

func credPlan(obs, run string) hostedPlanFile {
	return hostedPlanFile{RunID: run, Provider: "e2b", Custody: string(vocab.CustodyHomeRelay), Tool: "claude-code", ObserverDir: obs, TimeoutMinutes: 30}
}

func credRelayRecord(t *testing.T, obs, run string) {
	t.Helper()
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: run, Tool: "claude-code", ProjectRoot: "/w", WorkspaceDir: "/w", Roots: []string{"/w"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
}

// TestCredHomeRelayInjection: the box's env holds only the sentinel, the
// home side stamps the relay token (replacing a box-sent one), and the
// daemon's injector adds the real key for exactly that run, provider, host
// and auth form.
func TestCredHomeRelayInjection(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	run := "run-cred-1"
	credRelayRecord(t, obs, run)
	plan := credPlan(obs, run)
	if err := credSetup(context.Background(), plan); err != nil {
		t.Fatalf("setup: %v", err)
	}
	env := map[string]string{}
	credEnv(plan, env)
	sentinel := env["ANTHROPIC_API_KEY"]
	if !sandboxcred.IsSentinel(sentinel) || strings.Contains(sentinel, credTestKey) {
		t.Fatalf("box env holds %q, want a sentinel", sentinel)
	}
	h := http.Header{}
	h.Set(sandboxcred.TokenHeader, "box-forged")
	credStamp(h, run)
	token := h.Get(sandboxcred.TokenHeader)
	if token == "" || token == "box-forged" {
		t.Fatalf("stamp = %q", token)
	}
	inj := &credInjector{observerDir: obs}
	good := proxy.CredentialRequest{RunID: run, Token: token, Host: "api.anthropic.com", XAPIKey: sentinel}
	if hdr, val, ok := inj.Inject(context.Background(), good); !ok || hdr != "X-Api-Key" || val != credTestKey {
		t.Fatalf("inject = %q %v", hdr, ok)
	}
	refusals := map[string]proxy.CredentialRequest{
		"box-forged token":  {RunID: run, Token: "box-forged", Host: "api.anthropic.com", XAPIKey: sentinel},
		"another host":      {RunID: run, Token: token, Host: "evil.example.com", XAPIKey: sentinel},
		"wrong auth form":   {RunID: run, Token: token, Host: "api.anthropic.com", Authorization: "Bearer " + sentinel},
		"another run":       {RunID: "run-other", Token: token, Host: "api.anthropic.com", XAPIKey: sentinel},
		"another sentinel":  {RunID: run, Token: token, Host: "api.anthropic.com", XAPIKey: sandboxcred.SentinelPrefix + "anthropic-x"},
		"no run header set": {Token: token, Host: "api.anthropic.com", XAPIKey: sentinel},
	}
	for name, r := range refusals {
		if _, _, ok := inj.Inject(context.Background(), r); ok {
			t.Fatalf("%s: injected", name)
		}
	}
	// A dead run (its relay record gone) gets nothing.
	_ = sandboxrelayd.RemoveRun(obs, run)
	if _, _, ok := inj.Inject(context.Background(), good); ok {
		t.Fatal("a dead run was injected")
	}
	credRelayRecord(t, obs, run)
	credTeardown(plan)
	if _, _, ok := inj.Inject(context.Background(), good); ok {
		t.Fatal("injected after teardown")
	}
}

// TestCredSetupNeedsTheRunsProvider: home_relay through injection needs a
// key for the run's own provider; without one the launch is refused
// custody_unsatisfiable, unless a pool or the org route serves it.
func TestCredSetupNeedsTheRunsProvider(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	_ = ks.Set(sandboxcred.KeyName("openai"), "sk-openai")
	err := credSetup(context.Background(), credPlan(obs, "run-cred-2"))
	if err == nil || !strings.Contains(err.Error(), "custody_unsatisfiable") || !strings.Contains(err.Error(), "anthropic") {
		t.Fatalf("setup = %v", err)
	}
	credOtherHomeRelay = func() bool { return true }
	if err := credSetup(context.Background(), credPlan(obs, "run-cred-2")); err != nil {
		t.Fatalf("a pool-served home_relay was refused: %v", err)
	}
}

// TestCredOffIsTheNilPath: with the component off nothing is minted, put
// in the box or stamped, and homeRelayOK keeps its old rule.
func TestCredOffIsTheNilPath(t *testing.T) {
	obs, ks := credEnvForTest(t, false)
	_ = ks.Set(sandboxcred.KeyName("anthropic"), credTestKey)
	plan := credPlan(obs, "run-cred-3")
	if err := credSetup(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	credEnv(plan, env)
	h := http.Header{}
	credStamp(h, plan.RunID)
	if len(env) != 0 || h.Get(sandboxcred.TokenHeader) != "" {
		t.Fatalf("the off path changed the run: env=%v header=%v", env, h)
	}
	// An install with no [components] block never counts as injection-ready.
	if credReady(config.Config{}) {
		t.Fatal("credReady on a legacy config")
	}
}

// TestCredCLIAndRoutes: add stores the key, list never prints it, the
// routes answer 404 while the component is off.
func TestCredCLIAndRoutes(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	cmd := newSandboxCredentialsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(credTestKey + "\n"))
	cmd.SetArgs([]string{"add", "anthropic"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("add: %v", err)
	}
	if v, _ := ks.Get(sandboxcred.KeyName("anthropic")); v != credTestKey {
		t.Fatal("the key was not stored")
	}
	if got := credStoredProviders(obs); len(got) != 1 || got[0] != "anthropic" {
		t.Fatalf("stored providers = %v", got)
	}
	cmd.SetArgs([]string{"list"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), credTestKey) || !strings.Contains(out.String(), "key stored") {
		t.Fatalf("list output %q", out.String())
	}
	cmd.SetIn(strings.NewReader(sandboxcred.SentinelPrefix + "anthropic-x\n"))
	cmd.SetArgs([]string{"add", "anthropic"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("a sentinel was accepted as a key")
	}
	cmd.SetArgs([]string{"remove", "anthropic"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Get(sandboxcred.KeyName("anthropic")); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatal("remove left the key")
	}
	if len(credStoredProviders(obs)) != 0 {
		t.Fatal("remove left the provider marked")
	}
	credActive = func(context.Context) bool { return false }
	for _, rt := range credDashboardRoutes("") {
		method, path, _ := strings.Cut(rt.Pattern, " ")
		rr := httptest.NewRecorder()
		rt.Handler.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d with the component off", rt.Pattern, rr.Code)
		}
	}
}

// credFakeBroker is a vendor broker that records its rules.
type credFakeBroker struct{ rules map[string]bool }

func (b *credFakeBroker) Setup(_ context.Context, runID, provider, host string) (string, error) {
	id := runID + "/" + provider + "/" + host
	b.rules[id] = true
	return id, nil
}

func (b *credFakeBroker) Remove(_ context.Context, id string) error { delete(b.rules, id); return nil }

func (b *credFakeBroker) Exists(_ context.Context, id string) (bool, error) {
	return b.rules[id], nil
}

// TestProviderInjected: refused while no broker is built (today), and on a
// fake vendor: the org forbid and the org budget refuse, a sound run sets
// the broker rule up for the provider's model host and teardown removes it.
func TestProviderInjected(t *testing.T) {
	obs, _ := credEnvForTest(t, true)
	plan := credPlan(obs, "run-cred-4")
	plan.Custody = string(vocab.CustodyProviderInjected)
	if err := credSetup(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "not offered") {
		t.Fatalf("an unbuilt broker was used: %v", err)
	}
	b := &credFakeBroker{rules: map[string]bool{}}
	oldOffered, oldFacts := credBrokerOffered, credInjectedFacts
	credBrokers["e2b"] = b
	credBrokerOffered = func(string) bool { return true }
	t.Cleanup(func() { delete(credBrokers, "e2b"); credBrokerOffered, credInjectedFacts = oldOffered, oldFacts })
	for name, edit := range map[string]func(*sandboxcred.InjectedFacts){
		"org forbids":     func(f *sandboxcred.InjectedFacts) { f.OrgForbids = true },
		"org budgets":     func(f *sandboxcred.InjectedFacts) { f.OrgBudgetsEnforced = true },
		"managed, unsaid": func(f *sandboxcred.InjectedFacts) { f.Managed = true },
	} {
		credInjectedFacts = func(v string) sandboxcred.InjectedFacts {
			f := sandboxcred.InjectedFacts{Vendor: v, Offered: true}
			edit(&f)
			return f
		}
		if err := credSetup(context.Background(), plan); err == nil || !strings.Contains(err.Error(), sandboxcred.CodeCustodyNotAllowed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	credInjectedFacts = func(v string) sandboxcred.InjectedFacts { return sandboxcred.InjectedFacts{Vendor: v, Offered: true} }
	if err := credSetup(context.Background(), plan); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(b.rules) != 1 || !b.rules["run-cred-4/anthropic/api.anthropic.com"] {
		t.Fatalf("rules = %v", b.rules)
	}
	credTeardown(plan)
	if len(b.rules) != 0 {
		t.Fatalf("teardown left %v", b.rules)
	}
}

// TestCredTokenHeaderSpellings: the proxy's token header and
// internal/sandboxcred's are the same (the proxy does not import the
// sandbox module).
func TestCredTokenHeaderSpellings(t *testing.T) {
	if proxy.SandboxCredTokenHeader != sandboxcred.TokenHeader {
		t.Fatalf("%q != %q", proxy.SandboxCredTokenHeader, sandboxcred.TokenHeader)
	}
}

// TestHostedNetOffersInjectedOnlyForACitedBuiltBroker: a hosted registry
// row lists provider_injected only when its vendor's broker row is cited and
// built (none in this release).
func TestHostedNetOffersInjectedOnlyForACitedBuiltBroker(t *testing.T) {
	for _, id := range sandboxbackend.IDs() {
		row, _ := sandboxbackend.Get(id)
		if row.Iso.Location != vocab.LocationRemote {
			continue
		}
		if slices.Contains(row.Net.KeyCustody, vocab.CustodyProviderInjected) && !sandboxcred.Offered(row.ID) {
			t.Fatalf("%s offers provider_injected with no cited, built broker", row.ID)
		}
	}
}

// TestCredStampConcurrentFirstRequests (audit F1): a helper whose relayed
// connections each get their own server sees several first requests at
// once; every one is stamped with the same token, and the run's record
// holds that token's hash (run with -race).
func TestCredStampConcurrentFirstRequests(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	run := "run-cred-race"
	credRelayRecord(t, obs, run)
	if err := credSetup(context.Background(), credPlan(obs, run)); err != nil {
		t.Fatal(err)
	}
	// A re-adopting helper: no state of its own, only the record.
	credStates.Delete(run)
	const n = 16
	tokens := make([]string, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h := http.Header{}
			credStamp(h, run)
			tokens[i] = h.Get(sandboxcred.TokenHeader)
		}(i)
	}
	wg.Wait()
	for i, tok := range tokens {
		if tok == "" || tok != tokens[0] {
			t.Fatalf("request %d stamped %q, request 0 %q", i, tok, tokens[0])
		}
	}
	rec, err := credReadRecord(obs, run)
	if err != nil {
		t.Fatal(err)
	}
	if rec.TokenHash != sandboxcred.Hash(tokens[0]) {
		t.Fatal("the record's token hash differs from the token the run stamps")
	}
}

// TestCredStampReadsConfigOncePerRun (audit F6): with no record for the
// run (the component off at its launch), the observer dir is resolved once
// for the run, not on every relayed request, and nothing is stamped.
func TestCredStampReadsConfigOncePerRun(t *testing.T) {
	obs, _ := credEnvForTest(t, false)
	calls := 0
	credObserverDir = func() string { calls++; return obs }
	for range 5 {
		h := http.Header{}
		h.Set(sandboxcred.TokenHeader, "box-sent")
		credStamp(h, "run-cred-none")
		if h.Get(sandboxcred.TokenHeader) != "" {
			t.Fatal("a run with no record was stamped, or the box's token kept")
		}
	}
	if calls != 1 {
		t.Fatalf("the observer dir was resolved %d times for one run", calls)
	}
}

// TestCredConsentNamesInjection (audit F8): with the component on, the
// hosted consent screen's credential line is injection's own disclosure
// for home_relay; off, or for another custody, the line is unchanged.
func TestCredConsentNamesInjection(t *testing.T) {
	base := func(custody string) sandboxremote.ConsentScreen {
		return sandboxremote.ConsentScreen{Facts: sandboxremote.ConsentFacts{Custody: custody}, Lines: []sandboxremote.ConsentLine{{Label: "Model credential", Value: "the screen's own line"}}}
	}
	_, _ = credEnvForTest(t, true)
	scr := base(string(vocab.CustodyHomeRelay))
	hostedApplyCredConsent(context.Background(), &scr, "E2B", "full")
	if v := scr.Lines[0].Value; !strings.Contains(v, "sentinel") || !strings.Contains(v, "home_relay") {
		t.Fatalf("with injection on the line reads %q", v)
	}
	scr = base(string(vocab.CustodyInBoxAPIKey))
	hostedApplyCredConsent(context.Background(), &scr, "E2B", "full")
	if scr.Lines[0].Value != "the screen's own line" {
		t.Fatal("another custody's line was changed")
	}
	credActive = func(context.Context) bool { return false }
	scr = base(string(vocab.CustodyHomeRelay))
	hostedApplyCredConsent(context.Background(), &scr, "E2B", "full")
	if scr.Lines[0].Value != "the screen's own line" {
		t.Fatal("the line changed with injection off")
	}
}

// TestCredNotReadyWithoutTheProxy (audit F10): in a build without the
// capture proxy credReady is false even with a key stored, and a home_relay
// launch is refused up front naming why; with the proxy it is ready and the
// refusal carries no note.
func TestCredNotReadyWithoutTheProxy(t *testing.T) {
	obs, _ := credEnvForTest(t, true)
	oldSel, oldBuilt := credSelected, credProxyBuilt
	credSelected = func(config.Config) bool { return true }
	t.Cleanup(func() { credSelected, credProxyBuilt = oldSel, oldBuilt })
	if err := credMarkProvider(obs, "anthropic", true); err != nil {
		t.Fatal(err)
	}
	full := config.Config{}
	full.Observer.DBPath = filepath.Join(obs, "observer.db")
	if sandboxObserverDirFor(full) != obs {
		t.Skipf("the observer dir is %q here, not the test's", sandboxObserverDirFor(full))
	}
	credProxyBuilt = false
	if credReady(full) {
		t.Fatal("credReady in a proxy-less build")
	}
	note := credNotReady(full)
	if !strings.Contains(note, "capture proxy") {
		t.Fatalf("note = %q", note)
	}
	err := hostedCustodyCheckNoted(false, note, vocab.CustodyHomeRelay)
	if err == nil || !strings.Contains(err.Error(), "capture proxy") || !strings.Contains(err.Error(), verdictHostedCustody) {
		t.Fatalf("refusal = %v", err)
	}
	credProxyBuilt = true
	if !credReady(full) || credNotReady(full) != "" {
		t.Fatal("not ready with the proxy built and a key stored")
	}
}
