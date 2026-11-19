//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_cred_set_linux_test.go pins a hosted run that binds several
// providers (gap H2): a tool that picks its own provider (OpenCode's
// capability row: an open catalogue, a proxy route) gets one sentinel per
// stored key, each in its provider's own variable, and the injector adds
// provider P's key only on P's host for P's own sentinel.

const credTestOpenAIKey = "sk-proj-REAL-OPENAI-KEY-for-tests-only"

func TestCredHostedRunBindsEveryStoredProvider(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	_ = ks.Set(sandboxcred.KeyName("anthropic"), credTestKey)
	_ = ks.Set(sandboxcred.KeyName("openai"), credTestOpenAIKey)
	run := "run-cred-set-1"
	credRelayRecord(t, obs, run)
	plan := credPlan(obs, run)
	plan.Tool = "crush"
	if err := credSetup(context.Background(), plan); err != nil {
		t.Fatalf("setup: %v", err)
	}
	rec, err := credReadRecord(obs, run)
	if err != nil || rec.V != credRecordVersionSet || len(rec.Bindings) != 2 || rec.Provider != "" || rec.SentinelHash != "" {
		t.Fatalf("record %+v err %v, want version 2 with two bindings", rec, err)
	}
	env := map[string]string{}
	credEnv(plan, env)
	antS, oaiS := env["ANTHROPIC_API_KEY"], env["OPENAI_API_KEY"]
	if !sandboxcred.IsSentinel(antS) || !sandboxcred.IsSentinel(oaiS) || antS == oaiS {
		t.Fatalf("box env %v, want a sentinel of its own for each bound provider", env)
	}
	if len(env) != 2 {
		t.Fatalf("box env %v: a provider with no stored key got a sentinel", env)
	}
	h := http.Header{}
	credStamp(h, run)
	token := h.Get(sandboxcred.TokenHeader)
	inj := &credInjector{observerDir: obs}
	inject := func(r proxy.CredentialRequest) (string, string, bool) {
		r.RunID, r.Token = run, token
		return inj.Inject(context.Background(), r)
	}
	if hdr, val, ok := inject(proxy.CredentialRequest{Host: "api.anthropic.com", XAPIKey: antS}); !ok || hdr != "X-Api-Key" || val != credTestKey {
		t.Fatalf("anthropic: %q %v", hdr, ok)
	}
	if hdr, val, ok := inject(proxy.CredentialRequest{Host: "api.openai.com", Authorization: "Bearer " + oaiS}); !ok || hdr != "Authorization" || val != "Bearer "+credTestOpenAIKey {
		t.Fatalf("openai: %q %v", hdr, ok)
	}
	refusals := map[string]proxy.CredentialRequest{
		"anthropic's sentinel to openai's host":             {Host: "api.openai.com", XAPIKey: antS},
		"anthropic's sentinel as a bearer to openai's host": {Host: "api.openai.com", Authorization: "Bearer " + antS},
		"openai's sentinel to anthropic's host":             {Host: "api.anthropic.com", Authorization: "Bearer " + oaiS},
		"openai's sentinel to xai (not bound, same form)":   {Host: "api.x.ai", Authorization: "Bearer " + oaiS},
		"openai's sentinel to openrouter (not bound)":       {Host: "openrouter.ai", Authorization: "Bearer " + oaiS},
		"openai's sentinel to another host":                 {Host: "evil.example.com", Authorization: "Bearer " + oaiS},
		"anthropic's sentinel on its host in openai's form": {Host: "api.anthropic.com", Authorization: "Bearer " + antS},
		"a real key on openai's host":                       {Host: "api.openai.com", Authorization: "Bearer sk-real"},
	}
	for name, r := range refusals {
		if hdr, val, ok := inject(r); ok {
			t.Fatalf("%s: injected %s (%d bytes)", name, hdr, len(val))
		}
	}
	credTeardown(plan)
	if _, _, ok := inject(proxy.CredentialRequest{Host: "api.openai.com", Authorization: "Bearer " + oaiS}); ok {
		t.Fatal("injected after teardown")
	}
}

// TestCredHostedOneProviderWritesTheOldRecord: a run that binds one
// provider writes the version 1 record every run had before, with no
// bindings field, so an older reader decides it as before.
func TestCredHostedOneProviderWritesTheOldRecord(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	_ = ks.Set(sandboxcred.KeyName("anthropic"), credTestKey)
	_ = ks.Set(sandboxcred.KeyName("openai"), credTestOpenAIKey)
	run := "run-cred-set-2"
	credRelayRecord(t, obs, run)
	if err := credSetup(context.Background(), credPlan(obs, run)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(credRunsDir(obs), run+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["v"] != float64(1) || raw["provider"] != "anthropic" || raw["sentinel_hash"] == "" {
		t.Fatalf("record %s", b)
	}
	if _, ok := raw["bindings"]; ok {
		t.Fatalf("a one-provider record carries bindings: %s", b)
	}
}

// TestCredOldRecordDecidedAsBefore: a version 1 record exactly as a daemon
// before this change wrote it is read and decided as before (the key on
// its provider's host for its sentinel, nothing anywhere else).
func TestCredOldRecordDecidedAsBefore(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	_ = ks.Set(sandboxcred.KeyName("anthropic"), credTestKey)
	run := "run-cred-old-1"
	credRelayRecord(t, obs, run)
	sent, token := sandboxcred.SentinelPrefix+"anthropic-oldrun", "old-token"
	now := time.Now().UTC()
	body := `{"v":1,"run_id":"` + run + `","provider":"anthropic","custody":"home_relay","sentinel_hash":"` + sandboxcred.Hash(sent) +
		`","token_hash":"` + sandboxcred.Hash(token) + `","created_at":"` + now.Format(time.RFC3339Nano) + `","expires":"` + now.Add(time.Hour).Format(time.RFC3339Nano) + `"}`
	if err := os.MkdirAll(credRunsDir(obs), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credRunsDir(obs), run+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	inj := &credInjector{observerDir: obs}
	if hdr, val, ok := inj.Inject(context.Background(), proxy.CredentialRequest{RunID: run, Token: token, Host: "api.anthropic.com", XAPIKey: sent}); !ok || hdr != "X-Api-Key" || val != credTestKey {
		t.Fatalf("the old record: %q %v", hdr, ok)
	}
	for name, r := range map[string]proxy.CredentialRequest{
		"another host": {RunID: run, Token: token, Host: "api.openai.com", XAPIKey: sent},
		"a bearer":     {RunID: run, Token: token, Host: "api.anthropic.com", Authorization: "Bearer " + sent},
		"wrong token":  {RunID: run, Token: "x", Host: "api.anthropic.com", XAPIKey: sent},
	} {
		if _, _, ok := inj.Inject(context.Background(), r); ok {
			t.Fatalf("%s: injected", name)
		}
	}
}

// TestCredRecordShapes: a record whose version does not match its shape is
// refused (no injection).
func TestCredRecordShapes(t *testing.T) {
	two := []credBinding{{Provider: "anthropic", SentinelHash: "a"}, {Provider: "openai", SentinelHash: "b"}}
	cases := []struct {
		name string
		rec  credRunRecord
		ok   bool
	}{
		{"version 1", credRunRecord{V: 1, Provider: "anthropic", SentinelHash: "a"}, true},
		{"version 2", credRunRecord{V: 2, Bindings: two}, true},
		{"version 1 with bindings", credRunRecord{V: 1, Provider: "anthropic", Bindings: two}, false},
		{"version 2 with one binding", credRunRecord{V: 2, Bindings: two[:1]}, false},
		{"version 2 with the version 1 fields", credRunRecord{V: 2, Provider: "anthropic", Bindings: two}, false},
		{"version 2 binding one provider twice", credRunRecord{V: 2, Bindings: []credBinding{two[0], two[0]}}, false},
		{"version 2 with an unknown provider", credRunRecord{V: 2, Bindings: []credBinding{two[0], {Provider: "nope", SentinelHash: "c"}}}, false},
		{"version 2 with an empty hash", credRunRecord{V: 2, Bindings: []credBinding{two[0], {Provider: "openai"}}}, false},
		{"a later version", credRunRecord{V: 3, Bindings: two}, false},
	}
	for _, c := range cases {
		if got := credRecordShapeOK(c.rec); got != c.ok {
			t.Errorf("%s: %v, want %v", c.name, got, c.ok)
		}
	}
}

// TestCredHostedSetupNoKeyForAnyProvider: a tool that picks its own
// provider with no stored key of its providers is refused, naming them.
func TestCredHostedSetupNoKeyForAnyProvider(t *testing.T) {
	obs, _ := credEnvForTest(t, true)
	plan := credPlan(obs, "run-cred-set-3")
	plan.Tool = "crush"
	err := credSetup(context.Background(), plan)
	if err == nil || !strings.Contains(err.Error(), "custody_unsatisfiable") || !strings.Contains(err.Error(), "openai") {
		t.Fatalf("setup = %v", err)
	}
	// Under the org route it starts with no sentinel (no stored key to bind).
	credOtherHomeRelay = func() bool { return true }
	if err := credSetup(context.Background(), plan); err != nil {
		t.Fatalf("org route: %v", err)
	}
	env := map[string]string{}
	credEnv(plan, env)
	if len(env) != 0 {
		t.Fatalf("an open tool under the org route got sentinels %v", env)
	}
}

// TestCredInBoxKeysFromTheStore (gap H3): an in_box_api_key run fills a
// key variable the daemon's environment lacks from the stored key, only
// for the providers its tool can use, never over a variable the
// environment sets, and not at all with the component off.
func TestCredInBoxKeysFromTheStore(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	_ = ks.Set(sandboxcred.KeyName("anthropic"), credTestKey)
	_ = ks.Set(sandboxcred.KeyName("openai"), credTestOpenAIKey)
	oldEnv := hostedLookupEnv
	t.Cleanup(func() {
		hostedLookupEnv = oldEnv
		credInBoxCache.Range(func(k, _ any) bool { credInBoxCache.Delete(k); return true })
	})
	hostedLookupEnv = func(n string) (string, bool) {
		if n == "OPENAI_API_KEY" {
			return "sk-from-env", true
		}
		return "", false
	}
	plan := credPlan(obs, "run-inbox-1")
	plan.Custody, plan.Tool = string(vocab.CustodyInBoxAPIKey), "opencode"
	env := map[string]string{"OPENAI_API_KEY": "sk-from-env"}
	credInBoxKeys(plan, env)
	if env["ANTHROPIC_API_KEY"] != credTestKey || env["OPENAI_API_KEY"] != "sk-from-env" || len(env) != 2 {
		t.Fatalf("env %v", env)
	}
	// A vendor-locked tool gets only its own provider's key.
	plan2 := credPlan(obs, "run-inbox-2")
	plan2.Custody, plan2.Tool = string(vocab.CustodyInBoxAPIKey), "codex"
	hostedLookupEnv = func(string) (string, bool) { return "", false }
	env = map[string]string{}
	credInBoxKeys(plan2, env)
	if env["OPENAI_API_KEY"] != credTestOpenAIKey || len(env) != 1 {
		t.Fatalf("codex env %v", env)
	}
	// The agent's environment carries it: agentEnv runs the fill for an
	// in-box plan (its ForwardEnv set), and only then.
	plan2.ForwardEnv = hostedForwardEnvNames
	t.Setenv("OPENAI_API_KEY", "")
	if r := (&hostedRun{plan: plan2}); r.agentEnv()["OPENAI_API_KEY"] != credTestOpenAIKey {
		t.Fatal("agentEnv did not take the stored key")
	}
	// home_relay never takes the stored key into the box.
	plan3 := credPlan(obs, "run-inbox-3")
	env = map[string]string{}
	credInBoxKeys(plan3, env)
	if len(env) != 0 {
		t.Fatalf("home_relay env %v", env)
	}
	// With the component off nothing is read.
	credActive = func(context.Context) bool { return false }
	plan4 := credPlan(obs, "run-inbox-4")
	plan4.Custody, plan4.Tool = string(vocab.CustodyInBoxAPIKey), "opencode"
	env = map[string]string{}
	credInBoxKeys(plan4, env)
	if len(env) != 0 {
		t.Fatalf("component off env %v", env)
	}
}

// newCredLocalRigFor is newCredLocalRig for a run of tool.
func newCredLocalRigFor(t *testing.T, obs, run, tool string) *credLocalRig {
	t.Helper()
	rig := newCredLocalRig(t, obs, run, "127.0.0.1:1")
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: run, Tool: tool, ProjectRoot: "/w", WorkspaceDir: "/w", Roots: []string{"/w"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = sandboxrelayd.RemoveRun(obs, run)
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	return rig
}

// TestCredLocalLaneBindsSeveralProviders: a local run of a tool that picks
// its own provider binds every provider whose key variable the launching
// env carries and whose key is stored, one sentinel each; it stays without
// a lane (the env exactly as launched) when the env carries a key the lane
// could not replace, so no key the tool works with today is taken away.
func TestCredLocalLaneBindsSeveralProviders(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	_ = ks.Set(sandboxcred.KeyName("anthropic"), credTestKey)
	_ = ks.Set(sandboxcred.KeyName("openai"), credTestOpenAIKey)
	live := true
	credLocalHelperLive(t, &live)

	rig := newCredLocalRigFor(t, obs, "run-local-set-1", "crush")
	in := []string{"PATH=/usr/bin", "ANTHROPIC_API_KEY=" + credTestKey, "OPENAI_API_KEY=" + credTestOpenAIKey}
	env := credLocalBoxEnv(rig.h, in)
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if !sandboxcred.IsSentinel(got["ANTHROPIC_API_KEY"]) || !sandboxcred.IsSentinel(got["OPENAI_API_KEY"]) || got["PATH"] != "/usr/bin" || len(got) != 3 {
		t.Fatalf("box env %v", env)
	}
	rec, err := credReadRecord(obs, rig.run)
	if err != nil || rec.V != credRecordVersionSet || rec.Lane != sandboxcred.LaneLocal || len(rec.Bindings) != 2 {
		t.Fatalf("record %+v err %v", rec, err)
	}

	// A Gemini key in the env with no stored Gemini key: no lane at all.
	other := newCredLocalRigFor(t, obs, "run-local-set-2", "crush")
	in2 := append(append([]string(nil), in...), "GEMINI_API_KEY=gm-real")
	if out := credLocalBoxEnv(other.h, in2); strings.Join(out, "\n") != strings.Join(in2, "\n") {
		t.Fatalf("a lane opened over a key it cannot replace: %v", out)
	}
	if _, err := credReadRecord(obs, other.run); err == nil {
		t.Fatal("a record was written for a run with no lane")
	}

	// A vendor-locked tool's lane is unchanged: one provider, version 1.
	one := newCredLocalRigFor(t, obs, "run-local-set-3", "claude-code")
	_ = credLocalBoxEnv(one.h, in)
	if rec, err := credReadRecord(obs, one.run); err != nil || rec.V != credRecordVersion || rec.Provider != "anthropic" || len(rec.DroppedEnv) != 1 {
		t.Fatalf("claude-code record %+v err %v", rec, err)
	}
}
