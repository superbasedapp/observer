//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secask"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secfeed/online"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// installTestIndex installs a signed two-kind index into the content store
// of a config under dir and points depsTrust at the test key.
func installTestIndex(t *testing.T, root string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	prev := depsTrust
	depsTrust = func() contentchan.Trust { return contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}} }
	t.Cleanup(func() { depsTrust = prev })

	mal, _ := secfeed.MaliciousFromOSV([][]byte{[]byte(`{"id":"MAL-1","affected":[{"package":{"ecosystem":"npm","name":"evil-pkg"}}]}`)})
	pop, _ := secfeed.PopularFromList(secfeed.EcoNpm, []byte("react\nlodash\n"))
	store := contentchan.Store{Root: root}
	for _, k := range []struct {
		kind content.Kind
		name string
		data []byte
	}{
		{content.MaliciousPackages, secfeed.MaliciousArtifact, secfeed.EncodeMalicious(mal)},
		{content.PopularNames, secfeed.PopularArtifact, secfeed.EncodePopular(map[secfeed.Ecosystem][]string{secfeed.EcoNpm: pop})},
	} {
		m, err := secfeed.BuildManifest(secfeed.ManifestInput{Kind: k.kind, ManifestVersion: 1, Issued: time.Now().Add(-time.Minute), Validity: 7 * 24 * time.Hour, Name: k.name, Data: k.data})
		if err != nil {
			t.Fatal(err)
		}
		env, err := content.Sign(m, priv)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := content.EncodeEnvelope(env)
		if _, err := store.Install(k.kind, b, map[string][]byte{k.name: k.data}, depsTrust()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHookInstallCheckerOffline(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	installTestIndex(t, depsContentStore(cfg).Root)
	check := securityInstallChecker(cfg)
	res, err := check(context.Background(), hookctx.InstallRequest{Event: &policy.Event{Kind: policy.KindShellExec, Target: "npm install evil-pkg lodahs react --registry=https://x.example"}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]policy.InstallVerdict{}
	for _, c := range res.Checks {
		got[c.Name] = c.Verdict
	}
	// The --registry flag makes every name private (X4): the offline
	// listing still decides, and a private name is never a near miss.
	if got["evil-pkg"] != policy.InstallMalicious || got["lodahs"] != policy.InstallNotChecked || got["react"] != policy.InstallKnownGood || !res.CustomRegistry {
		t.Errorf("checks %+v", res)
	}
	proj := t.TempDir()
	res, _ = check(context.Background(), hookctx.InstallRequest{ProjectRoot: proj, Event: &policy.Event{Kind: policy.KindShellExec, Target: "npm install lodahs", Cwd: proj}})
	if len(res.Checks) != 1 || res.Checks[0].Verdict != policy.InstallNearMiss {
		t.Errorf("near miss without a registry flag: %+v", res)
	}
	// With no project root known, every name is private (X4, lane
	// SEC-D1FIX2 milestone 1a): not a near miss, never asked about.
	res, _ = check(context.Background(), hookctx.InstallRequest{Event: &policy.Event{Kind: policy.KindShellExec, Target: "npm install lodahs"}})
	if len(res.Checks) != 1 || !res.Checks[0].Private || res.Checks[0].Verdict == policy.InstallNearMiss {
		t.Errorf("no project root: %+v", res)
	}
	// Not an install: nothing to check, no index read.
	if res, _ := check(context.Background(), hookctx.InstallRequest{Event: &policy.Event{Kind: policy.KindShellExec, Target: "ls"}}); len(res.Checks) != 0 {
		t.Errorf("ls: %+v", res)
	}

	// No index installed and online checks not set up: not checked, with
	// one quiet S-744 note per session (TestNotSetUpQuietNote), never a
	// flag on every install.
	empty := filepath.Join(t.TempDir(), "config.toml")
	res, _ = securityInstallChecker(empty)(context.Background(), hookctx.InstallRequest{Event: &policy.Event{Kind: policy.KindShellExec, Target: "npm install some-pkg"}})
	if len(res.Checks) != 1 || res.Checks[0].Verdict != policy.InstallNotChecked || res.Checks[0].Reason != secfeed.ReasonNotSetUp {
		t.Errorf("no index: %+v", res)
	}
}

func TestSecurityDepsEnrichNeedsThePack(t *testing.T) {
	calls := 0
	hc := hookctx.Host(context.Background(), hookctx.Request{}, hookctx.Source{}, hookctx.HostProviders{
		Install: func(context.Context, hookctx.InstallRequest) (hookctx.InstallResult, error) {
			calls++
			return hookctx.InstallResult{}, nil
		},
	})
	ev := &policy.Event{Kind: policy.KindShellExec, Target: "npm i x"}
	hc.Security = &policy.Security{Packs: []string{"security"}}
	securityDepsEnrich(context.Background(), hc, ev, "/r")
	if calls != 0 {
		t.Error("the install check ran without the security.deps pack")
	}
	hc.Security.Packs = append(hc.Security.Packs, securityDepsComponent)
	securityDepsEnrich(context.Background(), hc, ev, "/r")
	if calls != 1 {
		t.Error("the install check did not run with the pack")
	}
}

func TestVerifyDependencyCheck(t *testing.T) {
	dir := t.TempDir()
	installTestIndex(t, dir)
	dc, err := verifyDependencyCheck(dir)
	if err != nil {
		t.Fatal(err)
	}
	hits, manifest := dc("web/package.json", "  \"evil-pkg\": \"1.0.0\",\n  \"lodahs\": \"^1\",\n")
	if !manifest || len(hits) != 2 {
		t.Errorf("hits %+v manifest=%v", hits, manifest)
	}
	if _, err := verifyDependencyCheck(t.TempDir()); err == nil {
		t.Error("an empty directory must be refused")
	}
}

// TestManagedNodeMakesZeroPublicRequests is the JSP-11 zero-request test
// (X19): on a managed node the security service is handed the relay, never
// the public client; with the relay down every answer is failed and the
// public client, pointed at a server that fails on any request, is never
// used.
func TestManagedNodeMakesZeroPublicRequests(t *testing.T) {
	var public atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		public.Add(1)
		t.Errorf("a managed node reached a public source: %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()
	eps := map[string]string{online.OSVHost: srv.URL, online.FeedHost: srv.URL}
	for _, e := range secfeed.Ecosystems() {
		eps[e.MetadataHost] = srv.URL
	}
	publicBuilt := false
	publicCtor := func() secfeed.Lookup {
		publicBuilt = true
		return publicDepsLookup(online.New(online.Options{HTTP: srv.Client(), Endpoints: eps}))
	}
	relayDown := func() secfeed.Lookup {
		return func(_ context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
			var out []secfeed.OnlineAnswer
			for _, s := range specs {
				out = append(out, secfeed.OnlineAnswer{Eco: s.Eco, Name: s.Name, Status: secfeed.OnlineFailed, Reason: "relay_unavailable"})
			}
			return out
		}
	}
	lookup := depsLookupFor(func(context.Context) depsTenancy { return depsManaged }, publicCtor, relayDown)
	svc := secfeed.NewService(secfeed.ServiceOptions{
		Classify: func(secfeed.Scope) secfeed.Classifier { return secfeed.NewClassifier(secfeed.PrivConfig{}) },
		Lookup:   lookup, Enabled: func() bool { return true },
	})
	got := svc.Answer(context.Background(), secfeed.Scope{ProjectRoot: "/r"}, []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad")})
	if publicBuilt || public.Load() != 0 {
		t.Fatalf("public client built=%v requests=%d", publicBuilt, public.Load())
	}
	if len(got) != 1 || got[0].Status != secfeed.OnlineFailed {
		t.Errorf("relay down must be online_unknown, never a public fallback: %+v", got)
	}
	// The answer through a real org relay is
	// TestManagedNodeAnswersThroughARealRelay (security_relay_node_test.go):
	// it needs the private org server packages, so it lives in the file the
	// public staging sweep drops whole.
	// An individual node gets the public client and no relay.
	relayBuilt := false
	indiv := depsLookupFor(func(context.Context) depsTenancy { return depsIndividual }, func() secfeed.Lookup {
		publicBuilt = true
		return func(context.Context, []secfeed.InstallSpec) []secfeed.OnlineAnswer { return nil }
	}, func() secfeed.Lookup { relayBuilt = true; return nil })
	_ = indiv(context.Background(), []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad")})
	if !publicBuilt || relayBuilt {
		t.Errorf("individual: public=%v relay=%v", publicBuilt, relayBuilt)
	}
}

// TestDisclosureGatesTheFirstQuery: no online query before the disclosure
// is accepted; a terminal start shows it and records nothing (milestone
// 3b: consent is an explicit action), and an explicit accept turns the
// checks on (P-011, D-764 Q23).
func TestDisclosureGatesTheFirstQuery(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	env := &depsEnv{cfg: cfg, dir: dir, logger: newLogger("error"), disclose: readDepsDisclosure(dir)}
	if env.onlineReady() {
		t.Fatal("online checks are ready before the disclosure")
	}
	var out strings.Builder
	env.showDisclosureOnTerminal(&out, false)
	if out.Len() != 0 || env.onlineReady() || readDepsDisclosure(dir).Shown() {
		t.Fatal("a headless daemon must not record the disclosure")
	}
	env.showDisclosureOnTerminal(&out, true)
	for _, want := range []string{"api.osv.dev", "superbased.app", "Code security", "security.deps.online"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the terminal text lacks %q: %q", want, out.String())
		}
	}
	if env.onlineReady() || readDepsDisclosure(dir).Shown() {
		t.Fatal("a terminal start must not record consent")
	}
	if _, err := recordDepsDisclosure(dir, "terminal", time.Now()); err == nil {
		t.Error("a terminal start is not a surface that records consent")
	}
	d, err := recordDepsDisclosure(dir, "dashboard", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	env.disclose = d
	if !env.onlineReady() {
		t.Error("an explicit accept turns the checks on")
	}
	out.Reset()
	env.showDisclosureOnTerminal(&out, true)
	if out.Len() != 0 {
		t.Error("an accepted disclosure is not shown again")
	}
	cfg.Security.Deps.Online = false
	env.cfg = cfg
	if env.onlineReady() {
		t.Error("online off must not be ready")
	}
	// A record an earlier build wrote from a terminal start does not count.
	if secfeed.DecodeDisclosure([]byte(`{"version":2,"shown_at":"2026-10-01T00:00:00Z","surface":"terminal"}`), depsRecordKey(dir)).Shown() {
		t.Error("a terminal record must not count as consent")
	}
}

// TestHookAsksTheDaemon drives the hook provider against a live ask
// endpoint backed by a service with a fake lookup: a cache miss for a
// public name waits for the daemon and gets its answer; a private name is
// answered private by the daemon and never looked up.
func TestHookAsksTheDaemon(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC")
	}
	base, err := os.MkdirTemp("", "dh")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	cfgPath := filepath.Join(base, "config.toml")
	dir := secposture.LayoutFor(cfgPath).Dir
	installTestIndex(t, depsContentStore(cfgPath).Root)
	var looked []string
	svc := secfeed.NewService(secfeed.ServiceOptions{
		Classify: func(secfeed.Scope) secfeed.Classifier {
			return secfeed.NewClassifier(secfeed.PrivConfig{NpmScopeRegistries: map[string]string{"@corp": "https://npm.corp.example/"}})
		},
		Lookup: func(_ context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
			var out []secfeed.OnlineAnswer
			for _, s := range specs {
				looked = append(looked, s.Name)
				out = append(out, secfeed.OnlineAnswer{Eco: s.Eco, Name: s.Name, Status: secfeed.OnlineNotFound})
			}
			return out
		},
		Enabled: func() bool { return true },
	})
	ln, _, err := secask.Listen(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = secask.Serve(ctx, ln, svc.Answer) }()
	cfg := config.Default()
	if err := writeDepsSettings(dir, cfg, true); err != nil {
		t.Fatal(err)
	}
	// The event carries its working directory: with none the names are
	// private (lane SEC-DEPS3 item 9) and nothing is asked.
	proj := filepath.Join(base, "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	res, err := securityInstallChecker(cfgPath)(context.Background(), hookctx.InstallRequest{
		ProjectRoot: proj, Event: &policy.Event{Kind: policy.KindShellExec, Target: "npm install made-up-pkg @corp/secret-lib", Cwd: proj},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Checks) != 2 || res.Checks[0].Verdict != policy.InstallUnknownName || res.Checks[0].Reason != secfeed.ReasonNotFound {
		t.Fatalf("checks %+v", res.Checks)
	}
	if !res.Checks[1].Private || len(looked) != 1 || looked[0] != "made-up-pkg" {
		t.Errorf("the private name must never be looked up: %+v %v", res.Checks[1], looked)
	}
}

func TestImportDepsIndex(t *testing.T) {
	src := t.TempDir()
	installTestIndex(t, src) // the store layout is the import layout
	dst := contentchan.Store{Root: t.TempDir()}
	n, err := importDepsIndex(src, dst)
	if err != nil || n != 2 {
		t.Fatalf("import %d %v", n, err)
	}
	if _, err := importDepsIndex(t.TempDir(), dst); err == nil {
		t.Error("an empty directory must be an error")
	}
}
