//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// security_deps_offer_test.go is the offer of security.deps to an install
// with no [components] block (lane SEC-D1FIX2 milestone 3 made it one step;
// lane sec-deps4 made it, decision log P-036, after the operator's
// download rulings PT-19).

// TestDepsOfferedWithNoComponentsBlock states what an install with no
// [components] block (every existing install) sees once security.deps is
// offered, with Guard in observe and in enforce: first with nothing set up
// (no signed index, online checks waiting for the disclosure), then with
// the signed index installed, for `npm install left-pad`, a
// private-registry install (a --registry flag, and a scope the project's
// .npmrc maps to a private registry) and a listed malicious package.
func TestDepsOfferedWithNoComponentsBlock(t *testing.T) {
	snap := componentSnapshotForConfig(config.Default())
	if securityInertByDefault() {
		// The managed edition leaves the module inert with no block: the
		// install check does not run and no rule of its pack is composed.
		if securitySelected(snap, securityDepsComponent) || slices.Contains(securityActivePacks(snap), securityDepsComponent) {
			t.Fatal("security.deps runs with no [components] block in an edition that leaves the module inert")
		}
		return
	}
	if !securitySelected(snap, securityDepsComponent) {
		t.Fatal("security.deps does not run with no [components] block although it is offered")
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
	depsScopeHome(t)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("# an existing install: no [components] block\n[guard]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	proj := t.TempDir()
	if r, err := filepath.EvalSymlinks(proj); err == nil {
		proj = r
	}
	writeFile(t, filepath.Join(proj, ".npmrc"), "@corp:registry=https://npm.corp.example/\n")
	type want struct {
		rule             string
		observe, enforce policy.Decision
	}
	check := func(stage, session, cmd string, w want) {
		t.Helper()
		ev := policy.Event{
			Kind: policy.KindShellExec, Target: cmd, ActionType: "run_command", SessionID: session, Cwd: proj, ProjectRoot: proj,
			Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}, Now: time.Unix(1, 0),
		}
		res, err := securityInstallChecker(cfgPath)(context.Background(), hookctx.InstallRequest{ProjectRoot: proj, Event: &ev})
		if err != nil {
			t.Fatal(err)
		}
		sec := &policy.Security{Posture: policy.SecurityPostureClean, Packs: packs, Installs: res.Checks, InstallCustomRegistry: res.CustomRegistry, InstallManifest: res.Manifest}
		sec.Install, sec.InstallSource = secfeed.Summarize(res.Checks)
		ev.Security = sec
		for m, d := range map[policy.Mode]policy.Decision{policy.ModeObserve: w.observe, policy.ModeEnforce: w.enforce} {
			got := engines[m].Evaluate(ev)
			if got.Decision != d || got.RuleID != w.rule {
				t.Errorf("%s, %s, %q: %s by %q, want %s by %q", stage, m, cmd, got.Decision, got.RuleID, d, w.rule)
			}
		}
	}
	const (
		leftPad   = "npm install left-pad"
		flagged   = "npm install --registry https://npm.corp.example internal-lib"
		corpScope = "npm install @corp/internal-lib"
		evil      = "npm install evil-pkg"
	)
	// Nothing set up: one quiet note per session ("package checks are not
	// set up yet"), nothing louder, S-745 included.
	check("not set up", "s1", leftPad, want{"S-744", policy.DecisionFlag, policy.DecisionFlag})
	check("not set up", "s1", leftPad, want{"", policy.DecisionAllow, policy.DecisionAllow})
	check("not set up", "s1", flagged, want{"", policy.DecisionAllow, policy.DecisionAllow})
	check("not set up", "s1", corpScope, want{"", policy.DecisionAllow, policy.DecisionAllow})
	check("not set up", "s1", evil, want{"", policy.DecisionAllow, policy.DecisionAllow})

	// The signed index installed (downloaded with index_download on, the
	// default, or imported), online checks still waiting for the disclosure: the
	// offline list decides; nothing is asked online.
	installTestIndex(t, depsContentStore(cfgPath).Root)
	check("index installed", "s2", leftPad, want{"", policy.DecisionAllow, policy.DecisionAllow})
	check("index installed", "s2", flagged, want{"S-745", policy.DecisionFlag, policy.DecisionFlag})
	check("index installed", "s2", corpScope, want{"", policy.DecisionAllow, policy.DecisionAllow})
	check("index installed", "s2", evil, want{"S-741", policy.DecisionAsk, policy.DecisionDeny})
}

// TestDepsIndexDownloadKey is the operator's ruling PT-19 (1): the signed
// index download is automatic with no consent, and
// [security.deps].index_download is its off switch, on by default; the
// retired string values still load (lane sec-deps4 audit finding 8:
// "after_consent" reads off, "always" on).
func TestDepsIndexDownloadKey(t *testing.T) {
	if !config.Default().Security.Deps.IndexDownload {
		t.Fatal("index_download is not on by default")
	}
	for _, tc := range []struct {
		on, online bool
		want       bool
	}{
		{true, false, true},
		{true, true, true},
		{false, true, false},
		{false, false, false},
	} {
		if got := depsIndexDownloadAllowed(config.SecurityDepsConfig{IndexDownload: tc.on, Online: tc.online}); got != tc.want {
			t.Errorf("%+v: %v", tc, got)
		}
	}
	dir := t.TempDir()
	for body, want := range map[string]bool{
		"[security.deps]\nindex_download = false\n":             false,
		"[security.deps]\nindex_download = true\n":              true,
		"[security.deps]\nindex_download = \"after_consent\"\n": false,
		"[security.deps]\nindex_download = \"always\"\n":        true,
	} {
		p := filepath.Join(dir, "c.toml")
		writeFile(t, p, "[components]\nadd = [\"security.deps\"]\n"+body)
		cfg, err := config.Load(config.LoadOptions{GlobalPath: p})
		if err != nil {
			t.Errorf("%q: load err %v", body, err)
			continue
		}
		if got := depsIndexDownloadAllowed(cfg.Security.Deps); got != want {
			t.Errorf("%q: download allowed %v, want %v", body, got, want)
		}
	}
}
