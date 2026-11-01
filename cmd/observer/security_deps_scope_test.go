//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// depsScopeHome points the user and config directories at an empty
// temporary home, so the machine running the test adds nothing.
func depsScopeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	for _, k := range []string{
		"GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOPROXY", "GOENV", "NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG",
		"NPM_CONFIG_GLOBALCONFIG", "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CONFIG_FILE", "UV_CONFIG_FILE", "UV_INDEX_URL", "CARGO_HOME",
		"VIRTUAL_ENV", "PROGRAMDATA", "CARGO_REGISTRY_DEFAULT", "BUN_CONFIG_REGISTRY", "YARN_NPM_REGISTRY_SERVER",
	} {
		t.Setenv(k, "")
	}
	return home
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDepsScopeReadsEveryDirectory is milestone 1a: a private scope named
// in a subdirectory's .npmrc keeps the name private for `cd frontend &&
// npm i`, for the working directory itself and for --prefix; a project
// root the hook does not know makes every name private.
func TestDepsScopeReadsEveryDirectory(t *testing.T) {
	depsScopeHome(t)
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	writeFile(t, filepath.Join(root, "frontend", ".npmrc"), "@corp:registry=https://npm.corp.example/\n")
	writeFile(t, filepath.Join(root, "svc", "pip.conf"), "[global]\nindex-url = https://pypi.corp.example/simple\n")
	corp := secfeed.ParseSpec(secfeed.EcoNpm, "@corp/x")
	for _, tc := range []struct {
		name, cmd, cwd string
		eco            secfeed.Ecosystem
		spec           string
		public         bool
	}{
		{"root only", "npm i @corp/x", root, secfeed.EcoNpm, "@corp/x", true},
		{"cd then install", "cd frontend && npm i @corp/x", root, secfeed.EcoNpm, "@corp/x", false},
		{"working directory", "npm i @corp/x", filepath.Join(root, "frontend"), secfeed.EcoNpm, "@corp/x", false},
		{"deeper working directory", "npm i @corp/x", filepath.Join(root, "frontend", "src", "a"), secfeed.EcoNpm, "@corp/x", false},
		{"--prefix", "npm --prefix frontend i @corp/x", root, secfeed.EcoNpm, "@corp/x", false},
		{"-C", "pnpm -C frontend add @corp/x", root, secfeed.EcoNpm, "@corp/x", false},
		{"pip cd", "cd svc && pip install requests", root, secfeed.EcoPyPI, "requests", false},
		{"unresolved cd", "cd $X && npm i left-pad", root, secfeed.EcoNpm, "left-pad", false},
		{"public name", "cd frontend && npm i left-pad", root, secfeed.EcoNpm, "left-pad", true},
		// Lane SEC-DEPS3 item 9: no working directory is Unknown, never
		// "the root", so even a public name stays private.
		{"no working directory", "npm i left-pad", "", secfeed.EcoNpm, "left-pad", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := &policy.Event{Kind: policy.KindShellExec, Target: tc.cmd, Cwd: tc.cwd}
			scope := hookDepsScope(hookctx.InstallRequest{ProjectRoot: root, Event: ev}, nil)
			sp := secfeed.ParseSpec(tc.eco, tc.spec)
			for side, cls := range map[string]secfeed.Classifier{"hook": hookDepsClassifier(scope), "daemon": depsClassifier(scope)} {
				got := cls != nil && cls(sp)
				if got != tc.public {
					t.Errorf("%s: public=%v want %v (scope %+v)", side, got, tc.public, scope)
				}
			}
		})
	}
	// No project root: nothing public, on either side.
	none := hookDepsScope(hookctx.InstallRequest{Event: &policy.Event{Kind: policy.KindShellExec, Target: "npm i left-pad", Cwd: root}}, nil)
	if hookDepsClassifier(none) != nil || depsClassifier(none) != nil {
		t.Error("no project root must classify nothing public")
	}
	// A manifest edit reads its own directory.
	ev := &policy.Event{
		Kind: policy.KindFileAccess, Target: filepath.Join(root, "frontend", "package.json"), Cwd: root,
		Edits: []policy.ProposedEdit{{Old: "{}", New: `{"dependencies":{"@corp/x":"1.0.0"}}`}},
	}
	if cls := hookDepsClassifier(hookDepsScope(hookctx.InstallRequest{ProjectRoot: root, Event: ev}, nil)); cls != nil && cls(corp) {
		t.Error("a manifest in frontend/ reads frontend/.npmrc")
	}
	// A manifest edit at an absolute path needs no working directory: its
	// own directory's chain applies, so a public name stays public.
	left := secfeed.ParseSpec(secfeed.EcoNpm, "left-pad")
	ev = &policy.Event{
		Kind: policy.KindFileAccess, Target: filepath.Join(root, "frontend", "package.json"),
		Edits: []policy.ProposedEdit{{Old: "{}", New: `{"dependencies":{"left-pad":"1.3.0"}}`}},
	}
	if cls := hookDepsClassifier(hookDepsScope(hookctx.InstallRequest{ProjectRoot: root, Event: ev}, nil)); cls == nil || !cls(left) {
		t.Error("a manifest edit at an absolute path with no working directory keeps a public name public")
	}
	ev.Target = filepath.Join("frontend", "package.json")
	if cls := hookDepsClassifier(hookDepsScope(hookctx.InstallRequest{ProjectRoot: root, Event: ev}, nil)); cls != nil && cls(left) {
		t.Error("a relative manifest path with no working directory is Unknown")
	}
}

// TestDepsScopeEnvOnlyRestricts is milestone 1b: the developer's variables
// the hook passes make a name private on the daemon even when the daemon's
// own environment says nothing, and can never make public what the
// daemon's environment keeps private.
func TestDepsScopeEnvOnlyRestricts(t *testing.T) {
	depsScopeHome(t)
	root := t.TempDir()
	mod := secfeed.ParseSpec(secfeed.EcoGo, "corp.example/lib@v1.0.0")
	pub := secfeed.ParseSpec(secfeed.EcoGo, "github.com/pkg/errors@v0.9.1")
	scope := hookDepsScope(hookctx.InstallRequest{ProjectRoot: root, Event: &policy.Event{Kind: policy.KindShellExec, Target: "go get corp.example/lib@v1.0.0", Cwd: root}},
		[]string{"GOPRIVATE=corp.example", "PATH=/bin"})
	if scope.Env["GOPRIVATE"] != "corp.example" || scope.Env["PATH"] != "" {
		t.Fatalf("scope env %v", scope.Env)
	}
	for side, cls := range map[string]secfeed.Classifier{"hook": hookDepsClassifier(scope), "daemon": depsClassifier(scope)} {
		if cls(mod) {
			t.Errorf("%s: a GOPRIVATE path from the developer's shell was public", side)
		}
		if !cls(pub) {
			t.Errorf("%s: a public module was private", side)
		}
	}
	// The daemon's own GOPRIVATE holds even when the hook's variables say
	// GOPROXY is the public proxy and name nothing private.
	t.Setenv("GOPRIVATE", "corp.example")
	quiet := secfeed.Scope{ProjectRoot: root, Env: map[string]string{"GOPROXY": "https://proxy.golang.org,direct"}}
	if depsClassifier(quiet)(mod) {
		t.Error("the hook's variables made a daemon-private path public")
	}
	// A virtual environment named by the developer's shell is read.
	venv := t.TempDir()
	writeFile(t, filepath.Join(venv, "pip.conf"), "[global]\nindex-url = https://pypi.corp.example/simple\n")
	vs := secfeed.Scope{ProjectRoot: root, Env: map[string]string{"VIRTUAL_ENV": venv}}
	if depsClassifier(vs)(secfeed.ParseSpec(secfeed.EcoPyPI, "requests")) {
		t.Error("$VIRTUAL_ENV/pip.conf was not read")
	}
}

// TestDepsUserFiles is milestone 1b's file list: each file names a
// private source and makes the name private.
func TestDepsUserFiles(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name string
		file func(home string) string
		body string
		eco  secfeed.Ecosystem
		spec string
	}{
		{"macOS pip", func(h string) string { return filepath.Join(h, "Library", "Application Support", "pip", "pip.conf") }, "[global]\nindex-url = https://p.corp.example/simple\n", secfeed.EcoPyPI, "requests"},
		{"uv xdg", func(h string) string { return filepath.Join(h, ".config", "uv", "uv.toml") }, "index-url = \"https://p.corp.example/simple\"\n", secfeed.EcoPyPI, "requests"},
		{"bunfig user", func(h string) string { return filepath.Join(h, ".bunfig.toml") }, "[install]\nregistry = \"https://b.corp.example/\"\n", secfeed.EcoNpm, "left-pad"},
		{"yarn 1 user", func(h string) string { return filepath.Join(h, ".yarnrc") }, "registry \"https://y.corp.example/\"\n", secfeed.EcoNpm, "left-pad"},
		{"cargo home", func(h string) string { return filepath.Join(h, ".cargo", "config.toml") }, "[source.crates-io]\nreplace-with = \"corp\"\n", secfeed.EcoCargo, "serde"},
		{"project bunfig", func(string) string { return filepath.Join(root, "bunfig.toml") }, "[install.scopes]\ncorp = \"https://b.corp.example/\"\n", secfeed.EcoNpm, "@corp/x"},
		{"project yarn 1", func(string) string { return filepath.Join(root, ".yarnrc") }, "\"@corp:registry\" \"https://y.corp.example/\"\n", secfeed.EcoNpm, "@corp/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := depsScopeHome(t)
			path := tc.file(home)
			writeFile(t, path, tc.body)
			defer func() { _ = os.Remove(path) }()
			if depsClassifier(secfeed.Scope{ProjectRoot: root})(secfeed.ParseSpec(tc.eco, tc.spec)) {
				t.Errorf("%s did not make %s private", path, tc.spec)
			}
		})
	}
	// $CARGO_HOME moves the user cargo file.
	home := depsScopeHome(t)
	ch := filepath.Join(home, "cargohome")
	writeFile(t, filepath.Join(ch, "config.toml"), "[source.crates-io]\nreplace-with = \"corp\"\n")
	s := secfeed.Scope{ProjectRoot: root, Env: map[string]string{"CARGO_HOME": ch}}
	if depsClassifier(s)(secfeed.ParseSpec(secfeed.EcoCargo, "serde")) {
		t.Error("$CARGO_HOME/config.toml was not read")
	}
}

// TestPrefetchSendsOnlyConfirmedNames is milestone 1c: the prefetch sends
// only the manifest names an ask classified public for that project, never
// the raw dependency list.
func TestPrefetchSendsOnlyConfirmedNames(t *testing.T) {
	depsScopeHome(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "package.json"), `{"dependencies":{"left-pad":"1.3.0","internal-thing":"2.0.0"}}`)
	writeFile(t, filepath.Join(root, "go.mod"), "module corp.example/app\n\nrequire corp.example/secret v1.0.0\n")
	c := &depsConfirmed{}
	if _, _, ok := c.filter(root, projectManifestSpecs(root, 100)); ok {
		t.Fatal("nothing is confirmed before an ask")
	}
	var sent []string
	svc := secfeed.NewService(secfeed.ServiceOptions{
		Classify: depsClassifier, Confirmed: c.add,
		Lookup: func(_ context.Context, specs []secfeed.InstallSpec) []secfeed.OnlineAnswer {
			var out []secfeed.OnlineAnswer
			for _, s := range specs {
				sent = append(sent, s.Name)
				out = append(out, secfeed.OnlineAnswer{Eco: s.Eco, Name: secfeed.Normalize(s.Eco, s.Name), Version: s.Version, Status: secfeed.OnlineNotFound})
			}
			return out
		},
	})
	svc.Answer(context.Background(), secfeed.Scope{ProjectRoot: root}, []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad@1.0.0")})
	sent = nil
	scope, specs, ok := c.filter(root, projectManifestSpecs(root, 100))
	if !ok || len(specs) != 1 || specs[0].Name != "left-pad" || scope.ProjectRoot != root {
		t.Fatalf("filter %v %+v", ok, specs)
	}
	svc.Prefetch(context.Background(), scope, specs)
	if len(sent) != 1 || sent[0] != "left-pad" {
		t.Errorf("prefetch sent %v", sent)
	}
}

// TestOnlineOffTakesEffectLive is milestone 2c: turning online checks off
// in the config file is read at the next ask without a restart, and the
// hook's settings file stops the hook asking.
func TestOnlineOffTakesEffectLive(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	writeFile(t, cfgPath, "[security.deps]\nonline = true\n")
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil || !cfg.Security.Deps.Online {
		t.Fatalf("load %v %+v", err, cfg.Security.Deps)
	}
	secDir := filepath.Join(dir, "security")
	live := newDepsLiveDeps(cfgPath, secDir, cfg.Security)
	live.setServing(true)
	if s := readDepsHookSettings(secDir); !s.Ask || !s.Online {
		t.Fatalf("settings at start %+v", s)
	}
	env := &depsEnv{cfg: cfg, live: live, disclose: secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: time.Now(), Surface: "cli", Verified: true}}
	if !env.onlineReady() {
		t.Fatal("online at start")
	}
	writeFile(t, cfgPath, "[security.deps]\nonline = false   # turned off\n")
	if env.onlineReady() {
		t.Error("online checks still on after the config turned them off")
	}
	if s := readDepsHookSettings(secDir); s.Ask || s.Online {
		t.Errorf("the hook's settings were not rewritten: %+v", s)
	}
	// A config that no longer loads sends nothing.
	writeFile(t, cfgPath, "[security.deps]\nonline = true\n")
	if !env.onlineReady() {
		t.Error("turning it back on is read too")
	}
	writeFile(t, cfgPath, "[security.deps\nonline = true # broken\n")
	if env.onlineReady() {
		t.Error("an unreadable config must not keep online checks on")
	}
}
