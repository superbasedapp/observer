package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// configCheckFixture builds a fresh tmp CODEX_HOME for a single
// branch-test of checkCodexConfigTOMLBaseURL. The fixture returns
// the codex_home path so the test can pass it as the single-element
// slice to the helper.
type configCheckFixture struct {
	t         *testing.T
	codexHome string
}

func newConfigCheckFixture(t *testing.T) *configCheckFixture {
	t.Helper()
	base := t.TempDir()
	codexHome := filepath.Join(base, "codex_home")
	if err := os.MkdirAll(codexHome, 0o755); err != nil {
		t.Fatal(err)
	}
	return &configCheckFixture{t: t, codexHome: codexHome}
}

func (f *configCheckFixture) writeConfigTOML(body string) {
	f.t.Helper()
	path := filepath.Join(f.codexHome, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

const testProxyURL = "http://127.0.0.1:8820"

// TestCodexNoProxyRouteConflict_FailsClosed: a config.toml that still routes
// openai_base_url to the proxy makes codexNoProxyRouteConflict return a
// non-nil, self-explanatory error (B3-1) naming the file, the key, the
// write-config origin, and the .bak revert path.
func TestCodexNoProxyRouteConflict_FailsClosed(t *testing.T) {
	f := newConfigCheckFixture(t)
	f.writeConfigTOML("openai_base_url = \"http://127.0.0.1:8820/v1\"\n")
	err := codexNoProxyRouteConflict([]string{f.codexHome}, testProxyURL, "")
	if err == nil {
		t.Fatal("expected a fail-closed error when config routes to the proxy")
	}
	msg := err.Error()
	for _, want := range []string{
		filepath.Join(f.codexHome, "config.toml"),
		"openai_base_url",
		"--write-config",
		".bak",
		"refusing to launch",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("fail-closed error missing %q:\n%s", want, msg)
		}
	}
}

// TestCodexNoProxyRouteConflict_CleanIsNil: when no config routes to the proxy
// (a config pointing at api.openai.com, or no key), the guard returns nil so
// --no-proxy-route launches normally.
func TestCodexNoProxyRouteConflict_CleanIsNil(t *testing.T) {
	f := newConfigCheckFixture(t)
	f.writeConfigTOML("openai_base_url = \"https://api.openai.com/v1\"\n")
	if err := codexNoProxyRouteConflict([]string{f.codexHome}, testProxyURL, ""); err != nil {
		t.Fatalf("non-proxy config must not fail closed, got: %v", err)
	}
	// A CODEX_HOME with no config.toml at all is also clean.
	g := newConfigCheckFixture(t)
	if err := codexNoProxyRouteConflict([]string{g.codexHome}, testProxyURL, ""); err != nil {
		t.Fatalf("missing config must not fail closed, got: %v", err)
	}
}

// TestCodexConfigsRoutingToProxy_Shapes exercises every config shape the guard
// must recognize (or ignore): the legacy top-level openai_base_url key, the
// managed model_provider + [model_providers.*] provider-table shape observer's
// own registrar writes, loopback host equivalence (localhost vs 127.0.0.1 vs
// [::1]), the /v1-suffix tolerance, a non-proxy provider (no conflict), a
// provider table present but NOT selected (inert — no conflict), and a
// different port (no conflict).
func TestCodexConfigsRoutingToProxy_Shapes(t *testing.T) {
	const managedProxyV1 = "" +
		"model_provider = \"openai-observer\"\n" +
		"[model_providers.openai-observer]\n" +
		"base_url = \"http://127.0.0.1:8820/v1\"\n"

	cases := []struct {
		name         string
		body         string
		wantConflict bool
	}{
		{"top-level key v1", "openai_base_url = \"http://127.0.0.1:8820/v1\"\n", true},
		{"top-level key no-suffix", "openai_base_url = \"http://127.0.0.1:8820\"\n", true},
		{"top-level key localhost", "openai_base_url = \"http://localhost:8820/v1\"\n", true},
		{"managed provider shape", managedProxyV1, true},
		{
			"managed provider localhost equivalence",
			"model_provider = \"openai-observer\"\n" +
				"[model_providers.openai-observer]\n" +
				"base_url = \"http://localhost:8820\"\n",
			true,
		},
		{
			"managed provider ipv6 loopback equivalence",
			"model_provider = \"openai-observer\"\n" +
				"[model_providers.openai-observer]\n" +
				"base_url = \"http://[::1]:8820/v1\"\n",
			true,
		},
		{
			"non-proxy provider selected",
			"model_provider = \"openai\"\n" +
				"[model_providers.openai]\n" +
				"base_url = \"https://api.openai.com/v1\"\n",
			false,
		},
		{
			"proxy provider present but not selected",
			"model_provider = \"openai\"\n" +
				"[model_providers.openai]\n" +
				"base_url = \"https://api.openai.com/v1\"\n" +
				"[model_providers.openai-observer]\n" +
				"base_url = \"http://127.0.0.1:8820/v1\"\n",
			false,
		},
		{
			"managed provider different port",
			"model_provider = \"openai-observer\"\n" +
				"[model_providers.openai-observer]\n" +
				"base_url = \"http://127.0.0.1:9999/v1\"\n",
			false,
		},
		{"non-proxy top-level key", "openai_base_url = \"https://api.openai.com/v1\"\n", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newConfigCheckFixture(t)
			f.writeConfigTOML(tc.body)
			offenders := codexConfigsRoutingToProxy([]string{f.codexHome}, testProxyURL, "")
			gotConflict := len(offenders) > 0
			if gotConflict != tc.wantConflict {
				t.Fatalf("codexConfigsRoutingToProxy conflict=%v, want %v (offenders=%v)\nbody:\n%s",
					gotConflict, tc.wantConflict, offenders, tc.body)
			}
			// The fail-closed guard must agree with the low-level detector.
			err := codexNoProxyRouteConflict([]string{f.codexHome}, testProxyURL, "")
			if (err != nil) != tc.wantConflict {
				t.Fatalf("codexNoProxyRouteConflict err=%v, want conflict=%v", err, tc.wantConflict)
			}
		})
	}
}

// TestCodexNoProxyRouteConflict_ManagedShapeMessage: the fail-closed error for
// the managed provider-table shape names the provider so an operator can find
// and remove the routing.
func TestCodexNoProxyRouteConflict_ManagedShapeMessage(t *testing.T) {
	f := newConfigCheckFixture(t)
	f.writeConfigTOML("model_provider = \"openai-observer\"\n" +
		"[model_providers.openai-observer]\n" +
		"base_url = \"http://127.0.0.1:8820/v1\"\n")
	err := codexNoProxyRouteConflict([]string{f.codexHome}, testProxyURL, "")
	if err == nil {
		t.Fatal("expected a fail-closed error for the managed provider shape")
	}
	for _, want := range []string{"model_provider", "openai-observer", "refusing to launch"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("managed-shape error missing %q:\n%s", want, err.Error())
		}
	}
}

// TestCodexActiveProfile pins the -p/--profile parser used to layer the profile
// overlay file (finding 3a): both flag names, both `=`-joined forms, stop at bare
// --, absent → "".
func TestCodexActiveProfile(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-p", "work"}, "work"},
		{[]string{"--profile", "work"}, "work"},
		{[]string{"-p=work"}, "work"},
		{[]string{"--profile=work"}, "work"},
		{[]string{"-pwork"}, "work"},                   // attached short form (finding N4)
		{[]string{"--model", "gpt", "-pwork"}, "work"}, // attached form amid other flags
		{[]string{"--model", "gpt", "--profile", "work", "exec"}, "work"},
		{[]string{"-m", "-pfoo", "exec"}, ""}, // -pfoo is -m's value, not a profile (finding N4 guard)
		{[]string{"--model", "-pfoo"}, ""},    // long value flag consumes -pfoo
		{[]string{"exec", "hi"}, ""},
		{[]string{"--", "--profile", "hi"}, ""},
		{[]string{"--", "-pwork"}, ""}, // attached form after bare -- is positional
		{nil, ""},
	}
	for _, tc := range cases {
		if got := codexActiveProfile(tc.args); got != tc.want {
			t.Errorf("codexActiveProfile(%v)=%q, want %q", tc.args, got, tc.want)
		}
	}
}

// TestCodexConfigsRoutingToProxy_ProfileOverlay pins finding 3a: the active
// `-p <name>` profile file ($CODEX_HOME/<name>.config.toml) layers ON TOP of the
// base config, so (a) a profile that ADDS a proxy route is caught only when the
// profile is active, and (b) a profile that OVERRIDES a routed base back to a
// non-proxy provider is honored (no conflict) when active.
func TestCodexConfigsRoutingToProxy_ProfileOverlay(t *testing.T) {
	writeProfile := func(t *testing.T, home, name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(home, name+".config.toml"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("profile adds a proxy route (caught only when profile active)", func(t *testing.T) {
		f := newConfigCheckFixture(t)
		f.writeConfigTOML("openai_base_url = \"https://api.openai.com/v1\"\n") // base = non-proxy
		writeProfile(t, f.codexHome, "work", "openai_base_url = \"http://127.0.0.1:8820/v1\"\n")

		if off := codexConfigsRoutingToProxy([]string{f.codexHome}, testProxyURL, ""); len(off) != 0 {
			t.Fatalf("no profile active: want 0 offenders, got %v", off)
		}
		off := codexConfigsRoutingToProxy([]string{f.codexHome}, testProxyURL, "work")
		if len(off) == 0 {
			t.Fatal("profile active: want a conflict from the profile overlay, got none")
		}
		// The offender must be the PROFILE file, not the base config.
		if !strings.Contains(strings.Join(off, ","), "work.config.toml") {
			t.Errorf("offender should name the profile overlay file, got %v", off)
		}
	})

	t.Run("profile overrides a routed base back to a non-proxy provider (no conflict)", func(t *testing.T) {
		f := newConfigCheckFixture(t)
		f.writeConfigTOML("openai_base_url = \"http://127.0.0.1:8820/v1\"\n") // base routes to proxy
		writeProfile(t, f.codexHome, "off", "openai_base_url = \"https://api.openai.com/v1\"\n")

		// Base alone → conflict.
		if off := codexConfigsRoutingToProxy([]string{f.codexHome}, testProxyURL, ""); len(off) == 0 {
			t.Fatal("base config routes to proxy: want a conflict, got none")
		}
		// With the profile that overrides the base to a non-proxy URL → NO conflict.
		if off := codexConfigsRoutingToProxy([]string{f.codexHome}, testProxyURL, "off"); len(off) != 0 {
			t.Fatalf("profile overrides base to non-proxy: want 0 offenders, got %v", off)
		}
	})
}

// TestCheckCodexConfigTOML_NoFileWarns: when config.toml is absent
// the operator hasn't set up routing at all. Warn with the
// create-config-toml instruction so they know what to add.
func TestCheckCodexConfigTOML_NoFileWarns(t *testing.T) {
	f := newConfigCheckFixture(t)
	warn := checkCodexConfigTOMLBaseURL([]string{f.codexHome}, testProxyURL, "")
	if !strings.Contains(warn, "does not exist") {
		t.Errorf("warn should name the missing file: %s", warn)
	}
	if !strings.Contains(warn, `openai_base_url = "http://127.0.0.1:8820/v1"`) {
		t.Errorf("warn should suggest the v1-suffixed URL: %s", warn)
	}
	if !strings.Contains(warn, "V6-2") {
		t.Errorf("warn should reference V6-2: %s", warn)
	}
}

// TestCheckCodexConfigTOML_MissingKeyWarns: file present but
// openai_base_url not set. Most common operator misconfig.
func TestCheckCodexConfigTOML_MissingKeyWarns(t *testing.T) {
	f := newConfigCheckFixture(t)
	f.writeConfigTOML(`model = "gpt-5-codex"` + "\n")
	warn := checkCodexConfigTOMLBaseURL([]string{f.codexHome}, testProxyURL, "")
	if !strings.Contains(warn, "no openai_base_url") {
		t.Errorf("warn should name the missing key: %s", warn)
	}
	if !strings.Contains(warn, `Add `+"`"+`openai_base_url = "http://127.0.0.1:8820/v1"`) {
		t.Errorf("warn should suggest adding the key: %s", warn)
	}
}

// TestCheckCodexConfigTOML_WrongURLWarns: file present and key set,
// but URL points elsewhere. Show both got and want.
func TestCheckCodexConfigTOML_WrongURLWarns(t *testing.T) {
	f := newConfigCheckFixture(t)
	f.writeConfigTOML(`openai_base_url = "https://api.openai.com/v1"` + "\n")
	warn := checkCodexConfigTOMLBaseURL([]string{f.codexHome}, testProxyURL, "")
	if !strings.Contains(warn, `openai_base_url="https://api.openai.com/v1"`) {
		t.Errorf("warn should show current value: %s", warn)
	}
	if !strings.Contains(warn, "http://127.0.0.1:8820/v1") {
		t.Errorf("warn should show expected value: %s", warn)
	}
}

// TestCheckCodexConfigTOML_CorrectURLSilent: happy path — file
// present, key matches, no warning. Pins the "zero stderr on a clean
// host" operator transparency contract from v1.7.4.
func TestCheckCodexConfigTOML_CorrectURLSilent(t *testing.T) {
	f := newConfigCheckFixture(t)
	f.writeConfigTOML(`openai_base_url = "http://127.0.0.1:8820/v1"` + "\n")
	if warn := checkCodexConfigTOMLBaseURL([]string{f.codexHome}, testProxyURL, ""); warn != "" {
		t.Errorf("expected silent success, got warning: %s", warn)
	}
}

// TestCheckCodexConfigTOML_TrailingSlashTolerated: operator might
// write the URL with or without trailing slash, with or without /v1.
// All four shapes are accepted.
func TestCheckCodexConfigTOML_TrailingSlashTolerated(t *testing.T) {
	cases := []string{
		`openai_base_url = "http://127.0.0.1:8820"`,
		`openai_base_url = "http://127.0.0.1:8820/"`,
		`openai_base_url = "http://127.0.0.1:8820/v1"`,
		`openai_base_url = "http://127.0.0.1:8820/v1/"`,
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			f := newConfigCheckFixture(t)
			f.writeConfigTOML(tc + "\n")
			if warn := checkCodexConfigTOMLBaseURL([]string{f.codexHome}, testProxyURL, ""); warn != "" {
				t.Errorf("expected silent, got: %s", warn)
			}
		})
	}
}

// TestCheckCodexConfigTOML_UnreadableFileSilentBestEffort: the file
// exists but TOML parsing fails. The check is diagnostic-only —
// must NEVER fail the wrapper or noise the operator with a non-
// actionable parser error. Silent is the right behavior.
func TestCheckCodexConfigTOML_UnreadableFileSilentBestEffort(t *testing.T) {
	f := newConfigCheckFixture(t)
	f.writeConfigTOML("this is not valid toml = [\nbroken")
	if warn := checkCodexConfigTOMLBaseURL([]string{f.codexHome}, testProxyURL, ""); warn != "" {
		t.Errorf("expected silent best-effort, got: %s", warn)
	}
}

// TestCheckCodexConfigTOML_MultiRootIteration: when crossmount
// returns multiple CODEX_HOME roots, every misconfigured one
// surfaces a warning, joined by newlines. Mirrors the WSL2 case
// where /home/u/.codex AND /mnt/c/Users/u/.codex both exist.
func TestCheckCodexConfigTOML_MultiRootIteration(t *testing.T) {
	a := newConfigCheckFixture(t)
	b := newConfigCheckFixture(t)
	a.writeConfigTOML(`model = "gpt-5-codex"` + "\n")
	b.writeConfigTOML(`openai_base_url = "https://api.openai.com/v1"` + "\n")

	warn := checkCodexConfigTOMLBaseURL([]string{a.codexHome, b.codexHome}, testProxyURL, "")
	if !strings.Contains(warn, "no openai_base_url") {
		t.Errorf("missing-key warn for first root absent: %s", warn)
	}
	if !strings.Contains(warn, "https://api.openai.com/v1") {
		t.Errorf("wrong-URL warn for second root absent: %s", warn)
	}
	if strings.Count(warn, "\n") < 1 {
		t.Errorf("expected multi-line warning, got: %s", warn)
	}
}

// TestCheckCodexConfigTOML_EmptyRootsListSilent pins the trivial
// guard: zero roots → zero warnings, no panic.
func TestCheckCodexConfigTOML_EmptyRootsListSilent(t *testing.T) {
	if warn := checkCodexConfigTOMLBaseURL(nil, testProxyURL, ""); warn != "" {
		t.Errorf("expected silent for empty roots, got: %s", warn)
	}
}
