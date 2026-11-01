// clinecli_test.go — `observer cline-cli` provider-routing preparation.
//
// Regression for the 2026-10-02 demo-node report "cline-cli was not starting
// after installation": a fresh `npm install -g cline` has NO
// ~/.cline/data/settings/providers.json, the launcher refused with an error
// Cobra had been told to silence, and the dashboard terminal exited 1 with no
// explanation. The launcher now starts cline unrouted into its own onboarding
// on a fresh install (with a note on how to opt into proxy routing), launches
// unrouted when the operator chose a different provider, routes only through
// an existing openai-compatible entry, and renders every remaining refusal.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

const clineTestBaseURL = "http://127.0.0.1:8820/v1"

// clineLauncherEnvOverride, when set by a test, is the CLINE_* environment
// clineLauncherRun launches with (default: none set).
var clineLauncherEnvOverride map[string]string

// clineTestOpenAI is the proxy's fixed OpenAI upstream in these tests (the
// [proxy].openai_upstream default).
const clineTestOpenAI = "https://api.openai.com"

var clineTestNow = time.Date(2026, 10, 2, 15, 41, 16, 673_000_000, time.UTC)

// TestDecideClineRouteRules has one case per clineRouteRules row (plus the
// precedence between them).
func TestDecideClineRouteRules(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state clineProvidersState
		want  clineRouteAction
	}{
		{"fresh install: no providers.json", clineProvidersState{missing: true}, clineRouteOnboard},
		{"openai-compatible already on the proxy", clineProvidersState{hasCompat: true, compatTarget: clineTargetObserver, configured: 1}, clineRouteSetBaseURL},
		{"openai-compatible on the OpenAI endpoint", clineProvidersState{hasCompat: true, compatTarget: clineTargetOpenAI, configured: 1}, clineRouteSetBaseURL},
		{"openai-compatible on OpenAI beside other providers", clineProvidersState{hasCompat: true, compatTarget: clineTargetOpenAI, configured: 3}, clineRouteSetBaseURL},
		{"openai-compatible on a foreign endpoint (Sol A5-03)", clineProvidersState{hasCompat: true, compatTarget: clineTargetForeign, configured: 1}, clineRouteForeignCompat},
		{"no provider configured yet", clineProvidersState{configured: 0}, clineRouteOnboard},
		{"another provider configured", clineProvidersState{configured: 1}, clineRouteDirect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideClineRoute(tc.state); got != tc.want {
				t.Fatalf("decideClineRoute(%+v) = %v, want %v", tc.state, got, tc.want)
			}
		})
	}
}

func clineProvidersPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), ".cline", "data", "settings", "providers.json")
}

func writeClineProvidersFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readClineProviders(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read providers.json: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("parse providers.json: %v\n%s", err, data)
	}
	return root
}

func clineCompatEntry(t *testing.T, root map[string]any) (entry, settings map[string]any) {
	t.Helper()
	providers, _ := root["providers"].(map[string]any)
	entry, _ = providers[clineCompatProvider].(map[string]any)
	if entry == nil {
		t.Fatalf("no %s entry in %v", clineCompatProvider, root)
	}
	settings, _ = entry["settings"].(map[string]any)
	if settings == nil {
		t.Fatalf("entry has no settings: %v", entry)
	}
	return entry, settings
}

// assertClineOnboardNote pins the fresh-install note: unrouted, capture still
// on, and the exact opt-in command carrying the real proxy URL.
func assertClineOnboardNote(t *testing.T, note string) {
	t.Helper()
	for _, want := range []string{
		"no provider configured yet", "onboarding", "NOT routed", "still captured",
		"cline auth openai-compatible -k <key> -m <model> -b " + clineTestBaseURL,
		"routes automatically",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("note %q missing %q", note, want)
		}
	}
}

// TestPrepareClineRouteFreshInstallOnboardsUnrouted is the reported case: no
// file at all. Nothing is created (a keyless openai-compatible entry forced
// with -P would start cline into a provider whose first prompt fails); cline
// runs its own onboarding, unrouted, and the note says how to opt in.
func TestPrepareClineRouteFreshInstallOnboardsUnrouted(t *testing.T) {
	path := clineProvidersPath(t)
	route, err := prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow)
	if err != nil {
		t.Fatalf("prepareClineRouteAt: %v", err)
	}
	if route.action != clineRouteOnboard {
		t.Fatalf("action = %v, want onboard", route.action)
	}
	assertClineOnboardNote(t, route.note)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("fresh install created providers.json (stat err %v)", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("fresh install created the settings dir (stat err %v)", err)
	}
}

func TestPrepareClineRouteEmptyProvidersOnboardsUntouched(t *testing.T) {
	path := clineProvidersPath(t)
	body := `{"version":1,"lastUsedProvider":"cline","modes":{"x":1},"providers":{}}`
	writeClineProvidersFixture(t, path, body)
	route, err := prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow)
	if err != nil || route.action != clineRouteOnboard {
		t.Fatalf("route = %+v, err = %v; want onboard", route, err)
	}
	assertClineOnboardNote(t, route.note)
	if got, _ := os.ReadFile(path); string(got) != body {
		t.Errorf("onboard launch modified providers.json:\n%s", got)
	}
}

// TestPrepareClineRouteExistingEntryKeepsEverythingElse pins the routed
// contract for an entry on the OpenAI endpoint the proxy forwards to: only
// baseUrl changes, the key and cline's own stamp survive, and the old
// endpoint is put back after the session.
func TestPrepareClineRouteExistingEntryKeepsEverythingElse(t *testing.T) {
	path := clineProvidersPath(t)
	writeClineProvidersFixture(t, path, `{"version":1,"lastUsedProvider":"openai-compatible","providers":{
	  "openai-compatible":{"settings":{"provider":"openai-compatible","model":"gpt-4o","apiKey":"sk-test-not-a-secret","baseUrl":"https://api.openai.com/v1"},"updatedAt":"2026-01-01T00:00:00.000Z","tokenSource":"manual"},
	  "anthropic":{"settings":{"provider":"anthropic","apiKey":"sk-ant-test"},"updatedAt":"2026-01-01T00:00:00.000Z","tokenSource":"manual"}}}`)
	route, err := prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow)
	if err != nil || route.action != clineRouteSetBaseURL || route.note != "" {
		t.Fatalf("route = %+v, err = %v; want set-baseUrl with no note", route, err)
	}
	root := readClineProviders(t, path)
	entry, settings := clineCompatEntry(t, root)
	if settings["baseUrl"] != clineTestBaseURL || settings["apiKey"] != "sk-test-not-a-secret" || settings["model"] != "gpt-4o" {
		t.Errorf("settings = %v", settings)
	}
	if entry["updatedAt"] != "2026-01-01T00:00:00.000Z" {
		t.Errorf("cline's own stamp was rewritten: %v", entry["updatedAt"])
	}
	other := root["providers"].(map[string]any)["anthropic"].(map[string]any)["settings"].(map[string]any)
	if other["apiKey"] != "sk-ant-test" {
		t.Errorf("another provider's settings changed: %v", other)
	}
	if route.restore == nil {
		t.Fatal("restore = nil; the launcher changed the endpoint and must put it back")
	}
	if err := route.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	_, settings = clineCompatEntry(t, readClineProviders(t, path))
	if settings["baseUrl"] != "https://api.openai.com/v1" || settings["apiKey"] != "sk-test-not-a-secret" {
		t.Errorf("after restore settings = %v, want the original endpoint back", settings)
	}
}

// TestPrepareClineRouteForeignEndpointIsNeverRetargeted (Sol A5-03, D-119): an
// openai-compatible entry configured for another service carries THAT
// service's key. Pointing it at the proxy would forward the key to the
// proxy's fixed OpenAI upstream and leave the user's provider retargeted
// after cline exits. It must be left byte-identical and launched unrouted.
func TestPrepareClineRouteForeignEndpointIsNeverRetargeted(t *testing.T) {
	for _, endpoint := range []string{
		"https://my-resource.openai.azure.com/openai/v1",
		"https://openrouter.ai/api/v1",
		"https://llm-gateway.corp.example/v1",
		"http://127.0.0.1:4000/v1", // another local proxy (LiteLLM) is not Observer
		"http://api.openai.com/v1", // plain http is not the https upstream
	} {
		t.Run(endpoint, func(t *testing.T) {
			path := clineProvidersPath(t)
			body := `{"providers":{"openai-compatible":{"settings":{"provider":"openai-compatible","apiKey":"sk-test-not-a-secret","baseUrl":"` +
				endpoint + `"},"updatedAt":"x","tokenSource":"manual"}}}`
			writeClineProvidersFixture(t, path, body)
			route, err := prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow)
			if err != nil {
				t.Fatalf("prepareClineRouteAt: %v", err)
			}
			if route.action != clineRouteForeignCompat || route.restore != nil {
				t.Fatalf("route = %+v; want foreign-compat (unrouted) with nothing to restore", route)
			}
			if !strings.Contains(route.note, "NOT routing") || !strings.Contains(route.note, "wrong service") {
				t.Errorf("note = %q", route.note)
			}
			if got, _ := os.ReadFile(path); string(got) != body {
				t.Errorf("a foreign endpoint was rewritten:\n%s", got)
			}
		})
	}
}

// TestRestoreClineBaseURLIsCompareAndSwap: a change the operator (or cline)
// made during the session wins over the restore.
func TestRestoreClineBaseURLIsCompareAndSwap(t *testing.T) {
	path := clineProvidersPath(t)
	writeClineProvidersFixture(t, path, `{"providers":{"openai-compatible":{"settings":{"apiKey":"sk-test-not-a-secret"},"updatedAt":"x","tokenSource":"manual"}}}`)
	route, err := prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow)
	if err != nil || route.restore == nil {
		t.Fatalf("route = %+v err = %v; want a routed launch with a restore", route, err)
	}
	changed := `{"providers":{"openai-compatible":{"settings":{"apiKey":"sk-test-not-a-secret","baseUrl":"https://their-new-endpoint.example/v1"},"updatedAt":"y","tokenSource":"manual"}}}`
	writeClineProvidersFixture(t, path, changed)
	if err := route.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != changed {
		t.Errorf("restore overwrote a change made during the session:\n%s", got)
	}

	// The unchanged case: an endpoint that was ABSENT is removed again.
	writeClineProvidersFixture(t, path, `{"providers":{"openai-compatible":{"settings":{"apiKey":"k"},"updatedAt":"x","tokenSource":"manual"}}}`)
	route, err = prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow)
	if err != nil || route.restore == nil {
		t.Fatalf("route = %+v err = %v", route, err)
	}
	if err := route.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, settings := clineCompatEntry(t, readClineProviders(t, path)); settings["baseUrl"] != nil || settings["apiKey"] != "k" {
		t.Errorf("after restore settings = %v, want no baseUrl and the key kept", settings)
	}
}

func TestPrepareClineRouteUnstampedEntryGetsStamp(t *testing.T) {
	path := clineProvidersPath(t)
	writeClineProvidersFixture(t, path, `{"version":1,"providers":{"openai-compatible":{"settings":{"provider":"openai-compatible","baseUrl":"`+clineTestBaseURL+`"}}}}`)
	if _, err := prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow); err != nil {
		t.Fatal(err)
	}
	entry, _ := clineCompatEntry(t, readClineProviders(t, path))
	if entry["updatedAt"] == nil || entry["tokenSource"] != "manual" {
		t.Errorf("stamp not filled: %v", entry)
	}
}

func TestPrepareClineRouteAlreadyPointedIsNoWrite(t *testing.T) {
	path := clineProvidersPath(t)
	body := `{"providers":{"openai-compatible":{"settings":{"baseUrl":"` + clineTestBaseURL + `"},"updatedAt":"x","tokenSource":"manual"}}}`
	writeClineProvidersFixture(t, path, body)
	if _, err := prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); string(got) != body {
		t.Errorf("file rewritten although already pointed at the proxy:\n%s", got)
	}
}

// TestPrepareClineRouteOtherProviderLaunchesDirect: an operator who chose a
// different provider is not hijacked; the file is untouched and the note says
// the launch is NOT routed.
func TestPrepareClineRouteOtherProviderLaunchesDirect(t *testing.T) {
	path := clineProvidersPath(t)
	body := `{"version":1,"lastUsedProvider":"anthropic","providers":{"anthropic":{"settings":{"provider":"anthropic"}}}}`
	writeClineProvidersFixture(t, path, body)
	route, err := prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow)
	if err != nil || route.action != clineRouteDirect {
		t.Fatalf("route = %+v, err = %v; want direct", route, err)
	}
	if !strings.Contains(route.note, "NOT routing") || !strings.Contains(route.note, "cline auth openai-compatible") {
		t.Errorf("note = %q", route.note)
	}
	if got, _ := os.ReadFile(path); string(got) != body {
		t.Errorf("direct launch modified providers.json:\n%s", got)
	}
}

// TestPrepareClineRouteBrokenFileIsVisibleRefusal: a corrupt file still
// refuses, but with a bounded message the silenced launcher renders, never the
// resolved absolute path.
func TestPrepareClineRouteBrokenFileIsVisibleRefusal(t *testing.T) {
	for name, body := range map[string]string{"invalid JSON": "{not json", "null": "null"} {
		t.Run(name, func(t *testing.T) {
			path := clineProvidersPath(t)
			writeClineProvidersFixture(t, path, body)
			_, err := prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow)
			var visible launcherMessageError
			if !errors.As(err, &visible) {
				t.Fatalf("err = %v, want a visible launcher error", err)
			}
			msg := visible.launcherMessage()
			if !strings.Contains(msg, clineProvidersDisplay) || strings.Contains(msg, path) {
				t.Errorf("message = %q; want the ~ spelling, not %s", msg, path)
			}
		})
	}
}

// clineLauncherRun executes `observer cline-cli` against a recording stub
// with HOME pointed at a throwaway dir. It returns the child argv (nil when
// the stub never ran), the launcher's own stderr, and the returned error.
func clineLauncherRun(t *testing.T, home string, args ...string) ([]string, string, error) {
	t.Helper()
	originalRuntimeDir := agentRuntimeDir
	originalLoginPathDirs := daemonLoginPathDirs
	agentRuntimeDir = func() string { return "" }
	daemonLoginPathDirs = func() []string { return nil }
	t.Cleanup(func() {
		agentRuntimeDir = originalRuntimeDir
		daemonLoginPathDirs = originalLoginPathDirs
	})
	setTestHome(t, home)
	for _, k := range []string{"CLINE_DIR", "CLINE_DATA_DIR", "CLINE_PROVIDER_SETTINGS_PATH"} {
		t.Setenv(k, clineLauncherEnvOverride[k])
	}
	dir := t.TempDir()
	cfgPath := writeCopilotCLITestConfig(t, dir)
	argvPath := filepath.Join(dir, "argv.out")
	stub := writeArgvEnvRecorderStub(t, dir, argvPath, filepath.Join(dir, "env.out"))

	output := new(bytes.Buffer)
	root := &cobra.Command{Use: "observer", SilenceUsage: true}
	child := newClineCLICmd()
	root.AddCommand(child)
	base := []string{
		"cline-cli", "--config", cfgPath, "--cline-path", stub,
		"--no-attach", "--proxy", "http://127.0.0.1:1",
	}
	root.SetArgs(append(base, args...))
	root.SetOut(output)
	root.SetErr(output)
	executed, err := root.ExecuteC()
	renderSuppressedLauncherError(output, root, executed, err)
	if _, statErr := os.Stat(argvPath); statErr != nil {
		return nil, output.String(), err
	}
	return readRecordedArgv(t, argvPath), output.String(), err
}

func TestClineLauncherFreshInstallStartsUnroutedOnboarding(t *testing.T) {
	home := t.TempDir()
	argv, stderr, err := clineLauncherRun(t, home)
	if err != nil {
		t.Fatalf("launch failed: %v\n%s", err, stderr)
	}
	if len(argv) != 0 {
		t.Fatalf("child argv = %v, want none (no -P: cline's own onboarding runs)", argv)
	}
	if !strings.Contains(stderr, "no provider configured yet") ||
		!strings.Contains(stderr, "-b http://127.0.0.1:1/v1") || strings.Contains(stderr, "routing via") {
		t.Errorf("stderr must carry only the onboarding note with the real proxy URL:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(home, ".cline")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("fresh-install launch wrote under ~/.cline (stat err %v)", err)
	}
}

func TestClineLauncherExistingCompatEntryStartsRouted(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".cline", "data", "settings", "providers.json")
	writeClineProvidersFixture(t, path, `{"providers":{"openai-compatible":{"settings":{"provider":"openai-compatible","apiKey":"sk-test-not-a-secret"},"updatedAt":"x","tokenSource":"manual"}}}`)
	argv, stderr, err := clineLauncherRun(t, home)
	if err != nil {
		t.Fatalf("launch failed: %v\n%s", err, stderr)
	}
	if proxyNotInBuild() {
		// D-514: a build without capture.proxy launches cline unrouted, names
		// the build, and leaves the entry exactly as it was.
		if len(argv) != 0 || !strings.Contains(stderr, "not in this build") {
			t.Fatalf("child argv = %v, stderr = %q; want an unrouted launch naming the build", argv, stderr)
		}
		_, settings := clineCompatEntry(t, readClineProviders(t, path))
		if settings["baseUrl"] != nil || settings["apiKey"] != "sk-test-not-a-secret" {
			t.Errorf("settings = %v, want the original entry untouched", settings)
		}
		return
	}
	if want := []string{"-P", clineCompatProvider}; !equalArgs(argv, want) {
		t.Fatalf("child argv = %v, want %v", argv, want)
	}
	// Routed for the session, then put back once cline exited (Sol A5-03):
	// the entry had no baseUrl, so it has none again and keeps its key.
	_, settings := clineCompatEntry(t, readClineProviders(t, path))
	if settings["baseUrl"] != nil || settings["apiKey"] != "sk-test-not-a-secret" {
		t.Errorf("settings after exit = %v, want the original (no baseUrl) back", settings)
	}
}

// TestClineLauncherForeignCompatEndpointStartsUnrouted (Sol A5-03): an
// openai-compatible provider on another service is launched with its own
// endpoint and key, unrouted, and providers.json is never written.
func TestClineLauncherForeignCompatEndpointStartsUnrouted(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".cline", "data", "settings", "providers.json")
	body := `{"providers":{"openai-compatible":{"settings":{"provider":"openai-compatible","apiKey":"sk-test-not-a-secret","baseUrl":"https://openrouter.ai/api/v1"},"updatedAt":"x","tokenSource":"manual"}}}`
	writeClineProvidersFixture(t, path, body)
	argv, stderr, err := clineLauncherRun(t, home, "--", "--verbose")
	if err != nil {
		t.Fatalf("launch failed: %v\n%s", err, stderr)
	}
	if want := []string{"--verbose"}; !equalArgs(argv, want) {
		t.Fatalf("child argv = %v, want %v (no -P: unrouted)", argv, want)
	}
	if !strings.Contains(stderr, "NOT routing") || strings.Contains(stderr, "routing via") {
		t.Errorf("stderr must carry only the not-routed note:\n%s", stderr)
	}
	if got, _ := os.ReadFile(path); string(got) != body {
		t.Errorf("providers.json was rewritten:\n%s", got)
	}
}

func TestClineLauncherOtherProviderStartsUnrouted(t *testing.T) {
	home := t.TempDir()
	writeClineProvidersFixture(t, filepath.Join(home, ".cline", "data", "settings", "providers.json"),
		`{"providers":{"anthropic":{"settings":{"provider":"anthropic"}}}}`)
	argv, stderr, err := clineLauncherRun(t, home, "--", "--verbose")
	if err != nil {
		t.Fatalf("launch failed: %v\n%s", err, stderr)
	}
	if want := []string{"--verbose"}; !equalArgs(argv, want) {
		t.Fatalf("child argv = %v, want %v (no -P: the operator's provider is kept)", argv, want)
	}
	if !strings.Contains(stderr, "NOT routing") || strings.Contains(stderr, "routing via") ||
		strings.Contains(stderr, "not reachable") {
		t.Errorf("stderr must carry only the not-routed note:\n%s", stderr)
	}
}

func TestClineLauncherBrokenProvidersRefusesVisibly(t *testing.T) {
	home := t.TempDir()
	writeClineProvidersFixture(t, filepath.Join(home, ".cline", "data", "settings", "providers.json"), "{oops")
	argv, stderr, err := clineLauncherRun(t, home)
	if err == nil || argv != nil {
		t.Fatalf("err = %v, argv = %v; want a refusal before cline starts", err, argv)
	}
	if !strings.Contains(stderr, "is not valid JSON") || strings.Contains(stderr, "Usage:") {
		t.Errorf("refusal not rendered (or usage printed):\n%s", stderr)
	}
}

// TestClineLauncherUtilitySubcommandIgnoresProviderFile: `cline auth` and
// `cline doctor` are how a broken provider file is fixed, so they must never
// be blocked by it.
func TestClineLauncherUtilitySubcommandIgnoresProviderFile(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".cline", "data", "settings", "providers.json")
	writeClineProvidersFixture(t, path, "{oops")
	argv, stderr, err := clineLauncherRun(t, home, "--", "doctor")
	if err != nil {
		t.Fatalf("doctor was blocked: %v\n%s", err, stderr)
	}
	if len(argv) == 0 || argv[len(argv)-1] != "doctor" {
		t.Fatalf("child argv = %v, want it to end in doctor", argv)
	}
	if got, _ := os.ReadFile(path); string(got) != "{oops" {
		t.Errorf("a utility subcommand rewrote providers.json: %q", got)
	}
}

// TestResolveToolBinNotFoundIsVisible: the not-installed verdict is rendered
// by a silenced launcher instead of exiting 1 with no output.
func TestResolveToolBinNotFoundIsVisible(t *testing.T) {
	empty := t.TempDir()
	// resolveEnv is process-memoized; pin an empty filesystem so a cline
	// installed on the test host cannot satisfy the lookup.
	swapResolveEnv(t, fakeEnv("linux", false, empty, nil, []string{empty}, map[string]os.FileMode{}))
	_, err := resolveToolBin("cline-cli", "", "--cline-path", filepath.Join(empty, "none.toml"), new(bytes.Buffer))
	var visible launcherMessageError
	if !errors.As(err, &visible) {
		t.Fatalf("err = %v, want a visible launcher error", err)
	}
	if !strings.Contains(visible.launcherMessage(), "cline-cli: not installed") {
		t.Errorf("message = %q", visible.launcherMessage())
	}
}
