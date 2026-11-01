package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The S-6 / D9 half of the cline-cli launcher: providers.json is a credential
// file (OAuth tokens and API keys), so the route write is a surgical splice
// of the one member the launcher owns, never a decode-and-re-encode of the
// whole file, and the file is the one cline itself reads given CLINE_*.

//nolint:gosec // G101: a fake fixture value, not a credential.
const clineSurgicalFakeKey = "sk-test-not-real-0000"

// clineSurgicalFixture is deliberately in unsorted key order with uneven
// spacing: the old writer's json.MarshalIndent of a map sorted every key and
// re-indented every provider (red on the old code).
const clineSurgicalFixture = "{\n" +
	"  \"version\": 1,\n" +
	"  \"providers\": {\n" +
	"    \"zz-other\": {\"settings\": {\"apiKey\": \"" + clineSurgicalFakeKey + "\"}, \"updatedAt\": \"x\"},\n" +
	"    \"openai-compatible\": {\n" +
	"      \"settings\": {\"provider\": \"openai-compatible\", \"apiKey\": \"" + clineSurgicalFakeKey + "\", \"baseUrl\": \"https://api.openai.com/v1\"},\n" +
	"      \"updatedAt\": \"2026-01-01T00:00:00.000Z\",\n" +
	"      \"tokenSource\": \"manual\"\n" +
	"    }\n" +
	"  },\n" +
	"  \"lastUsedProvider\":  \"openai-compatible\"\n" +
	"}\n"

func TestPrepareClineRouteIsSurgical(t *testing.T) {
	path := clineProvidersPath(t)
	writeClineProvidersFixture(t, path, clineSurgicalFixture)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	route, err := prepareClineRouteAt(path, clineTestBaseURL, clineTestOpenAI, clineTestNow)
	if err != nil || route.action != clineRouteSetBaseURL || route.restore == nil {
		t.Fatalf("route = %+v, err = %v; want a routed launch with a restore", route, err)
	}
	got, _ := os.ReadFile(path)
	want := strings.Replace(clineSurgicalFixture, "https://api.openai.com/v1", clineTestBaseURL, 1)
	if string(got) != want {
		t.Errorf("the write changed more than settings.baseUrl:\n%s\nwant\n%s", got, want)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
			t.Errorf("mode = %v, want the file's own 0640 kept", fi.Mode().Perm())
		}
	}
	if err := route.restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != clineSurgicalFixture {
		t.Errorf("restore did not give back the original bytes:\n%s", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("the write left extra files beside providers.json: %v", entries)
	}
}

// TestClineProvidersPathFollowsClineEnv: the launcher writes and re-reads
// the providers.json cline reads: CLINE_PROVIDER_SETTINGS_PATH, then
// CLINE_DATA_DIR, then CLINE_DIR (the old launcher hard-coded
// ~/.cline/data/settings/providers.json).
func TestClineProvidersPathFollowsClineEnv(t *testing.T) {
	home := t.TempDir()
	alt := t.TempDir()
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"default", nil, filepath.Join(home, ".cline", "data", "settings", "providers.json")},
		{"file variable", map[string]string{"CLINE_PROVIDER_SETTINGS_PATH": filepath.Join(alt, "p.json"), "CLINE_DIR": home}, filepath.Join(alt, "p.json")},
		{"data dir", map[string]string{"CLINE_DATA_DIR": alt, "CLINE_DIR": home}, filepath.Join(alt, "settings", "providers.json")},
		{"cline home", map[string]string{"CLINE_DIR": alt}, filepath.Join(alt, "data", "settings", "providers.json")},
	} {
		env := tc.env
		if got, err := clineProvidersPathFor(home, func(k string) string { return env[k] }); err != nil || got != tc.want {
			t.Errorf("%s: got %s (%v), want %s", tc.name, got, err, tc.want)
		}
	}
	// FU-31: a relative variable is what cline reads against its own
	// working directory, so no file is named (never the default one).
	if got, err := clineProvidersPathFor(home, func(k string) string {
		if k == "CLINE_DATA_DIR" {
			return "rel"
		}
		return ""
	}); !errors.Is(err, errClineProvidersRelative) || got != "" {
		t.Errorf("relative CLINE_DATA_DIR: got %q, %v; want errClineProvidersRelative", got, err)
	}
}

// TestClineLauncherHonoursClineDataDir: with CLINE_DATA_DIR set, the launch
// routes through the provider file cline reads there (the old launcher found
// no file under ~/.cline and started cline unrouted into onboarding).
func TestClineLauncherHonoursClineDataDir(t *testing.T) {
	if proxyNotInBuild() {
		t.Skip("capture.proxy is not in this build")
	}
	home := t.TempDir()
	data := t.TempDir()
	path := filepath.Join(data, "settings", "providers.json")
	writeClineProvidersFixture(t, path, `{"providers":{"openai-compatible":{"settings":{"apiKey":"`+clineSurgicalFakeKey+`"},"updatedAt":"x","tokenSource":"manual"}}}`)
	t.Setenv("CLINE_DATA_DIR", data)
	stub := clineLauncherRunEnv(t, home)
	if want := []string{"-P", clineCompatProvider}; !equalArgs(stub, want) {
		t.Fatalf("child argv = %v, want %v (routed through $CLINE_DATA_DIR)", stub, want)
	}
	if _, err := os.Stat(filepath.Join(home, ".cline")); err == nil {
		t.Error("the launcher wrote under ~/.cline although CLINE_DATA_DIR moved the store")
	}
}

// clineLauncherRunEnv is clineLauncherRun keeping the caller's CLINE_*
// environment.
func clineLauncherRunEnv(t *testing.T, home string) []string {
	t.Helper()
	keep := map[string]string{}
	for _, k := range []string{"CLINE_DIR", "CLINE_DATA_DIR", "CLINE_PROVIDER_SETTINGS_PATH"} {
		keep[k] = os.Getenv(k)
	}
	clineLauncherEnvOverride = keep
	t.Cleanup(func() { clineLauncherEnvOverride = nil })
	argv, stderr, err := clineLauncherRun(t, home)
	if err != nil {
		t.Fatalf("launch failed: %v\n%s", err, stderr)
	}
	return argv
}
