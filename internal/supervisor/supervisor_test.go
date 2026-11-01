package supervisor

import (
	"path/filepath"
	"testing"
)

// TestDetectTable: one case per rules row, plus the no-match edges.
func TestDetectTable(t *testing.T) {
	home := filepath.FromSlash("/home/dev")
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	files := func(paths ...string) func(string) bool {
		set := map[string]bool{}
		for _, p := range paths {
			set[p] = true
		}
		return func(p string) bool { return set[p] }
	}
	cases := []struct {
		name string
		p    Probe
		want Mechanism
	}{
		{"linux: running under a systemd unit", Probe{GOOS: "linux", Getenv: env(map[string]string{"INVOCATION_ID": "abc"})}, MechanismSystemd},
		{"linux: user unit installed", Probe{GOOS: "linux", HomeDir: home, Exists: files(filepath.Join(home, ".config", "systemd", "user", SystemdUnit))}, MechanismSystemd},
		{"linux: global user unit", Probe{GOOS: "linux", Exists: files("/etc/systemd/user/" + SystemdUnit)}, MechanismSystemd},
		{"linux: system unit", Probe{GOOS: "linux", Exists: files("/etc/systemd/system/" + SystemdUnit)}, MechanismSystemd},
		{"darwin: running under the launchd job", Probe{GOOS: "darwin", Getenv: env(map[string]string{"XPC_SERVICE_NAME": LaunchdLabel})}, MechanismLaunchd},
		{"darwin: user agent installed", Probe{GOOS: "darwin", HomeDir: home, Exists: files(filepath.Join(home, "Library", "LaunchAgents", LaunchdLabel+".plist"))}, MechanismLaunchd},
		{"darwin: global agent", Probe{GOOS: "darwin", Exists: files("/Library/LaunchAgents/" + LaunchdLabel + ".plist")}, MechanismLaunchd},
		{"darwin: launch daemon", Probe{GOOS: "darwin", Exists: files("/Library/LaunchDaemons/" + LaunchdLabel + ".plist")}, MechanismLaunchd},
		{"windows: service installed", Probe{GOOS: "windows", ServiceExists: func(n string) bool { return n == WindowsService }}, MechanismWindowsService},
	}
	if len(cases) != len(rules) {
		t.Fatalf("%d cases for %d rules: add one case per row", len(cases), len(rules))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(tc.p)
			if !got.Detected || got.Mechanism != tc.want || got.Evidence == "" {
				t.Fatalf("Detect = %+v, want %q", got, tc.want)
			}
		})
	}
	for name, p := range map[string]Probe{
		"nothing on linux":                {GOOS: "linux", HomeDir: home, Getenv: env(nil), Exists: files()},
		"a terminal launch on darwin":     {GOOS: "darwin", Getenv: env(map[string]string{"XPC_SERVICE_NAME": "0"})},
		"a linux env var on windows":      {GOOS: "windows", Getenv: env(map[string]string{"INVOCATION_ID": "abc"})},
		"nil probes":                      {GOOS: "linux"},
		"another service name on windows": {GOOS: "windows", ServiceExists: func(n string) bool { return n == "Other" }},
	} {
		if got := Detect(p); got.Detected {
			t.Errorf("%s: Detect = %+v, want none", name, got)
		}
	}
}
