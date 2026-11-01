package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestHookProbeReadsGooseAtTheRegisteredFailState pins T-885 (guard tamper
// re-test 2026-10-17, node 1): goose's hook entry carries "on_failure":"block"
// only while guard enforcement closes the tool gate, and the auto-registration
// writes it with that answer (autoRegisterOptions). The doctor / launch probe
// built its dry-run registry WITHOUT the answer, so on an enforcing node it
// compared the current entry with the non-enforcing one and reported "missing
// or stale" (sandbox_enforce) at baseline and after every repair. The probe
// now resolves ToolGateFailsClosed the same way, so a hook written for the
// node's state reads as registered, and a hook written for the OTHER state
// still reads as stale (the next registration pass rewrites it).
func TestHookProbeReadsGooseAtTheRegisteredFailState(t *testing.T) {
	const binary = "/opt/observer-t885/observer"
	cases := []struct {
		name        string
		guardTOML   string
		writtenWith bool // ToolGateFailsClosed the hook was registered with
		want        hookRegistrationState
	}{
		{"enforcing node, hook written fail-closed", "[guard]\nenabled = true\nmode = \"enforce\"\n", true, hookRegRegistered},
		{"observing node, hook written fail-open", "[guard]\nenabled = true\nmode = \"observe\"\n", false, hookRegRegistered},
		{"enforcing node, hook written for the other state", "[guard]\nenabled = true\nmode = \"enforce\"\n", false, hookRegNotRegistered},
		{"observing node, hook written for the other state", "[guard]\nenabled = true\nmode = \"observe\"\n", true, hookRegNotRegistered},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			pinToolHomesAt(t, home)
			cfgDir := filepath.Join(home, ".observer")
			if err := os.MkdirAll(cfgDir, 0o700); err != nil {
				t.Fatal(err)
			}
			cfgPath := filepath.Join(cfgDir, "config.toml")
			body := "[observer]\ndb_path = " + tomlString(filepath.Join(cfgDir, "observer.db")) + "\n" + tc.guardTOML
			if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := hookRegistrationOptions(binary, cfgPath).ToolGateFailsClosed; got != registrationToolGateFailsClosed(cfgPath) {
				t.Fatalf("probe ToolGateFailsClosed = %v, the registration resolves %v", got, !got)
			}
			reg, err := hook.NewRegistry(hook.Options{
				BinaryPath: registrationCommand(binary), ConfigPath: cfgPath, HomeDir: home,
				ToolGateFailsClosed: tc.writtenWith,
			})
			if err != nil {
				t.Fatal(err)
			}
			if res := reg.Register("goose"); res.Error != nil || len(res.HooksAdded) == 0 {
				t.Fatalf("register goose: err=%v added=%v", res.Error, res.HooksAdded)
			}
			state, detail, err := checkHookRegistration(binary, cfgPath, "goose", "PreToolUse")
			if err != nil || state != tc.want {
				t.Fatalf("probe = %v (%s, %v), want %v", state, detail, err, tc.want)
			}
		})
	}
}

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	out := []byte{'"'}
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\\' {
			out = append(out, '\\')
		}
		out = append(out, s[i])
	}
	return string(append(out, '"'))
}
