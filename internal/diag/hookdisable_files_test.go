package diag

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
)

// pinSwitchEnv blanks every env-scope switch variable for the test.
func pinSwitchEnv(t *testing.T) {
	t.Helper()
	for _, s := range hookdisable.Switches {
		if s.Scope == hookdisable.ScopeEnv {
			t.Setenv(s.Key, "")
		}
	}
}

// TestHookSwitchFilesMatchTheirHomeRel pins each user row's File (FU-38) to
// a catalogue row whose default path (no relocation) is the row's own
// HomeRel on every OS, so naming the FileRow moves no file the row read
// before and only the relocation rules change where it reads.
func TestHookSwitchFilesMatchTheirHomeRel(t *testing.T) {
	const home = "/h"
	rows := map[string]agentconfig.FileRow{}
	for _, r := range agentconfig.Files() {
		rows[r.ID] = r
	}
	for _, s := range hookdisable.Switches {
		for _, id := range []string{s.File, s.DenyHooksFile} {
			if id == "" {
				continue
			}
			if _, ok := rows[id]; !ok {
				t.Errorf("%s: File %s is not a catalogue row", s.ID, id)
			}
		}
		if s.File == "" {
			continue
		}
		for _, goos := range []string{"linux", "darwin", "windows"} {
			rel := s.HomeRel
			if r, ok := s.HomeRelOS[goos]; ok {
				rel = r
			}
			resolve := hookSwitchUserFiles(home, goos, func(string) string { return "" })
			got, ok := resolve(s.File)
			want := agentconfig.PathEnv{GOOS: goos}.Join(home, rel)
			if !ok || got != want {
				t.Errorf("%s on %s: %s resolves to %q, want %q", s.ID, goos, s.File, got, want)
			}
		}
	}
}

// TestHookSwitchUserFilesRelocate pins FU-38 end to end: with
// CODEBUDDY_CONFIG_DIR set, the doctor's inputs read the relocated
// settings file, not the default home's; a sandboxed run stays in its home.
func TestHookSwitchUserFilesRelocate(t *testing.T) {
	home, moved := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codebuddy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codebuddy", "settings.json"), []byte(`{"disableAllHooks":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moved, "settings.json"), []byte(`{"disableAllHooks":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"CODEBUDDY_CONFIG_DIR": moved}
	getenv := func(k string) string { return env[k] }
	o := HookSwitchInputs(hookdisable.Options{Home: home, GOOS: runtime.GOOS, Getenv: getenv, ReadFile: os.ReadFile})
	var got []string
	for _, f := range hookdisable.Detect(o) {
		if f.SwitchID == "codebuddy.disableAllHooks" {
			got = append(got, f.Path)
		}
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], moved) {
		t.Fatalf("findings at %v, want one under %s", got, moved)
	}
	o = HookSwitchInputs(hookdisable.Options{Home: home, Getenv: getenv, ReadFile: os.ReadFile})
	for _, f := range hookdisable.Detect(o) {
		if f.SwitchID == "codebuddy.disableAllHooks" {
			t.Fatalf("sandboxed run left the override home: %+v", f)
		}
	}
}
