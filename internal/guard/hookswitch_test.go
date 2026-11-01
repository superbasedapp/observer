package guard

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hookdisable"
)

// TestHookSwitchesForPolicyCoversTheTable pins the projection (T-910):
// every internal/hookdisable row reaches the R-162 table with its key, off
// value and a glob for its file, so a new switch row is refused at the
// agent boundary without a second edit here.
func TestHookSwitchesForPolicyCoversTheTable(t *testing.T) {
	got := hookSwitchesForPolicy()
	for _, s := range hookdisable.Switches {
		if !s.KeySwitch() {
			for _, h := range got {
				if h.Desc == "hook switch "+s.ID {
					t.Errorf("%s: a non-key switch projected to %q", s.ID, h.Glob)
				}
			}
			continue
		}
		want := map[hookdisable.Scope]string{
			hookdisable.ScopeUser:    "~/" + s.HomeRel,
			hookdisable.ScopeProject: "**/" + s.ProjectRel,
		}[s.Scope]
		found := false
		for _, h := range got {
			if h.Desc != "hook switch "+s.ID {
				continue
			}
			if h.Key != s.Key || h.Off != s.Off {
				t.Errorf("%s: key/off = %s/%v", s.ID, h.Key, h.Off)
			}
			if want == "" || h.Glob == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no projected glob (want %q)", s.ID, want)
		}
	}
	for _, h := range got {
		if strings.Contains(h.Glob, `\`) {
			t.Errorf("glob %q keeps a backslash; the engine matches forward slashes", h.Glob)
		}
	}
}

// TestHookSwitchManagedGlobsFromTheFileRow pins CC-5 at the agent
// boundary: Claude Code's managed rows project the Windows file under
// C:\Program Files (the agentconfig FileRow), never the legacy
// C:\ProgramData path, beside the Linux and macOS files.
func TestHookSwitchManagedGlobsFromTheFileRow(t *testing.T) {
	var globs []string
	for _, h := range hookSwitchesForPolicy() {
		if h.Desc == "hook switch claude.managed.disableAllHooks" {
			globs = append(globs, h.Glob)
		}
	}
	for _, want := range []string{
		"/etc/claude-code/managed-settings.json",
		"/Library/Application Support/ClaudeCode/managed-settings.json",
		"C:/Program Files/ClaudeCode/managed-settings.json",
	} {
		if !slices.Contains(globs, want) {
			t.Errorf("globs %v lack %s", globs, want)
		}
	}
	for _, g := range globs {
		if strings.Contains(g, "ProgramData") {
			t.Errorf("glob %s is the legacy path Claude Code does not read", g)
		}
	}
}

// TestReadHookSwitchFile pins the injected reader: content of an existing
// absolute file, unknown for a relative path, a missing file or one over
// the bound.
func TestReadHookSwitchFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "settings.local.json")
	if err := os.WriteFile(p, []byte(`{"disableAllHooks":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, ok := readHookSwitchFile(filepath.ToSlash(p)); !ok || string(b) != `{"disableAllHooks":true}` {
		t.Fatalf("existing file: %q %v", b, ok)
	}
	if _, ok := readHookSwitchFile("relative/settings.json"); ok {
		t.Fatal("relative path read")
	}
	if _, ok := readHookSwitchFile(filepath.ToSlash(filepath.Join(dir, "absent.json"))); ok {
		t.Fatal("missing file read")
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, make([]byte, hookSwitchReadLimit+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readHookSwitchFile(filepath.ToSlash(big)); ok {
		t.Fatal("over-bound file read")
	}
}

// TestHookSwitchManagedDropInGlobs pins FU-35: Claude Code merges
// managed-settings.d/*.json into the managed file, so the drop-ins carry the
// same switch, globbed from the FileRow's DropInDir on every OS.
func TestHookSwitchManagedDropInGlobs(t *testing.T) {
	var globs []string
	for _, h := range hookSwitchesForPolicy() {
		if h.Desc == "hook switch claude.managed.disableAllHooks" {
			globs = append(globs, h.Glob)
		}
	}
	for _, want := range []string{
		"/etc/claude-code/managed-settings.d/*.json",
		"/Library/Application Support/ClaudeCode/managed-settings.d/*.json",
		"C:/Program Files/ClaudeCode/managed-settings.d/*.json",
	} {
		if !slices.Contains(globs, want) {
			t.Errorf("globs %v lack %s", globs, want)
		}
	}
}
