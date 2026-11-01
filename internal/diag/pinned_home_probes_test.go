package diag

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestHookSwitchUserFilesFollowThePinnedHomeRule pins FU-129 for the
// hook-off switch table's user rows: with no lookup passed, the relocation
// variables are read under crossmount.HomeEnvAt, so a home that is not this
// process's own resolves every user file under itself even with
// CLAUDE_CONFIG_DIR set, and the process's own home follows the variable.
func TestHookSwitchUserFilesFollowThePinnedHomeRule(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	t.Setenv("CLAUDE_CONFIG_DIR", outside)

	pinned := t.TempDir()
	p, ok := hookSwitchUserFiles(pinned, runtime.GOOS, nil)("claude-code/user-settings")
	if !ok || !strings.HasPrefix(p, pinned) {
		t.Errorf("a pinned home resolved %q (ok %v), want a file under %s", p, ok, pinned)
	}

	own := t.TempDir()
	t.Setenv("HOME", own)
	t.Setenv("USERPROFILE", own)
	p, ok = hookSwitchUserFiles(own, runtime.GOOS, nil)("claude-code/user-settings")
	if !ok || p != filepath.Join(outside, "settings.json") {
		t.Errorf("the process's own home resolved %q (ok %v), want the CLAUDE_CONFIG_DIR file", p, ok)
	}
}

// TestHooksDisabledReadsTheDoctorsLookup: the hooks.disabled row reads the
// env-scope switches through the lookup it is given (the doctor's one,
// under the pinned-home rule), so a sandboxed doctor (nil) reads none.
func TestHooksDisabledReadsTheDoctorsLookup(t *testing.T) {
	home := t.TempDir()
	pinSwitchEnv(t)
	t.Setenv("JUNIE_CONFIG_DEFAULT_LOCATIONS", "false")
	if c := checkHooksDisabled(home, home, nil, nil); strings.Contains(c.Message, "junie") {
		t.Errorf("a nil lookup read the process environment: %s", c.Message)
	}
	if c := checkHooksDisabled(home, home, nil, os.Getenv); !strings.Contains(c.Message, "junie") {
		t.Errorf("the given lookup was not read: %s", c.Message)
	}
}
