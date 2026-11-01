package main

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestHookDisableWatchFollowsThePinnedHomeRule pins FU-129 for the
// daemon's hook-off watch: its lookup is crossmount.HomeEnvAt for the
// process home, so it reads the relocation variables (and the env-scope
// switches) of the daemon's environment, and none under an isolated home,
// as the managed-integrity layers do.
func TestHookDisableWatchFollowsThePinnedHomeRule(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", outside)

	if got := newHookDisableWatch(nil).getenv("CLAUDE_CONFIG_DIR"); got != outside {
		t.Fatalf("unisolated watch reads %q, want the daemon's CLAUDE_CONFIG_DIR", got)
	}
	crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{Root: t.TempDir(), RealHome: t.TempDir()})
	if crossmount.IsolationReason() == "" {
		t.Fatal("the staged real home did not isolate HOME")
	}
	if got := newHookDisableWatch(nil).getenv("CLAUDE_CONFIG_DIR"); got != "" {
		t.Errorf("an isolated watch reads CLAUDE_CONFIG_DIR = %q, want none", got)
	}
}
