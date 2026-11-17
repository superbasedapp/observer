package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// writePolicyStateConfig writes a config.toml carrying only the
// [org_client.share].policy_state line, padded so a flip always changes the
// file's size (mtime granularity on some filesystems is coarse).
func writePolicyStateConfig(t *testing.T, path string, on bool, pad int) {
	t.Helper()
	body := "[org_client.share]\npolicy_state = false\n"
	if on {
		body = "[org_client.share]\npolicy_state = true\n"
	}
	for i := 0; i < pad; i++ {
		body += "# pad\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestPolicyStateLocalSwitchIsLive is round 3 bug 3: the reporter's local
// [org_client.share].policy_state opt-in is read live, so turning it on (or
// off) in config.toml while the daemon runs reports (or stops reporting) at
// once, without a restart. Table: each row flips the file and checks what
// report() does.
func TestPolicyStateLocalSwitchIsLive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writePolicyStateConfig(t, path, false, 0)
	fp := &fakePoster{}
	rep := newPolicyStateReporter(fp, fourReaders(), seqCounter(t), "v", false, nil)
	rep.localSwitch = newLiveConfigSwitch(config.Config{}, path, func(c config.Config) bool { return c.OrgClient.Share.PolicyState }, nil)

	steps := []struct {
		name      string
		on        bool
		wantPosts int
	}{
		{"off at start: dormant", false, 0},
		{"turned on while running: reports", true, 1},
		{"still on: reports again", true, 2},
		{"turned off while running: dormant again", false, 2},
	}
	for i, st := range steps {
		writePolicyStateConfig(t, path, st.on, i+1)
		rep.report(context.Background())
		if got := fp.callCount(); got != st.wantPosts {
			t.Fatalf("%s: posts = %d, want %d", st.name, got, st.wantPosts)
		}
	}
}

// TestWatchLiveConfigSwitchPokesOnChange: a change of the value (not merely
// of the file) wakes the reporter.
func TestWatchLiveConfigSwitchPokesOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writePolicyStateConfig(t, path, false, 0)
	sw := newLiveConfigSwitch(config.Config{}, path, func(c config.Config) bool { return c.OrgClient.Share.PolicyState }, nil)
	var pokes atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchLiveConfigSwitch(ctx, sw, func() { pokes.Add(1) }, 10*time.Millisecond)

	writePolicyStateConfig(t, path, false, 3) // file changed, value did not
	time.Sleep(100 * time.Millisecond)
	if n := pokes.Load(); n != 0 {
		t.Fatalf("pokes after a value-preserving edit = %d, want 0", n)
	}
	writePolicyStateConfig(t, path, true, 5)
	deadline := time.Now().Add(5 * time.Second)
	for pokes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if pokes.Load() == 0 {
		t.Fatal("turning policy_state on never woke the reporter")
	}
	if !sw.value() {
		t.Fatal("switch value = false after the file turned it on")
	}
}
