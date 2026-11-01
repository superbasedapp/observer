package hook

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHookForensicsFollowStateDir is the 2026-10-21 live proof fix: with a
// resolver installed (the `observer hook --config` Observer home), the
// event log lands there (cursor-stop-debug.jsonl: TestStopRejectFollowsStateDir) and NOT under ~/.observer; the resolver runs
// once; a resolver answering "" and no resolver both keep the ~/.observer
// default. Not parallel: the resolver and HOME are process-wide.
func TestHookForensicsFollowStateDir(t *testing.T) {
	home := withTempHome(t)
	t.Cleanup(func() { SetStateDirResolver(nil) })

	cases := []struct {
		name    string
		resolve func() string
		wantDir string
	}{
		{"config-home", nil, filepath.Join(t.TempDir(), "elsewhere")},
		{"resolver-empty-falls-back", func() string { return "" }, filepath.Join(home, ".observer")},
		{"no-resolver-default", nil, filepath.Join(home, ".observer")},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			switch {
			case i == 0:
				dir := c.wantDir
				SetStateDirResolver(func() string { calls++; return dir })
			case c.resolve != nil:
				fn := c.resolve
				SetStateDirResolver(func() string { calls++; return fn() })
			default:
				SetStateDirResolver(nil)
			}
			_ = os.RemoveAll(filepath.Join(home, ".observer"))

			appendHookEventLog(hookEvent{Event: "PreToolUse", Action: "approve"})
			appendHookEventLog(hookEvent{Event: "PostToolUse", Action: "approve"})
			if _, err := os.Stat(filepath.Join(c.wantDir, "hook-events.jsonl")); err != nil {
				t.Fatalf("hook-events.jsonl not in %s: %v", c.wantDir, err)
			}
			if i == 0 {
				if _, err := os.Stat(filepath.Join(home, ".observer", "hook-events.jsonl")); !os.IsNotExist(err) {
					t.Errorf("hook-events.jsonl also written under ~/.observer (err=%v)", err)
				}
			}
			if c.resolve != nil || i == 0 {
				if calls != 1 {
					t.Errorf("resolver ran %d times, want once", calls)
				}
			}
		})
	}
}
