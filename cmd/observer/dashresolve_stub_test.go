package main

import (
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// stubDashResolveEnv replaces the dashboard's host env capture with a hermetic
// empty Env for one test and drops the cached one, so nothing resolves from
// the machine and no login shell or npm probe starts (tracker F-031; the
// toolresolve/host test-binary guard is the backstop for a test that forgets).
// It restores the seam and the cache after the test.
func stubDashResolveEnv(t *testing.T) {
	t.Helper()
	prevBuild := dashResolveEnvBuild
	prevHave, prevAt, prevVal := dashResolveEnvHave, dashResolveEnvAt, dashResolveEnvVal
	t.Cleanup(func() {
		dashResolveEnvMu.Lock()
		defer dashResolveEnvMu.Unlock()
		dashResolveEnvBuild = prevBuild
		dashResolveEnvHave, dashResolveEnvAt, dashResolveEnvVal = prevHave, prevAt, prevVal
	})
	dashResolveEnvMu.Lock()
	defer dashResolveEnvMu.Unlock()
	dashResolveEnvBuild = func() toolresolve.Env { return toolresolve.Env{GOOS: runtime.GOOS} }
	dashResolveEnvHave = false
}
