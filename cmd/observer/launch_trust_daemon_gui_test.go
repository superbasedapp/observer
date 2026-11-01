//go:build !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"
)

// This test needs the GUI launcher (guiChildEnv, gui_launch.go), which a
// build without terminals does not have, so it lives apart from the rest of
// launch_trust_daemon_test.go.

// TestCheckedMarkerIsStrippedFromChildren (item a): a marker the daemon
// inherited never reaches a child it spawns.
func TestCheckedMarkerIsStrippedFromChildren(t *testing.T) {
	if !isInternalChildEnv(repoTrustCheckedEnv + "=" + strings.Repeat("a", 64)) {
		t.Fatal("an inherited checked marker is not stripped")
	}
	t.Setenv(repoTrustCheckedEnv, strings.Repeat("b", 64))
	for _, kv := range guiChildEnv(nil) {
		if strings.HasPrefix(kv, repoTrustCheckedEnv+"=") {
			t.Fatalf("GUI child inherited %s", kv)
		}
	}
	env := guiChildEnv([]string{repoTrustCheckedEnv + "=" + strings.Repeat("c", 64)})
	if env[len(env)-1] != repoTrustCheckedEnv+"="+strings.Repeat("c", 64) {
		t.Fatalf("the launch's own marker did not reach the GUI child: %v", env[len(env)-1])
	}
}
