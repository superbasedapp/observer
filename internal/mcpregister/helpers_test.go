package mcpregister

import (
	"os"
	"testing"
)

// mustMkdir creates dir and its parents or fails the test. Untagged:
// removal_provenance_test.go uses it too, and that file builds without the
// Agent Access relay (RB1: the sbo_omit_agentaccess_relay vet failed while
// the helper lived in the relay-tagged cline_shared_test.go).
func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}
