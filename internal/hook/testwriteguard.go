package hook

import (
	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// INCIDENT 2026-10-21: a cmd/observer test run inside WSL rewrote the
// operator's real Windows C:\Users\<u>\.claude\settings.json so that all 22
// Claude Code hooks ran the (since deleted) test binary. The 2026-10-02 guard
// (crossmount testguard.go) keeps a test binary from DISCOVERING a foreign
// home, but it has a deliberate escape hatch for read-only adapter grounding
// (OBSERVER_ALLOW_LIVE_CROSSMOUNT_IN_TEST), and a test that opens it for one
// package opens it for every package of the run, including the writers here.
//
// This is the WRITE-side guard: inside a `go test` binary the hook writers
// refuse to lock, write or remove any file outside the OS temp directory
// (every t.TempDir lives there), whatever resolved the path. No environment
// variable opens it. The check itself is internal/testwriteguard, shared
// with the MCP and proxy-route writers.

// testWriteRefused returns an error when a test binary would touch a hook
// config file outside the temp directory.
func testWriteRefused(path string) error {
	return testwriteguard.Check("write", path)
}
